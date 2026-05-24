#!/usr/bin/env python3
# Copyright (C) 2026 Mandeep Patel
# SPDX-License-Identifier: AGPL-3.0-only
"""
MCP stdio driver for the secretenv smoke harness (section 35).

Spawns `secretenv mcp serve --config <path>` as a subprocess, performs
the MCP initialize handshake, then sequentially invokes each `tools/call`
request described in a JSON plan and emits a list of responses as JSON.

Usage:
    mcp-driver.py --bin <path> --config <toml> --plan <plan.json> \
        > <responses.json> 2> <driver.log>

Plan JSON shape:
    {
        "calls": [
            {"id": "1", "name": "getting_started", "arguments": {}},
            {"id": "2", "name": "list_backends", "arguments": {}},
            ...
        ],
        "timeout_secs": 30
    }

Response JSON shape (one object per plan call, in input order):
    [
        {"id": "1", "tool": "getting_started", "ok": true,
         "result": <decoded structuredContent>, "error": null,
         "duration_ms": 12},
        ...
    ]

This script intentionally has NO third-party deps — stdlib only. It
relies on the MCP stdio transport being one-JSON-message-per-line
(MCP-stdio convention; no Content-Length headers, unlike LSP).
"""

from __future__ import annotations

import argparse
import json
import os
import select
import subprocess
import sys
import time
from pathlib import Path


def fatal(msg: str, code: int = 1) -> "None":
    print(f"[mcp-driver] FATAL: {msg}", file=sys.stderr)
    sys.exit(code)


def log(msg: str) -> None:
    print(f"[mcp-driver] {msg}", file=sys.stderr)


def send_frame(proc: subprocess.Popen, payload: dict) -> None:
    """Write one JSON message to the MCP server's stdin, newline-terminated."""
    if proc.stdin is None:
        fatal("subprocess stdin not piped")
    line = json.dumps(payload, separators=(",", ":")) + "\n"
    proc.stdin.write(line)
    proc.stdin.flush()


def read_frame(proc: subprocess.Popen, timeout: float) -> dict:
    """Read one JSON message from the MCP server's stdout with a timeout.

    Uses select() because the server may write multiple frames in
    quick succession; we want to consume exactly one per call.
    """
    if proc.stdout is None:
        fatal("subprocess stdout not piped")
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            fatal(f"timed out after {timeout}s waiting for MCP frame")
        readable, _, _ = select.select([proc.stdout], [], [], remaining)
        if not readable:
            continue
        line = proc.stdout.readline()
        if not line:
            fatal("MCP server closed stdout unexpectedly")
        line = line.strip()
        if not line:
            continue  # skip blank keep-alive lines if any
        try:
            return json.loads(line)
        except json.JSONDecodeError as e:
            fatal(f"unparseable frame from MCP server: {e}: {line[:200]}")


def initialize(proc: subprocess.Popen, timeout: float) -> dict:
    """Run the MCP initialize handshake. Returns the initialize result."""
    send_frame(
        proc,
        {
            "jsonrpc": "2.0",
            "id": "init",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {
                    "name": "secretenv-smoke-driver",
                    "version": "0.16.0",
                },
            },
        },
    )
    init_resp = read_frame(proc, timeout)
    if init_resp.get("id") != "init":
        fatal(f"initialize response had wrong id: {init_resp}")
    if "error" in init_resp:
        fatal(f"initialize errored: {init_resp['error']}")
    # Per MCP spec: client sends `notifications/initialized` after.
    send_frame(
        proc,
        {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {},
        },
    )
    return init_resp.get("result", {})


def list_tools(proc: subprocess.Popen, timeout: float) -> list:
    send_frame(
        proc,
        {
            "jsonrpc": "2.0",
            "id": "tools-list",
            "method": "tools/list",
            "params": {},
        },
    )
    resp = read_frame(proc, timeout)
    if resp.get("id") != "tools-list":
        fatal(f"tools/list response had wrong id: {resp}")
    if "error" in resp:
        fatal(f"tools/list errored: {resp['error']}")
    return resp.get("result", {}).get("tools", [])


def call_tool(
    proc: subprocess.Popen, call_id: str, name: str, arguments: dict, timeout: float
) -> dict:
    t_start = time.monotonic()
    send_frame(
        proc,
        {
            "jsonrpc": "2.0",
            "id": call_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
    )
    resp = read_frame(proc, timeout)
    duration_ms = int((time.monotonic() - t_start) * 1000)
    out = {
        "id": call_id,
        "tool": name,
        "duration_ms": duration_ms,
        "ok": "error" not in resp,
        "error": resp.get("error"),
        "result": None,
        "raw": resp,
    }
    if "result" in resp:
        # rmcp emits structuredContent under result.structuredContent for
        # Json-wrapped tool returns. Surface both shapes for assertion
        # convenience.
        result = resp["result"]
        out["result"] = result.get("structuredContent", result)
        out["isError"] = result.get("isError", False)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True, help="path to secretenv binary")
    ap.add_argument("--config", required=True, help="path to config.toml for the MCP server")
    ap.add_argument("--plan", required=True, help="path to plan.json with calls[]")
    ap.add_argument(
        "--list-tools-only",
        action="store_true",
        help="emit tools/list result only and exit (skip plan.calls)",
    )
    args = ap.parse_args()

    bin_path = Path(args.bin).resolve()
    if not bin_path.exists():
        fatal(f"binary not found: {bin_path}")
    cfg_path = Path(args.config).resolve()
    if not cfg_path.exists():
        fatal(f"config not found: {cfg_path}")

    if args.list_tools_only:
        plan = {"calls": [], "timeout_secs": 30}
    else:
        plan_path = Path(args.plan).resolve()
        if not plan_path.exists():
            fatal(f"plan not found: {plan_path}")
        with plan_path.open("r", encoding="utf-8") as fh:
            plan = json.load(fh)

    timeout = float(plan.get("timeout_secs", 30))

    log(f"spawning {bin_path} mcp serve --config {cfg_path}")
    env = os.environ.copy()
    # Pin RUST_LOG quiet so server stderr stays parseable in driver.log.
    env.setdefault("RUST_LOG", "error")
    proc = subprocess.Popen(
        [str(bin_path), "--config", str(cfg_path), "mcp", "serve"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )

    try:
        init_result = initialize(proc, timeout)
        log(f"initialized; server={init_result.get('serverInfo', {})}")

        tools = list_tools(proc, timeout)
        log(f"tools/list returned {len(tools)} tools: {[t.get('name') for t in tools]}")

        if args.list_tools_only:
            json.dump({"tools": tools}, sys.stdout)
            return 0

        responses = []
        for call in plan.get("calls", []):
            cid = str(call["id"])
            name = call["name"]
            arguments = call.get("arguments", {})
            log(f"calling tools/call name={name} id={cid}")
            r = call_tool(proc, cid, name, arguments, timeout)
            responses.append(r)
            if not r["ok"]:
                log(f"  → ERROR: {r['error']}")
            else:
                log(f"  → ok in {r['duration_ms']}ms")

        json.dump({"tools": tools, "responses": responses}, sys.stdout)
        return 0
    finally:
        # Best-effort graceful shutdown: close stdin, wait briefly, kill.
        try:
            if proc.stdin and not proc.stdin.closed:
                proc.stdin.close()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
        except Exception as e:  # noqa: BLE001
            log(f"shutdown cleanup error (ignored): {e}")
        # Always emit server stderr to driver.log so failures are debuggable.
        if proc.stderr is not None:
            try:
                stderr_tail = proc.stderr.read()
                if stderr_tail:
                    log("--- server stderr ---")
                    sys.stderr.write(stderr_tail)
            except Exception:  # noqa: BLE001
                pass


if __name__ == "__main__":
    sys.exit(main())
