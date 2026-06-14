# `secretenv mcp` — Model Context Protocol server

`secretenv mcp serve` is a stdio-only [Model Context Protocol][mcp] server that gives AI coding agents (Claude Code, Cursor, Cline, Gemini CLI / Code Assist, Codex, OpenCode, VS Code Copilot, Continue) structured access to your SecretEnv registry — **without ever returning a resolved secret value**.

This reference covers everything an operator needs: setup per IDE, the 14 tools the server exposes, the confirmation surface, the audit log, and the known limitations as of v0.19.0.

For the design rationale + implementation walkthrough, see [`kb/wiki/build-plan-v0.16-mcp.md`](https://github.com/TechAlchemistX/secretenv/blob/main/kb/wiki/build-plan-v0.16-mcp.md) (build plan) + [`docs/reference/redact.md`](redact.md) + [`docs/reference/migrate.md`](migrate.md) for the v0.14/v0.15 features the MCP server wraps.

[mcp]: https://modelcontextprotocol.io

---

## Quick start

```bash
# 1. Install secretenv (covers Homebrew, cargo install, GitHub release tarballs).
brew install TechAlchemistX/tap/secretenv

# 2. Pick your IDE + apply the config. See `--list-ides` for all 8 supported.
secretenv mcp setup --list-ides
secretenv mcp setup --ide claude-code        # prints the snippet + path
secretenv mcp setup --ide claude-code --write # writes to the IDE's config file

# 3. Restart your IDE. Verify the server connected.
# Claude Code: `claude mcp get secretenv`
# Gemini CLI / OpenCode / Codex: their respective `mcp list` subcommand
# VS Code Copilot / Cline: their MCP-status panel

# 4. In the agent chat:
#    "What SecretEnv tools are available?"
#    "Use secretenv to list all aliases in the default registry."
```

---

## The 14 tools

Each tool's name is exactly what the agent calls. All tools return **structured JSON responses** — never plain text — and **none of them return a resolved secret value**.

### Read-only (8)

| Tool | Purpose |
|---|---|
| `getting_started` | One-shot overview + suggested next tool given the current registry/backend state. Always start here in a fresh session. |
| `version_info` | secretenv version + rmcp SDK version + the 14-tool inventory. |
| `redact_status` | Whether `secretenv run --redact` is enabled (always true since v0.14). |
| `list_backends` | All configured `[backends.*]` instances + their type. |
| `detect_password_managers` | Which password-manager CLIs are installed on this machine (op, vault, doppler, etc.) — for suggesting backends the operator could add. |
| `doctor` | Backend health probe — auth status per configured instance. Mirrors `secretenv doctor --json`. |
| `resolve_status` | Per-registry probe: is the registry's primary source URI's backend reachable + authenticated? Per-alias info comes from `list_aliases`. |
| `list_aliases` | Every alias across every registry + the backend instance/type it points at. **No URI paths, no values** — just alias names + their target backend instance name. |

### Mutations (4)

Mutations go through the `[mcp].allow_mutations` policy gate and are recorded in the mutation audit log. See [Confirmation surface](#confirmation-surface) below.

| Tool | Purpose |
|---|---|
| `set_alias` | Create / update an alias → backend-URI mapping in a registry. **Does NOT create the backend secret itself** — only the registry pointer. |
| `delete_alias` | Remove an alias from a registry. **Does NOT delete the backend secret** — call the backend's native delete CLI for that. ALWAYS CONFIRM PER ALIAS; never batched. |
| `init_project` | Scaffold a `secretenv.toml` from a `.env` file. KEY NAMES only — values structurally cannot be read (the parser stops at `=`). `apply=false` (default) returns the proposed manifest without writing. |
| `redact_file` | Post-hoc file scrubbing — replaces every alias's resolved value with `[redacted:<alias>]`. Returns COUNTS only, never matched bytes. `apply=false` (default) is a dry-run dual to `secretenv redact --dry-run`. |

### Generation + migration (2)

| Tool | Purpose |
|---|---|
| `gen_password` | Generate a cryptographically random value, write it to a backend URI, and register an alias for it. The value **never crosses the MCP boundary** — written directly to the backend. Charsets: `alphanumeric`, `alphanumeric_symbols`, `hex`, `base64_url_safe`. Length floor 16, ceiling 1024. |
| `migrate_alias` | Migrate an alias's value from one backend to another. Wraps `secretenv registry migrate`. `dry_run=true` for probe + plan without mutation; `delete_source=true` opts into post-commit source cleanup. |

---

## Per-IDE setup

Run `secretenv mcp setup --list-ides` to see all 8. Each profile auto-emits a `--allow-mutations=always` flag if Phase 8b empirical testing showed the IDE lacks working MCP elicitation — see [Confirmation surface](#confirmation-surface).

| IDE | Helper key | Config path | Elicitation status (v0.16) |
|---|---|---|---|
| Claude Code | `claude-code` | `~/.claude.json` (use `claude mcp add`) | ✅ Works end-to-end (modal renders, single-click) |
| Cursor | `cursor` | `~/.cursor/mcp.json` | ⏸ Untested — helper ships speculative `--allow-mutations=always` |
| Codex (OpenAI) | `codex` | `~/.codex/config.toml` | ❌ No elicitation — helper ships `--allow-mutations=always`. Codex maintains its own per-tool approval DB (`[mcp_servers.X.tools.Y] approval_mode`) |
| VS Code Copilot | `vscode-copilot` | `.vscode/mcp.json` (workspace-scoped) | ❌ Advertises capability but does not render empty-schema requests — helper ships `--allow-mutations=always`. v0.16.1 will investigate a single-field schema variant. |
| Continue | `continue` | `~/.continue/config.json` | ⏸ Untested — helper ships speculative `--allow-mutations=always` |
| Cline | `cline` | `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` | ❌ No elicitation — operator adds `--allow-mutations=always` manually (Cline's own "Run Tool" UI gate fires too) |
| Gemini CLI + Gemini Code Assist | `gemini` | `~/.gemini/settings.json` | ❌ No elicitation — helper ships `--allow-mutations=always`. Single config covers both the standalone Gemini CLI and the Gemini Code Assist IDE extension. |
| OpenCode | `opencode` | `~/.config/opencode/opencode.jsonc` | ❌ No elicitation — helper ships `--allow-mutations=always`. OpenCode + Codex agents BOTH demonstrate model-level conversational confirmation (the agent asks the operator in chat before firing mutations) — meaningful defense-in-depth at the model layer even when MCP-protocol elicitation is silenced. |

### `--write` mode

`secretenv mcp setup --ide <key> --write` writes the config file directly. Refuses if the target file already exists unless you pass `--force`. The `claude-code` profile is special: it emits a `claude mcp add` shell command rather than writing JSON, because `~/.claude.json` is a 1000+ line shared config file with lots of unrelated Claude Code state.

For IDEs with pre-existing settings.json content (Gemini, Cline, Continue): the helper has no merge logic yet (v0.16.1). Use `jq` to merge:

```bash
jq '. * {"mcpServers": {"secretenv": {"command": "secretenv", "args": ["mcp", "serve", "--allow-mutations", "always"]}}}' \
  ~/.gemini/settings.json > ~/.gemini/settings.json.new
mv ~/.gemini/settings.json.new ~/.gemini/settings.json
```

### `--binary <path>` for portability

By default the rendered config uses `"command": "secretenv"` — relying on the IDE's `$PATH`. Some IDEs spawn MCP servers with a sparser environment than your shell. For maximum portability:

```bash
secretenv mcp setup --ide claude-code --binary $(which secretenv)
```

This bakes the absolute path into the config block.

### `--ide generic`

Print-only profile for any IDE adopting the de-facto Claude `mcpServers` shape. Useful for IDEs not yet in the per-IDE list (or that adopt the shape post-v0.16). Compatible with Claude Code, Cursor, Cline, Gemini. NOT compatible with VS Code Copilot (needs `"type": "stdio"`), Continue (`experimental.modelContextProtocolServers`), OpenCode (`command`-as-list), or Codex (TOML).

---

## Confirmation surface

The `[mcp].allow_mutations` policy controls how the server gates mutation tool calls:

- `never` — every mutation tool returns a structured refusal. Mutation tools are still listed in `tools/list`.
- `confirm` (default) — every mutation gates on operator confirmation surfaced per `[mcp].confirm_via`.
- `always` — every mutation auto-approves. The audit log still records every call.

The `[mcp].confirm_via` value controls how the confirmation prompt reaches you:

- `auto` (default since v0.16 Phase 7c) — **resolves at runtime per request**:
  1. If the MCP client declared the elicitation capability at the initialize handshake → uses `Elicitation`.
  2. Else if `stdin` is a TTY (server launched standalone from an interactive shell) → uses `Tty`.
  3. Else refuses the mutation with a clear error pointing at remediation.
- `elicitation` — MCP server→client elicit RPC. Modal renders in the IDE's native UI. **Only works on clients that advertised the elicitation capability** (Claude Code in v0.16).
- `tty` — Prompt on `/dev/tty`. **Deadlocks inside TUI host IDEs** that own the controlling terminal (Claude Code, Cline, OpenCode TUI, Codex REPL). Safe for standalone `secretenv mcp serve` from an interactive shell.
- `notification` — Desktop notification (planned, currently returns an error).
- `none` — no confirmation surface; equivalent to `allow_mutations = "always"` but emitted as a distinct flag in the audit log.

### Per-IDE policy override

Operators scope the override to a specific IDE's `mcpServers` args block rather than weakening their global config. The setup helper auto-emits this for IDEs that need it:

```json
"mcpServers": {
  "secretenv": {
    "command": "secretenv",
    "args": ["mcp", "serve", "--allow-mutations", "always"]
  }
}
```

When this server spawns, it reads `[mcp].allow_mutations = "confirm"` from your global config (the safer default), then applies the CLI override to bump it to `always` **for this subprocess only**. Other IDEs (Claude Code, etc.) spawn the binary without the flag and stay on the safer policy.

The override is logged via `tracing::info!`:

```
INFO policy override from CLI flag: allow_mutations = Always (was Confirm in config)
```

---

## Mutation audit log

Every mutation tool call writes one JSON-Lines entry to `$XDG_STATE_HOME/secretenv/mcp-mutations.log` (or platform equivalent — `~/.local/state/` on Linux, `~/Library/Application Support/` on macOS, `%LOCALAPPDATA%` on Windows).

```json
{
  "ts_unix_secs": 1779648391,
  "tool_name": "set_alias",
  "alias_name": "phase8b-vscode-temp",
  "backend_instance": "local-data",
  "agent_reason": "User request to register a temporary alias for testing.",
  "operator_decision": "autoapproved",
  "mcp_client_id": "unknown"
}
```

`operator_decision` is one of:

- `approved` — operator clicked Accept in the elicitation modal or typed `y` at the TTY prompt
- `denied` — operator clicked Decline / Cancel or typed `n`
- `timeout` — operator did not respond within 30s
- `autoapproved` — policy was `always` (or per-IDE override; see above) — no operator gate fired
- `policy_refusal` — policy refused outright (e.g. `Auto` resolver found no usable surface)

The file is created mode `0o600` (operator-only). Tampering protection is operator's responsibility: store on a non-shared filesystem, ship to a write-once log shipper if needed.

**`mcp_client_id`** resolves from the rmcp `initialize` handshake's `clientInfo.name` (landed v0.16.1 F-7). Falls back to `"unknown"` only when peer info is unavailable during the handshake itself — never inside a tool handler.

---

## Tool disabling

To remove specific tools from the inventory (e.g. ban `gen_password` in a production environment):

```toml
[mcp]
disabled_tools = ["gen_password", "redact_file"]
```

Disabled tools are absent from BOTH `tools/list` AND dispatch — the agent literally cannot see or invoke them.

---

## Disable / enable the server

```bash
secretenv mcp disable           # indefinite — sentinel at $XDG_CONFIG_HOME/secretenv/mcp-disabled
secretenv mcp disable --duration 2h
secretenv mcp enable            # remove the sentinel
```

When the sentinel is present, every `mcp serve` invocation exits immediately with a clear stderr message (no transport bind, no tool registration). Useful for incident response or maintenance windows where you want to block all IDEs from invoking secretenv without removing the per-IDE config files.

---

## Security model

The full SEC-INV catalog is at `kb/wiki/security-invariants.md`. The v0.16-specific guarantees:

- **SEC-INV-02:** The `secretenv-mcp` crate **structurally cannot construct, deserialize, or serialize** a `Secret<T>`. Three CI gates enforce this: clippy `disallowed-types`, `tests/boundary_test.rs` compile-time assertions, and the Phase 8 live-smoke value-grep. The Cargo feature `value-access` is documentation, not the structural guarantee.
- **SEC-INV-12:** `agent_reason` is recorded verbatim in the audit log but NEVER included in the JSON-RPC tool-result payload returned to the agent NOR set as an OTel span attribute. Operator-facing surfaces (TTY prompt body, elicitation modal body) MAY render it so the operator can evaluate intent.
- **SEC-INV-15:** `gen_password` response carries **no value bytes** — only metadata (alias name, charset, length, success/failure outcome).
- **SEC-INV-20:** Backend URIs do NOT appear in `Err::Display` paths flowing into MCP response `error_message` fields. Two-layer defense: source-side cleanup of `with_context` strings + `safe_error_message()` runtime scrubber that rewrites `scheme://body` → `scheme://[redacted]`. Compile-time regression guard in `tests/uri_not_in_error_message.rs::no_raw_anyhow_format_in_tool_module` catches future re-introduction.

---

## Known limitations

See the `Known limitations` section of [`CHANGELOG.md`](../../CHANGELOG.md) for the full catalog. Summary:

- **Only Claude Code has working MCP elicitation.** All 5 other tested non-Claude IDEs (Gemini, VS Code Copilot, Cline, Codex, OpenCode) need the per-IDE `--allow-mutations=always` override. Upstream PRs queued.
- **Per-IDE override has no user-scope opt-out by default.** A hostile workspace `.mcp.json` can silently weaken your global mutation policy. Mitigated by IDE-side workspace-trust prompts + audit log. Set `[mcp].allow_cli_overrides = false` in your global config to block all per-IDE `--allow-mutations` overrides (shipped v0.18 F-3).
- **TTY TOCTOU + migrate dual-control collapse + dry-run reconnaissance gate** — Phase 7 audit M-7/M-9/M-12 carry-forwards.
- **No `--merge` mode in setup helper** for IDEs with existing settings.json. Use `jq`.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `policy_refusal: no usable confirmation surface` | Client doesn't advertise MCP elicitation + stdin isn't a TTY | Add `--allow-mutations always` to that IDE's args, OR run from a shell terminal directly |
| Mutation times out after 30s | Elicitation request sent but client didn't render the modal | Same fix as above. Likely F-11 (Copilot empty-schema) if VS Code Copilot. |
| UI freezes when triggering a mutation | `confirm_via = "tty"` deadlocked the TUI host | Set `confirm_via = "auto"` (the default since v0.16) — the resolver picks the safe path |
| `secretenv: command not found` in IDE logs | IDE spawned with a sparser `$PATH` than your shell | Re-run `secretenv mcp setup --ide <key> --binary $(which secretenv)` and re-apply the config |
| macOS: binary SIGKILL on first run | Unsigned binary copied via `cp` (not via Homebrew which signs on install) | `codesign --remove-signature ~/.cargo/bin/secretenv && codesign --sign - ~/.cargo/bin/secretenv` |
| Tool descriptions truncated in IDE | IDE's MCP UI has a per-tool character budget | Cosmetic; full descriptions are in the `tools/list` response — IDE UI is the limitation |
| `--allow-mutations=always` reads as a security loss | It is, scoped to that IDE. Audit log still captures every mutation; backend access controls are unaffected | Document the trust trade-off in your team's onboarding; remove the flag when the IDE adds elicitation upstream |

---

## See also

- [`docs/reference/redact.md`](redact.md) — the `redact_file` tool wraps `secretenv redact`
- [`docs/reference/migrate.md`](migrate.md) — the `migrate_alias` tool wraps `secretenv registry migrate`
- [`docs/reference/configuration.md`](configuration.md) — full `[mcp]` config section reference
- [`kb/wiki/build-plan-v0.16-mcp.md`](https://github.com/TechAlchemistX/secretenv/blob/main/kb/wiki/build-plan-v0.16-mcp.md) — v0.16 design + implementation walkthrough
- [`kb/wiki/v0.16-phase-8b-checklist.md`](https://github.com/TechAlchemistX/secretenv/blob/main/kb/wiki/v0.16-phase-8b-checklist.md) — per-IDE manual gate sign-off
- [`kb/wiki/audits/2026-05-24-v0.16-phase9-*.md`](https://github.com/TechAlchemistX/secretenv/tree/main/kb/wiki/audits) — Phase 9 release-prep audit trio
