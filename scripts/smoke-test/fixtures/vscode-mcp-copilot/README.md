# vscode-mcp-copilot fixture

VS Code workspace pre-configured to register SecretEnv as an MCP
server for GitHub Copilot. Used by the v0.16.2 F-11 A/B test for
the Copilot empty-schema elicitation finding (see
[`kb/wiki/runbooks/copilot-elicitation-validation.md`](../../../../../kb/wiki/runbooks/copilot-elicitation-validation.md)).

## What this fixture exists for

Phase 8b FINDING-11 (documented in v0.16.0): VS Code Copilot
advertises the MCP `elicitation` capability at the initialize
handshake but renders NO UI when the SecretEnv MCP server sends
an elicit RPC with an empty-schema body (`MutationApproval {}`).
Mutation calls time out after 30s server-side; the audit log
records `decision: "timeout"`.

The v0.16.2 F-11 cycle is set up to A/B test the leading
hypothesis — adding a single no-op `confirm: bool` field to the
schema — against the 6 elicitation-capable IDEs (Claude Code,
Gemini, Cline, Codex, OpenCode, Copilot) to verify whether option
(a) unlocks Copilot without regressing the 5 IDEs that currently
work.

## How to use

1. Open this directory as a VS Code workspace (`code <path-to-fixture>`).
2. The `.vscode/mcp.json` entry points VS Code Copilot at the
   `secretenv` binary on `$PATH` with `mcp serve`. Restart Copilot
   if it doesn't auto-detect the server.
3. From Copilot Chat, ask the agent to call `set_alias` with any
   valid `target_uri`. Watch for whether the modal appears.

The full A/B procedure (current-schema baseline → patched-schema
test → decision) lives in
[`kb/wiki/runbooks/copilot-elicitation-validation.md`](../../../../../kb/wiki/runbooks/copilot-elicitation-validation.md).

## NOT a smoke-harness fixture

This fixture is not invoked by `scripts/smoke-test/run-tests.sh`.
It's a manual-validation fixture for the F-11 carry-forward,
intentionally human-driven (no headless way to drive Copilot's
modal UI as of v0.16.2).
