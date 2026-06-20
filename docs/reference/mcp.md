# `secretenv mcp`: Model Context Protocol server

`secretenv mcp serve` is a stdio-only [MCP][mcp] server providing AI coding agents structured access to SecretEnv registries, **without returning resolved secret values**.

Setup per IDE, 14 tools, confirmation surface, audit log, and v0.19.0 limitations covered here. See [`redact.md`](redact.md) and [`migrate.md`](migrate.md) for the wrapped features.

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

All tools return **structured JSON** and **never return resolved secret values**.

### Read-only (8)

| Tool | Purpose |
|---|---|
| `getting_started` | One-shot overview + suggested next tool given the current registry/backend state. Always start here in a fresh session. |
| `version_info` | secretenv version + rmcp SDK version + the 14-tool inventory. |
| `redact_status` | Whether `secretenv run --redact` is enabled (always true since v0.14). |
| `list_backends` | All configured `[backends.*]` instances + their type. |
| `detect_password_managers` | Which password-manager CLIs are installed on this machine (op, vault, doppler, etc.), for suggesting backends the operator could add. |
| `doctor` | Backend health probe: auth status per configured instance. Mirrors `secretenv doctor --json`. |
| `resolve_status` | Per-registry probe: is the registry's primary source URI's backend reachable + authenticated? Per-alias info comes from `list_aliases`. |
| `list_aliases` | Every alias across every registry + the backend instance/type it points at. **No URI paths, no values**, just alias names + their target backend instance name. |

### Mutations (4)

Mutations gate on `[mcp].allow_mutations` policy and record to audit log (see [Confirmation surface](#confirmation-surface)).

| Tool | Purpose |
|---|---|
| `set_alias` | Create / update an alias → backend-URI mapping in a registry. **Does NOT create the backend secret itself**, only the registry pointer. |
| `delete_alias` | Remove an alias from a registry. **Does NOT delete the backend secret**. Call the backend's native delete CLI for that. ALWAYS CONFIRM PER ALIAS; never batched. |
| `init_project` | Scaffold a `secretenv.toml` from a `.env` file. KEY NAMES only, values structurally cannot be read (the parser stops at `=`). `apply=false` (default) returns the proposed manifest without writing. |
| `redact_file` | Post-hoc file scrubbing: replaces every alias's resolved value with `[redacted:<alias>]`. Returns COUNTS only, never matched bytes. `apply=false` (default) is a dry-run dual to `secretenv redact --dry-run`. |

### Generation + migration (2)

| Tool | Purpose |
|---|---|
| `gen_password` | Generate a cryptographically random value, write it to a backend URI, and register an alias for it. The value **never crosses the MCP boundary**, written directly to the backend. Charsets: `alphanumeric`, `alphanumeric_symbols`, `hex`, `base64_url_safe`. Length floor 16, ceiling 1024. |
| `migrate_alias` | Migrate an alias's value from one backend to another. Wraps `secretenv registry migrate`. `dry_run=true` for probe + plan without mutation; `delete_source=true` opts into post-commit source cleanup. |

---

## Per-IDE setup

Run `secretenv mcp setup --list-ides` to see all 8. Testing determined which IDEs lack MCP elicitation; those profiles auto-emit `--allow-mutations=always` (see [Confirmation surface](#confirmation-surface)).

| IDE | Helper key | Config path | Elicitation (v0.16) |
|---|---|---|---|
| Claude Code | `claude-code` | `~/.claude.json` (use `claude mcp add`) | ✅ End-to-end (modal + single-click) |
| Cursor | `cursor` | `~/.cursor/mcp.json` | ⏸ Speculative `--allow-mutations=always` |
| Codex (OpenAI) | `codex` | `~/.codex/config.toml` | ❌ No elicitation; ships `--allow-mutations=always`. Maintains own per-tool approval DB. |
| VS Code Copilot | `vscode-copilot` | `.vscode/mcp.json` | ❌ No empty-schema render; ships `--allow-mutations=always` (single-field variant pending v0.16.1). |
| Continue | `continue` | `~/.continue/config.json` | ⏸ Speculative `--allow-mutations=always` |
| Cline | `cline` | `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` | ❌ No elicitation; operator adds flag manually (Cline UI gate also fires). |
| Gemini CLI + Gemini Code Assist | `gemini` | `~/.gemini/settings.json` | ❌ No elicitation; ships `--allow-mutations=always` (single config for both tools). |
| OpenCode | `opencode` | `~/.config/opencode/opencode.jsonc` | ❌ No MCP elicitation; model-level conversational confirmation (agent asks in chat). Ships `--allow-mutations=always`. |

### `--write` mode

`secretenv mcp setup --ide <key> --write` writes the config file (refuses if exists unless `--force`). `claude-code` is special: emits `claude mcp add` command (not JSON) because `~/.claude.json` is 1000+ lines of shared state.

For IDEs with existing settings.json (Gemini, Cline, Continue): no merge logic yet (v0.16.1). Use `jq`:

```bash
jq '. * {"mcpServers": {"secretenv": {"command": "secretenv", "args": ["mcp", "serve", "--allow-mutations", "always"]}}}' \
  ~/.gemini/settings.json > ~/.gemini/settings.json.new
mv ~/.gemini/settings.json.new ~/.gemini/settings.json
```

### `--binary <path>` for portability

By default, config uses `"command": "secretenv"` (relying on IDE's `$PATH`). Some IDEs spawn with sparser env. For portability:

```bash
secretenv mcp setup --ide claude-code --binary $(which secretenv)
```

### `--ide generic`

Print-only profile for any IDE adopting the Claude `mcpServers` shape. Compatible with Claude Code, Cursor, Cline, Gemini. Incompatible with VS Code Copilot (`"type": "stdio"`), Continue (`experimental.modelContextProtocolServers`), OpenCode (`command`-as-list), Codex (TOML).

---

## Confirmation surface

**`[mcp].allow_mutations` policy:**
- `never`: mutations return refusal (still listed in `tools/list`)
- `confirm` (default): gates on confirmation per `[mcp].confirm_via`
- `always`: auto-approve (audit log records all)

**`[mcp].confirm_via` method:**
- `auto` (default v0.16+), resolves per request:
  1. Client advertised elicitation at initialize → use `Elicitation` (modal)
  2. Else if `stdin` is TTY → use `Tty` prompt
  3. Else refuse with remediation hint
- `elicitation`: MCP server→client modal (only works if client advertised; Claude Code v0.16)
- `tty`: `/dev/tty` prompt (deadlocks in TUI host IDEs: Claude Code, Cline, OpenCode TUI, Codex REPL; safe standalone)
- `notification`: desktop notification (planned; errors currently)
- `none`: no surface (equivalent to `always`; audit log records as distinct flag)

### Per-IDE policy override

Scope overrides to a specific IDE's `mcpServers` args block (not global config):

```json
"mcpServers": {
  "secretenv": {
    "command": "secretenv",
    "args": ["mcp", "serve", "--allow-mutations", "always"]
  }
}
```

Server reads global `[mcp].allow_mutations = "confirm"`, then CLI flag bumps to `always` **for this subprocess only**. Other IDEs spawn without the flag and stay safer. Logged:

```
INFO policy override from CLI flag: allow_mutations = Always (was Confirm in config)
```

---

## Mutation audit log

Every mutation writes JSON-Lines to `$XDG_STATE_HOME/secretenv/mcp-mutations.log` (`~/.local/state/` Linux, `~/Library/Application Support/` macOS, `%LOCALAPPDATA%` Windows):

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

**`operator_decision`:** `approved` (clicked Accept / typed `y`) | `denied` (clicked Decline / typed `n`) | `timeout` (30s no response) | `autoapproved` (policy=`always`/per-IDE override) | `policy_refusal` (Auto resolver found no surface).

File created mode `0o600` (operator-only). Tampering protection is operator's responsibility.

**`mcp_client_id`** from rmcp `initialize` handshake `clientInfo.name` (v0.16.1+). Falls back to `"unknown"` only if handshake unavailable.

---

## Tool disabling

```toml
[mcp]
disabled_tools = ["gen_password", "redact_file"]
```

Disabled tools are absent from `tools/list` and dispatch. Agents cannot see or invoke them.

---

## Disable / enable the server

```bash
secretenv mcp disable              # indefinite (sentinel at $XDG_CONFIG_HOME/secretenv/mcp-disabled)
secretenv mcp disable --duration 2h
secretenv mcp enable               # remove sentinel
```

Sentinel present: `mcp serve` exits immediately with clear message (no transport, no tools). Useful for incidents or maintenance without removing per-IDE configs.

---

## Security model

The MCP server enforces these structural security guarantees:

- **No `Secret<T>` in the MCP crate:** `secretenv-mcp` structurally cannot construct/deserialize/serialize `Secret<T>`. Enforced by clippy `disallowed-types`, `tests/boundary_test.rs` compile-time assertions, and a live-smoke value-grep. The Cargo feature `value-access` is documentation only.
- **`agent_reason` is audit-only:** recorded in the audit log but NEVER in the tool-result JSON-RPC payload or OTel attributes. Operator surfaces (TTY/elicitation modal) MAY render it for intent evaluation.
- **No password bytes in `gen_password` output:** the response carries only metadata (alias, charset, length, outcome), never value bytes.
- **No backend URIs in error messages:** backend URIs are absent from `Err::Display` in MCP response `error_message` fields. Two-layer defense: source-side `with_context` cleanup plus a `safe_error_message()` scrubber (`scheme://body` → `scheme://[redacted]`). A compile-time guard in `tests/uri_not_in_error_message.rs` prevents regression.

---

## Known limitations

Full catalog in [`CHANGELOG.md`](../../CHANGELOG.md). Key items:

- **Only Claude Code has working elicitation.** All other IDEs (Gemini, VS Code Copilot, Cline, Codex, OpenCode) need per-IDE `--allow-mutations=always` override (upstream PRs queued).
- **Per-IDE override has no user opt-out by default.** Hostile workspace `.mcp.json` can weaken global policy. Mitigated by IDE-side workspace-trust + audit log. Set `[mcp].allow_cli_overrides = false` to block per-IDE overrides.
- **TTY TOCTOU, migrate dual-control collapse, and dry-run reconnaissance gate**: carry-forward hardening for a future cycle.
- **No `--merge` mode in setup helper** for existing settings.json. Use `jq`.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `policy_refusal: no usable confirmation surface` | No MCP elicitation + stdin not TTY | Add `--allow-mutations always` to IDE args OR run from shell |
| Mutation timeout after 30s | Elicitation sent, client didn't render modal | Same. Likely the Copilot empty-schema issue if VS Code. |
| UI freezes on mutation | `confirm_via = "tty"` deadlocked TUI host | Set `confirm_via = "auto"` (default v0.16) |
| `secretenv: command not found` in IDE logs | IDE spawned with sparse `$PATH` | Re-run `secretenv mcp setup --ide <key> --binary $(which secretenv)` |
| macOS binary SIGKILL on first run | Unsigned binary (copied via `cp`, not Homebrew) | `codesign --remove-signature ~/.cargo/bin/secretenv && codesign --sign - ~/.cargo/bin/secretenv` |
| Tool descriptions truncated | IDE UI character budget per tool | Cosmetic; full descriptions in `tools/list` response |
| `--allow-mutations=always` as security loss | True, scoped to that IDE; audit log + backend controls unaffected | Document trust trade-off in onboarding; remove when IDE adds elicitation |

---

## See also

- [Redaction](redact.md): the `redact_file` tool wraps `secretenv redact`
- [Registry migrate](migrate.md): the `migrate_alias` tool wraps `secretenv registry migrate`
- [CLI Reference: `secretenv mcp`](cli-reference-full.md#secretenv-mcp): the `mcp` subcommands and flags
- [Security & threat model](../security.md): the MCP no-leak invariants in context
