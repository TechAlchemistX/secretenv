# `secretenv redact` & runtime redaction

`secretenv` ships two redaction surfaces in v0.14:

- **Mode A (runtime)**: built into `secretenv run`. Pipes child stdout/stderr through a streaming scrubber, substituting resolved values with `[redacted:<alias>]`. On by default.
- **Mode B (post-hoc)**: `secretenv redact <path>` subcommand. Scrubs existing files or streams.

Both use one engine (Aho-Corasick byte scanner, alias-aware substitution) and one safety guard set. See [`security.md`](../security.md#redaction-v014) for threat model; this page is the operator reference.

---

## Mode A: runtime stdout/stderr filter

```
secretenv run [--registry <name|uri>] [--dry-run] [--verbose]
              [--redact | --no-redact --i-know]
              [--redact-token <fixed>]
              -- <command> [args...]
```

| Flag | Default | Effect |
|---|---|---|
| `--redact` | off | Force pipe-based redaction even when stdin is a TTY. PTY-bound children (`psql`, `vim`, `ssh`) may misbehave. |
| `--no-redact` | off | Disable redaction entirely; fall back to the pre-v0.14 `exec()` path. Requires `--i-know`. |
| `--i-know` | off | Acknowledge the audit consequences of `--no-redact`. Required by `--no-redact` on non-TTY parents so CI typos don't silently print secrets. |
| `--redact-token <s>` | (alias-aware) | Override the substitution: emit `<s>` for every match regardless of which alias produced it. |

### Default dispatch (`Auto`)

| Parent stdin | Behavior |
|---|---|
| TTY (interactive) | Falls back to `exec()`. Advisory: `secretenv: interactive TTY detected; runtime redaction disabled for this invocation. Run with --redact to force pipe-based redaction (may break PTY-bound prompts).` |
| Non-TTY (CI, pipe, redirect) | Pipe-based redaction via `tokio::process::Command`; both streams flow through independent `StreamingScrubber`s. |

The fallback exists because pipe-based stdio breaks `tcgetattr`, `tcsetattr`, and `ioctl(TIOCGWINSZ)`, the kernel contract TUIs rely on. `secretenv run -- vim file` under pipe redaction would render garbage.

### Signal forwarding

In pipe-based mode, the parent forwards `SIGINT`, `SIGTERM`, and `SIGHUP` to the child via `kill(2)`. Ctrl-C tears down the child cleanly instead of orphaning it.

### Streaming buffering

The scrubber maintains a `max(pattern_len) - 1` byte tail across pipe reads to catch values split across `read()` calls. Maximum pattern length: **64 KiB**. Larger patterns refuse mode-A redaction at startup.

---

## Mode B: `secretenv redact <path>`

```
secretenv redact <path>
                 [--registry <name|uri>]
                 [--alias <name>[,<name>...]]
                 [--in-place [--backup <suffix>]]
                 [--dry-run]
                 [--allow-foreign-owner]
                 [--redact-token <fixed>]
```

| Flag | Default | Effect |
|---|---|---|
| `<path>` | required | File to scrub. v0.14 requires regular-file path; stdin (`-`) reserved for future. |
| `--registry <r>` | active | Same semantics as `run --registry`. Determines alias taint set. |
| `--alias <name>` | every alias | Restrict taint set. Repeatable; comma-separated accepted. |
| `--in-place` | off | Atomic rewrite via sibling tempfile + `rename(2)`. Mode preserved; ownership NOT preserved (file becomes caller's EUID). Conflicts with `--dry-run`. |
| `--backup <suffix>` | (none) | Backup at `<path><suffix>` when `--in-place`. Uses `O_CREAT \| O_EXCL \| O_NOFOLLOW`; refuses if suffix exists or is a symlink. |
| `--dry-run` | off | Count matches, no write or stdout. |
| `--allow-foreign-owner` | off | Bypass foreign-owner refusal (default mode B defense against malicious log planting). |
| `--redact-token <s>` | (alias-aware) | Override substitution (same as mode A). |

### Example

```sh
# Scrub in place, keep .bak:
$ secretenv redact /tmp/ci-build.log --in-place --backup=.bak
secretenv redact: rewrote '/tmp/ci-build.log', 14 match(es), 252 byte(s) replaced; backup at '/tmp/ci-build.log.bak'

# Stream to stdout (default):
$ secretenv redact build.log | grep ERROR

# Count matches only:
$ secretenv redact build.log --dry-run
secretenv redact: would redact 14 match(es) totaling 252 byte(s) in 'build.log'
```

---

## Substitution token

The default token is `[redacted:<alias-name>]`. The alias name is operator-chosen and treated as non-sensitive (it already appears in your `secretenv.toml` and the registry document), so it stays in the token as a diagnostic breadcrumb in build logs without leaking the value. Pass `--redact-token '<fixed-string>'` (for example `[REDACTED]` or `***`) to emit a constant token regardless of which alias matched, for cases where alias names themselves are sensitive by policy.

---

## Shared safety guards

| Guard | Mode A | Mode B | Bypass |
|---|---|---|---|
| Minimum value length (8 bytes) | enforced | enforced | none: vendor problem; rotate to a longer credential |
| `O_NOFOLLOW` open | n/a (no file) | enforced | none |
| Foreign-owner refusal | n/a | enforced | `--allow-foreign-owner` |
| `/proc`, `/sys`, `/dev` refusal | n/a | enforced | none |
| 64 KiB max tainted-value length | enforced | n/a (whole-file scan) | rotate to shorter credential |
| Substitution-token format | shared | shared | `--redact-token <fixed>` |

---

## Error catalog

| Error fragment | Cause | Resolution |
|---|---|---|
| `tainted value below minimum length` | Alias resolved value < 8 bytes. | Skipped; warning lists alias (never value). Rotate to longer credential. |
| `tail-window cap` | Alias resolved value > 64 KiB (mode A only). | Use mode B for large blobs, or rotate. |
| `O_NOFOLLOW` / `symbolic link` | Symlink placed at target between stat and open. | Resolve to target and re-run. |
| `file is owned by UID N` | Foreign-owner refusal. | Use `--allow-foreign-owner` if intentional. |
| `kernel pseudo-filesystems` | Path starts with `/proc`, `/sys`, or `/dev`. | These paths refuse outright; not safe to scrub. |
| `interactive TTY detected` | Mode A `Auto` fell back to `exec()` (TTY stdin). | Use `--redact` to force pipe mode, or confirm child doesn't leak secrets. |
| `--no-redact requires --i-know` | Missing `--i-know` flag. | Add `--i-know`. Two-flag dance makes disable a code-review event. |

---

## See also

- [Security: redaction threat model](../security.md#redaction-v014): defense-in-depth framing and the limits matrix
- [CLI Reference: `secretenv redact`](cli-reference-full.md#secretenv-redact): full flag reference for the post-hoc scrubber
- [CLI Reference: `secretenv run`](cli-reference-full.md#secretenv-run): the runtime redaction flags (`--redact`, `--no-redact`)
