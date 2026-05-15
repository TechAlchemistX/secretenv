# `secretenv redact` & runtime redaction

`secretenv` ships two redaction surfaces in v0.14:

- **Mode A (runtime)** — built into `secretenv run`. Pipes the child's stdout/stderr through a streaming scrubber that substitutes resolved values with `[redacted:<alias>]`. **On by default.**
- **Mode B (post-hoc)** — the dedicated `secretenv redact <path>` subcommand. Scrubs an existing file or stream.

Both share one engine (Aho-Corasick byte scanner, alias-aware substitution) and one set of safety guards. The threat-model summary lives in [`security.md`](../security.md#redaction-v014); this page is the operator-facing reference.

---

## Mode A — runtime stdout/stderr filter

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
| `--i-know` | off | Acknowledge the audit consequences of `--no-redact`. Required by `--i-know` on non-TTY parents so CI typos don't silently print secrets. |
| `--redact-token <s>` | (alias-aware) | Override the substitution: emit `<s>` for every match regardless of which alias produced it. |

### Default dispatch (`Auto`)

| Parent stdin | Behavior |
|---|---|
| TTY (interactive) | `Auto` falls back to `exec()`. One-line stderr advisory: `secretenv: interactive TTY detected; runtime redaction disabled for this invocation. Run with --redact to force pipe-based redaction (may break PTY-bound prompts).` |
| Non-TTY (CI, pipe, redirect) | Pipe-based redaction. Child runs under `tokio::process::Command` with stdout/stderr piped; both streams flow through independent `StreamingScrubber`s before reaching the parent's stdout/stderr. |

The auto fallback exists because pipe-based stdio breaks `tcgetattr`, `tcsetattr`, and `ioctl(TIOCGWINSZ)` — the kernel-level contract any TUI relies on. `secretenv run -- vim file` under pipe redaction would render garbage.

### Signal forwarding

While in pipe-based mode, the parent forwards `SIGINT`, `SIGTERM`, and `SIGHUP` to the child via `kill(2)`. Ctrl-C in the parent terminal tears down the child cleanly instead of orphaning it.

### Streaming buffering

The scrubber maintains a carry-over tail of `max(pattern_len) - 1` bytes across pipe reads so a tainted value split across two `read()` calls still matches. Maximum supported pattern length: **64 KiB**. Larger patterns refuse mode-A redaction at startup with `redact mode A: a tainted value exceeds the 65536-byte tail-window cap; refusing to start runtime redaction (would otherwise miss matches split across chunk boundaries)`.

---

## Mode B — `secretenv redact <path>`

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
| `<path>` | required | File to scrub. `-` reads stdin (writes stdout). |
| `--registry <r>` | active | Same semantics as `run --registry`. Determines which aliases populate the tainted set. |
| `--alias <name>` | every alias | Restrict the tainted set. Repeatable; comma-separated also accepted. |
| `--in-place` | off | Atomic rewrite via sibling tempfile + `rename(2)`. Mode (`0o600` etc.) is preserved. Conflicts with `--dry-run`. |
| `--backup <suffix>` | (none) | When `--in-place` is set, also keep a backup at `<path><suffix>` (e.g. `--backup .bak`). |
| `--dry-run` | off | Count matches without writing. Implies neither `--in-place` nor stdout emission. |
| `--allow-foreign-owner` | off | Allow scrubbing files owned by a UID other than the caller's EUID. Off by default. |
| `--redact-token <s>` | (alias-aware) | Override the substitution (same as mode A). |

### Example

```sh
# Scrub a CI build log in place, keep a .bak copy:
$ secretenv redact /tmp/ci-build.log --in-place --backup=.bak
secretenv redact: rewrote '/tmp/ci-build.log' — 14 match(es), 252 byte(s) replaced; backup at '/tmp/ci-build.log.bak'

# Stream-scrub to stdout (default):
$ secretenv redact build.log | grep ERROR

# Just count what would be scrubbed:
$ secretenv redact build.log --dry-run
secretenv redact: would redact 14 match(es) totaling 252 byte(s) in 'build.log'
```

---

## Shared safety guards

| Guard | Mode A | Mode B | Bypass |
|---|---|---|---|
| Minimum value length (8 bytes) | enforced | enforced | none — vendor problem; rotate to a longer credential |
| `O_NOFOLLOW` open | n/a (no file) | enforced | none |
| Foreign-owner refusal | n/a | enforced | `--allow-foreign-owner` |
| `/proc`, `/sys`, `/dev` refusal | n/a | enforced | none |
| 64 KiB max tainted-value length | enforced | n/a (whole-file scan) | rotate to shorter credential |
| Substitution-token format | shared | shared | `--redact-token <fixed>` |

---

## Error catalog

| Error fragment | Cause | Resolution |
|---|---|---|
| `tainted value below minimum length` | An alias's resolved value is < 8 bytes. | Skipped; warning lists alias name (never value or length). Rotate to a longer credential or accept the gap. |
| `tail-window cap` | An alias's resolved value > 64 KiB (mode A only). | Mode A refuses to start. Use mode B for very large blobs, or rotate. |
| `O_NOFOLLOW` / `symbolic link` / `Too many levels of symbolic links` | A symlink was placed at the target path between stat and open. | Resolve the symlink to its target and re-run. |
| `file is owned by UID N` | Foreign-owner refusal fired. | Use `--allow-foreign-owner` if intentional (e.g. scrubbing a root-owned log as the current user). |
| `kernel pseudo-filesystems (/proc, /sys, /dev) are not safe redact targets` | Path starts with `/proc`, `/sys`, or `/dev`. | These paths cannot be scrubbed meaningfully; refuses outright. |
| `interactive TTY detected; runtime redaction disabled for this invocation` | Mode A `Auto` fell back to `exec()` because stdin is a TTY. | Use `--redact` to force pipe-based mode, or accept the fallback and confirm your child doesn't print secrets to the terminal. |
| `--no-redact requires --i-know` (clap-emitted) | Operator passed `--no-redact` without `--i-know`. | Add `--i-know`. The two-flag dance is deliberate; it makes the disable a code-review event. |

---

## See also

- [`security.md`](../security.md#redaction-v014) — threat model + Limits matrix
- v0.14 build plan ([[build-plan-v0.14-redact]] in the SecretEnv design KB)
- Synthesis §2.3 ([[v0.14-plus-synthesis]] in the SecretEnv design KB) — Q-O2 (substitution token) and Q-O3 (isatty fallback) resolutions
