# macOS Keychain

**Type:** `keychain`
**CLI required:** `security` (ships with every macOS)
**URI scheme:** `<instance-name>:///<service>/<account>`
**Platform:** macOS only — `secretenv doctor` reports `keychain-<instance>` as CliMissing on Linux/Windows, and the factory bails with a clear error at config-load time.

---

## Configuration

```toml
[backends.keychain-default]
type = "keychain"                                    # required
# All three fields below are optional.
# keychain_path = "~/Library/Keychains/login.keychain-db"
# kind          = "generic-password"                 # or "internet-password"
# timeout_secs  = 5
```

### Fields

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Must be `"keychain"` |
| `keychain_path` | No | Absolute path to the keychain file. Default: user's login keychain (the bare `security` subcommand with no trailing positional uses the default search list, which is login.keychain-db for interactive users). |
| `kind` | No | `"generic-password"` (default) or `"internet-password"`. Selects which `security` subcommand family wraps `get` / `set` / `delete`. |
| `timeout_secs` | No | Per-instance fetch deadline. Default: `DEFAULT_GET_TIMEOUT` (30 s). Keychain operations are local and sub-100ms; this field is mostly there for symmetry with cloud backends. |

### Multiple keychains

```toml
[backends.keychain-default]
type = "keychain"

[backends.keychain-team]
type          = "keychain"
keychain_path = "/Users/you/Library/Keychains/team.keychain-db"
```

Each instance targets a distinct keychain file. The URI scheme (`keychain-default:///…` vs `keychain-team:///…`) picks which.

---

## URI Format

```
keychain-default:///com.acme.prod/stripe-key
└──────────────┘    └───────────┘ └────────┘
instance name        service       account
```

The two path segments map directly to `security`'s `-s <service>` and `-a <account>` arguments. Both are **required**; a URI with one segment or three segments is rejected.

### Slashes in service or account names

Some apps use dotted service names like `com.acme/subteam` that contain a literal `/`. Percent-encode the inner slash as `%2F` (case-insensitive):

```
keychain-default:///com.acme%2Fsubteam/stripe-key
                            └┬┘
                             └── decodes to literal '/'
```

Only `%2F` is decoded — no general percent-escape handling. Keychain's service/account fields accept raw bytes, so other characters pass through verbatim.

### Fragment directives

**None.** The keychain backend does not consume any `#key=value` fragment directives. A URI carrying a fragment is rejected at `get` / `set` / `delete` time with a clear error.

---

## `kind`: generic-password vs internet-password

macOS's Keychain Services distinguishes two password item categories:

| `kind` | `security` subcommands | Use case |
|---|---|---|
| `generic-password` (default) | `find-generic-password` / `add-generic-password` / `delete-generic-password` | Generic API keys, tokens, shared secrets. What the Keychain Access UI calls "application passwords". |
| `internet-password` | `find-internet-password` / `add-internet-password` / `delete-internet-password` | Protocol+host-scoped secrets (HTTP basic-auth creds, SMB shares). Ships extra attributes like protocol and port that we don't surface in v0.5. |

Most SecretEnv use cases want `generic-password`. Pick `internet-password` only if your items were created through Keychain Access → Add Password or by an app (browser, VPN client) that writes to the internet-password realm.

Two instances can coexist targeting the same keychain:

```toml
[backends.keychain-generic]
type = "keychain"
kind = "generic-password"

[backends.keychain-internet]
type = "keychain"
kind = "internet-password"
```

---

## The `list()` limitation — registry alternatives

**The keychain backend does not implement `list()`.** `security` has no safe, scriptable list-by-prefix operation — the closest (`security dump-keychain`) requires per-item user confirmation, prompts for the keychain password if locked, and dumps every credential in the keychain. Implementing that as a registry-read surface would be a security footgun and operationally unreliable.

### What this means for you

- **The keychain backend cannot host an alias registry.** `secretenv.toml` aliases can't point their `sources = [...]` at a keychain URI.
- **Keychain URIs are alias TARGETS only.** Put `keychain-default:///service/account` on the right-hand side of a registry entry; host the registry itself on `local`, `aws-ssm`, `aws-secrets`, `1password`, `vault`, `gcp`, or `azure`.

Recommended shape:

```toml
# ~/.config/secretenv/config.toml

[registries.default]
sources = ["local-main:///Users/you/.config/secretenv/aliases.toml"]

[backends.local-main]
type = "local"

[backends.keychain-default]
type = "keychain"
```

```toml
# /Users/you/.config/secretenv/aliases.toml — the registry

stripe-key = "keychain-default:///com.acme.prod/stripe-key"
db-url     = "keychain-default:///com.acme.prod/db-url"
```

Run `secretenv registry list` and you'll see the aliases resolved from the local file; `secretenv get stripe-key` fetches via the keychain backend. The registry itself never lives in the keychain.

### Related limitation — `history()` + extensive check

- **`history()`** falls through to the trait default (`"not implemented for backend type 'keychain'"`). The Keychain has no version-history API; items are overwritten in place on `set` with no audit trail.
- **`check_extensive` (via `secretenv doctor --extensive`)** bails with an "unsupported" error for the same reason `list` does.

---

## Authentication

The Keychain has no user-level auth surface like cloud backends. Access is gated per-keychain by two facts:

1. **Lock state.** The login keychain is unlocked automatically when you log in; custom keychains you manage yourself via `security unlock-keychain`.
2. **Per-item ACL.** Set at item creation. See [ACL setup for automation](#acl-setup-for-automation) below.

### Locked-keychain remediation

If `secretenv doctor` reports a keychain as `NotAuthenticated` with a `security unlock-keychain <path>` hint, your target keychain is locked. Run the suggested command interactively:

```sh
security unlock-keychain ~/Library/Keychains/login.keychain-db
# prompts for your keychain password
```

Then re-run `secretenv doctor` to verify.

### ACL setup for automation

When you create a keychain item through `security add-generic-password`, macOS sets an ACL tied to the creating process. Items created through Keychain Access.app default to "Confirm before allowing" — which works for interactive use but breaks automation (triggers a system dialog per fetch).

For automation-friendly items, set the "Always allow" ACL at creation time via the `-T` flag:

```sh
# Always-allow for a specific binary
security add-generic-password \
    -s myapp -a stripe-key \
    -w "sk_test_…" \
    -T /usr/local/bin/secretenv \
    -T /bin/zsh \
    ~/Library/Keychains/login.keychain-db

# Always-allow for ANY process (less secure but simplest)
security add-generic-password \
    -s myapp -a stripe-key \
    -w "sk_test_…" -A \
    ~/Library/Keychains/login.keychain-db
```

`-A` (uppercase) is the "any process, no warning" form — use it for solo-dev convenience, not for shared machines.

---

## Security notes

- **Stdin discipline.** Every `security` invocation the backend spawns sets `stdin: Stdio::null()`. Without this, a locked keychain hangs waiting on the TTY password prompt; with it, `security` fails fast with `errSecAuthFailed` (25), which `get`/`doctor` map to a clear "keychain is locked — run `security unlock-keychain …`" error.
- **`set` argv exposure.** `security add-*-password -w <value>` passes the value through child argv. On macOS's same-UID process model, `ps -ww` output is visible only to the same UID (structurally different from Linux's world-readable `/proc/<pid>/cmdline`). We accept this exposure on single-user machines and do **not** gate behind an opt-in flag (unlike 1Password's `op_unsafe_set`). A `tracing::warn!` at `set` time records the exposure for audit.
- **Multi-user macOS.** Machines with multiple active UIDs (university Macs, shared dev workstations) don't get additional protection for `set`. If that's your environment, avoid `secretenv registry set` against keychain targets — edit the items directly through Keychain Access.app or reach for a different backend for write-heavy flows.
- **Path handling.** `keychain_path` is passed verbatim to `security`; tilde (`~`) expansion happens at shell-eval time during config load, not inside the backend. If your configured path contains `~`, expand it or use an absolute path.

---

## doctor Output

Healthy (unlocked, configured keychain exists):

```
keychain-default                                        (keychain)
  ✓ security (macOS system)
  ✓ authenticated  keychain=login.keychain-db
```

Locked:

```
keychain-default                                        (keychain)
  ✓ security (macOS system)
  ✗ not authenticated — keychain is locked
      → run: security unlock-keychain ~/Library/Keychains/login.keychain-db
```

Non-macOS:

```
keychain-default                                        (keychain)
  ✗ CLI 'security' not found
      → the 'security' tool ships with macOS — non-macOS hosts cannot use this backend
```

(On non-macOS the factory refuses to construct the instance, so the above only renders if someone constructs the backend struct directly — useful context for future debug output.)

---

## Related

- [`docs/backends/local.md`](local.md) — recommended registry host when keychain is the secret target.
- [`docs/registry.md`](../registry.md) — how the alias → URI resolution works end-to-end.
- [`docs/security.md`](../security.md) — the full threat-model comparison including the argv-on-`set` trade-off.
- [`examples/single-backend-keychain/`](../../examples/single-backend-keychain) — canonical macOS-only setup.
- [`man security`](https://www.unix.com/man-page/osx/1/security/) — the authoritative CLI reference.
