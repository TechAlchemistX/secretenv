# CyberArk Conjur

**Type:** `conjur`
**CLI required:** `conjur` (Go-based v8+; v7 Ruby line is rejected at startup)
**URI scheme:** `<instance-name>://<variable-id>[#json-key=<field>]`

[CyberArk Conjur](https://www.conjur.org/) is the open-source PAM secrets store. Conjur OSS (Apache-2.0) and Conjur Enterprise (paid) share the same wire protocol — this backend wraps the CLI so the same crate works against both.

Unlike Vault / OpenBao's KV-mount-and-path model, Conjur uses a **resource-graph identity model**: every secret is a `variable` resource owned by a `policy`, with access mediated by per-resource `permit` statements rather than path-prefix capabilities. SecretEnv hides this by treating the variable ID as the URI path.

---

## Install

The Conjur v8 CLI is **Go-based** and currently distributed as the `cyberark/conjur-cli:8` Docker image — there is no Homebrew tap or native macOS binary at the time of v0.11. The PyPI `conjur` package is the EOL Ruby v7 line and is rejected by `secretenv doctor`.

```bash
docker pull cyberark/conjur-cli:8
```

Wrap it with a `docker run` shim and put the wrapper on `$PATH` as `conjur`:

```bash
#!/usr/bin/env bash
# /usr/local/bin/conjur — wrapper around cyberark/conjur-cli:8
set -euo pipefail
exec docker run --rm -i \
  --network host \
  -v "$HOME/.conjur-data:/home/cli" \
  cyberark/conjur-cli:8 "$@"
```

Linux / Windows native builds are tracked in <https://github.com/cyberark/cyberark-conjur-cli>; if CyberArk publishes a Homebrew tap or universal binary in the future, point `conjur` directly at it and remove the wrapper.

> **PyPI gotcha:** `pip install conjur` resolves to v7.1.0 (Ruby line, EOL) and pins `cryptography~=3.3.2` which fails to build on modern macOS. SecretEnv's `doctor` parses `conjur --version` and refuses to proceed against v7 with an explicit `v8+ required` message.

---

## Configuration

```toml
[backends.conjur-prod]
type           = "conjur"
conjur_url     = "https://conjur.company.com"     # required
conjur_account = "myorg"                           # required
conjur_authn   = "authn-jwt"                       # optional, default "authn"
```

### Fields

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Must be `"conjur"` |
| `conjur_url` | Yes | Full URL of the Conjur server (OSS or Enterprise). Set per-instance even though the CLI also reads `~/.conjurrc` — the registry document must deterministically point at the same Conjur cluster regardless of operator shell state. |
| `conjur_account` | Yes | Top-level account namespace this instance targets. Conjur is multi-tenant; the account is a hard namespace boundary. Same per-instance discipline as `conjur_url`. |
| `conjur_authn` | No | Authenticator name. Defaults to `"authn"` (API-key). Other valid values: `authn-jwt`, `authn-oidc`, `authn-iam`, `authn-k8s`, `authn-azure`, `authn-gcp`. SecretEnv does NOT take credentials directly — surface the configured authenticator in the doctor identity line. The CLI's pre-established session controls actual auth. |
| `conjur_login` | No | Identity for non-default authenticators (`host/<id>` or `<user>`). Reserved — currently surfaced in the identity line only when set. |
| `conjur_bin` | No | Override the `conjur` binary path. Defaults to `"conjur"` (resolved via `$PATH`). Primarily a test hook. |
| `conjur_unsafe_set` | No | Defense-in-depth opt-in for the `-v <value>` argv path. Leave at the default `false` unless `/dev/stdin` is unavailable in your execution environment (rare — chrooted CI runner with a stripped `/dev`). See "Storage model" below. |
| `timeout_secs` | No | Per-instance fetch timeout in seconds. Defaults to 30. |

### URL gotcha (HTTP vs HTTPS)

Conjur OSS local dev (`docker compose up` from the official `conjur-quickstart`) listens on plain HTTP. Production deployments use HTTPS with a CA-signed certificate. Always set `conjur_url` explicitly with the scheme:

```toml
conjur_url = "http://localhost:8083"          # local dev (HTTP only)
conjur_url = "https://conjur.company.com"     # production
```

For HTTP-only local servers, the CLI's `conjur init` requires `--insecure`. SecretEnv passes the URL through verbatim, so whichever scheme `conjur_url` carries is the scheme used.

### Account is required

Conjur is multi-tenant: every variable lives under exactly one account. Set `conjur_account` per-instance even though the CLI itself reads `CONJUR_ACCOUNT` from `~/.conjurrc` — same discipline as `conjur_url`, applied for the same reason.

### Multiple Conjur instances or accounts

```toml
[backends.conjur-eng]
type           = "conjur"
conjur_url     = "https://conjur.company.com"
conjur_account = "engineering"

[backends.conjur-payments]
type           = "conjur"
conjur_url     = "https://conjur.company.com"
conjur_account = "payments"
```

---

## URI Format

```
conjur-prod://prod/db/password
└────────┘   └──────────────┘
 instance    variable ID (the / separators are part of the ID,
             reflecting Conjur policy hierarchy — NOT URL path
             delimiters)
```

Conjur has **no KV-mount concept**. The entire URI path IS the variable ID. SecretEnv strips a single leading `/` and passes the rest verbatim to `conjur variable get/set -i <variable-id>`.

### `#json-key=<field>` fragment

When a single variable holds multiple values encoded as a JSON object, the `#json-key=<field>` fragment selects one top-level scalar:

```toml
[registries.default.aliases]
db_password = "conjur-prod://prod/db/credentials#json-key=password"
db_username = "conjur-prod://prod/db/credentials#json-key=username"
```

Provision side:

```bash
echo -n '{"username":"app","password":"sk_live_abc"}' \
  | conjur variable set -i prod/db/credentials -f /dev/stdin
```

The fragment is recognized only on `get`. `set`, `delete`, `list`, and `history` reject any fragment.

---

## Storage model

Conjur variables hold opaque string values. SecretEnv writes the value through the safe-stdin path and reads it back via `conjur variable get -i <id>`, stripping exactly one trailing `\n`.

Registry documents are stored as a JSON alias→URI map serialized to the variable value, matching the [`aws-secrets`](./aws-secrets.md), [`aws-ssm`](./aws-ssm.md), and [`openbao`](./openbao.md) shape. `secretenv registry set` produces this layout automatically.

### `set` argv discipline (no `--value-from-stdin`)

Conjur v8 CLI has **no `--value-from-stdin` flag** (verified against `Conjur CLI version 8.1.3`). Only `-v <value>` argv and `-f <file>` file-path. SecretEnv defaults to `-f /dev/stdin` with the value piped through child stdin: `/dev/stdin` is the kernel pseudo-file present on every supported platform, the CLI reads bytes "as if from a file" without touching disk, and the value never appears on argv. This is CV-1 discipline equivalent to OpenBao's `value=-`.

`conjur_unsafe_set = true` is the explicit operator opt-in that switches `set` to `-v <value>` argv path. The only legitimate reason to flip it: a constrained execution environment without `/dev/stdin` (chrooted CI runner with stripped `/dev/`). Default is `false`; the default-off invariant is machine-checked in the test suite.

### `delete` clears, doesn't remove

**Conjur has no `conjur variable delete` command.** Variables are policy-defined and can only be removed by reloading policy with the variable stripped, which requires policy-edit privileges far beyond a typical SecretEnv operator's `read`/`update` scope.

SecretEnv's `delete()` therefore implements **clear** semantics — it sets the value to the empty string via the same safe `-f /dev/stdin` path used by `set`. The variable retains its policy definition; only the value is emptied. This mirrors 1Password's `delete` precedent and is documented as a deliberate semantic gap.

To fully remove a variable, reload policy without it via `conjur policy load --replace`.

---

## Authentication

SecretEnv delegates to the `conjur` CLI. Any auth method the CLI supports works — set `conjur_authn` to surface the configured authenticator in `secretenv doctor`:

- **API key** (`authn`, default) — `conjur login -i <user>`. Session persisted in OS keystore (macOS Keychain / Linux Secret Service / Windows Credential Manager) by default; `~/.netrc` only when launched with `--force-netrc` for Summon compatibility.
- **JWT** (`authn-jwt`) — for CI / Kubernetes runners. Operator pre-establishes via `conjur login --jwt-from-file <path>` or env-driven flow.
- **OIDC** (`authn-oidc`) — browser / device-code flow.
- **Cloud-native** (`authn-iam`, `authn-azure`, `authn-gcp`, `authn-k8s`) — workload identity flows; SecretEnv just trusts the CLI.

### Minimum policy

```yaml
- !policy
  id: secretenv-readonly
  body:
    - !variable prod/stripe-key
    - !permit
        role: !user alice
        privileges: [ read, execute ]
        resource: !variable prod/stripe-key
```

`set` additionally needs `update`. `delete` (clear) also needs `update`. SecretEnv does NOT manage policy — operators load policies via `conjur policy load`.

---

## doctor Output

```
conjur-prod                                                  (conjur)
  ✓ conjur CLI Conjur CLI version 8.1.3-879b90b
  ✓ authenticated  account=myorg identity=admin authn=authn
```

The `authn=` value comes from your configured `conjur_authn`. Conjur's `whoami` does not surface the authenticator name, so the doctor identity line uses the configured value — keep `conjur_authn` aligned with the auth method you actually used to log in.

```
conjur-prod                                                  (conjur)
  ✓ conjur CLI Conjur CLI version 8.1.3-879b90b
  ✗ not authenticated — session expired
      → run: conjur login  (or 'conjur init' then 'conjur login' if first-time)
```

```
conjur-prod                                                  (conjur)
  ✗ conjur CLI not found
      → install: docker pull cyberark/conjur-cli:8 (alias `conjur` to a docker-run wrapper)
        — see https://github.com/cyberark/cyberark-conjur-cli for native builds
```

---

## License note

Conjur OSS is **Apache-2.0** (CyberArk-led, recently donated to CNCF as an incubating project). Conjur Enterprise is the commercial offering — same wire protocol, additional features (Enterprise authn methods, HA replication, audit). The SecretEnv `conjur` backend wraps the open-source CLI, so the same crate works against both deployments. SecretEnv itself ships under AGPL-3.0-only.
