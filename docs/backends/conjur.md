# CyberArk Conjur

**Type:** `conjur`
**CLI required:** [`conjur`](https://github.com/cyberark/conjur-cli-go) (Go-based v8+; v7 Ruby line is rejected at startup)
**URI scheme:** `<instance-name>://<variable-id>[#json-key=<field>]`
**Platform:** all (macOS, Linux, Windows)
**Tested:** `Conjur CLI v8.1.3-879b90b` on macOS Darwin 25.4 (SecretEnv v0.13.0, 2026-05-07)

> SecretEnv injects secrets from any backend as environment variables. This page covers the `conjur` backend. New here? See the [main README](../../README.md).

[CyberArk Conjur](https://www.conjur.org/) is the open-source PAM secrets store — Apache-2.0 (OSS) and Enterprise deployments share the same wire protocol. Unlike Vault's KV-mount-and-path model, Conjur uses a **resource-graph identity model**: every secret is a `variable` resource with access mediated by per-resource policies. SecretEnv treats the variable ID as the URI path. The v8 CLI is Go-based and currently distributed as the `cyberark/conjur-cli:8` Docker image (the PyPI `conjur` package is EOL Ruby v7 and is rejected by `secretenv doctor`).

## When to pick this

- **You're using Conjur Enterprise or OSS:** native integration, shared policy/audit infrastructure
- **Policy-scoped access:** Conjur's resource-graph model suits complex permission hierarchies
- **Team workflows:** machine accounts and role-based access control built-in
- **Docker-friendly CI:** the official CLI image works in containerized pipelines

## Configuration

```toml
[backends.conjur-prod]
type                = "conjur"
conjur_appliance_url = "https://conjur.company.com"
conjur_account       = "myorg"
conjur_authn         = "authn"                       # optional, default "authn"
```

### Fields

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Must be `"conjur"` |
| `conjur_appliance_url` | Yes | Full URL (HTTP or HTTPS) of the Conjur server. Local dev typically uses `http://localhost:8083` (HTTP only). |
| `conjur_account` | Yes | Top-level account namespace. Conjur is multi-tenant; every variable lives under exactly one account. |
| `conjur_authn` | No | Authenticator name. Defaults to `"authn"` (API-key). Other values: `authn-jwt`, `authn-oidc`, `authn-iam`, `authn-k8s`, `authn-azure`, `authn-gcp`. Surfaced in the doctor identity line. The CLI's pre-established session controls actual auth. |
| `conjur_unsafe_set` | No | Defense-in-depth opt-in for the `-v <value>` argv path. Defaults to `false`; use the safe `-f /dev/stdin` path by default. Set `true` only if `/dev/stdin` is unavailable. |
| `timeout_secs` | No | Per-instance fetch timeout. Default: 30s. |

### Multiple Conjur instances

```toml
[backends.conjur-eng]
type                 = "conjur"
conjur_appliance_url = "https://conjur.company.com"
conjur_account       = "engineering"

[backends.conjur-payments]
type                 = "conjur"
conjur_appliance_url = "https://conjur.company.com"
conjur_account       = "payments"
```

## URI Format

```
conjur-prod://prod/db/password
└──────────┘  └──────────────┘
instance      variable ID (the entire path is the variable ID)
```

Conjur variables have **no KV-mount concept** — the entire URI path IS the variable ID. SecretEnv strips a single leading `/` and passes the rest to `conjur variable get -i <variable-id>`.

### `#json-key=<field>` fragment

When a variable holds a JSON object, extract a top-level scalar field:

```toml
db_password = "conjur-prod://prod/db/credentials#json-key=password"
db_username = "conjur-prod://prod/db/credentials#json-key=username"
```

The fragment is recognized on `get` only. `set`, `delete`, `list`, and `history` reject any fragment.

**Verify your setup with:** `secretenv doctor` — green output means you're ready to run `secretenv run -- <your command>`.

## Authentication

SecretEnv delegates to the `conjur` CLI. The CLI's pre-established session controls actual auth — SecretEnv does not take credentials directly. Set `conjur_authn` to surface the configured authenticator in `secretenv doctor`:

- **API key** (`authn`, default) — `conjur login -i <user>`. Session persisted in OS keystore (Keychain / Secret Service / Credential Manager) by default.
- **JWT** (`authn-jwt`) — for CI / Kubernetes. Operator pre-establishes via `conjur login --jwt-from-file <path>`.
- **OIDC** (`authn-oidc`) — browser / device-code flow.
- **Cloud-native** (`authn-iam`, `authn-azure`, `authn-gcp`, `authn-k8s`) — workload identity flows. SecretEnv trusts the CLI's session.

### Set safety (no argv)

`set` uses `-f /dev/stdin` with the value piped through stdin — the kernel pseudo-file lets the CLI read bytes without touching disk or argv. This is CV-1 safe. `conjur_unsafe_set = true` switches to `-v <value>` argv path (expose only if `/dev/stdin` is unavailable — rare).

### Delete semantics

Conjur has **no `conjur variable delete` command** — variables are policy-defined. SecretEnv's `delete()` implements **clear** semantics: it sets the value to the empty string via the safe stdin path. The variable retains its policy definition; only the value is emptied.

## Minimum policy

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

For `set` and `delete` (clear), the role also needs `update` privilege.

## doctor Output

Healthy state:

```
conjur-prod                                                      (conjur)
  ✓ conjur CLI Conjur CLI version 8.1.3-879b90b
  ✓ authenticated  account=myorg  identity=admin  authn=authn
```

Not authenticated (session expired):

```
conjur-prod                                                      (conjur)
  ✓ conjur CLI Conjur CLI version 8.1.3-879b90b
  ✗ not authenticated — session expired
      → run: conjur login  (or 'conjur init' then 'conjur login' if first-time)
```

CLI not found (v7 Ruby or not installed):

```
conjur-prod                                                      (conjur)
  ✗ conjur CLI not found
      → install: docker pull cyberark/conjur-cli:8 (alias `conjur` to a docker-run wrapper)
        — see https://github.com/cyberark/conjur-cli-go for native builds
```

## Fragment directives

| Directive | Effect | Example |
|---|---|---|
| `json-key=<field>` | Extract top-level JSON field from variable value | `conjur-prod://prod/db/creds#json-key=password` |

Other fragments are rejected with an enumerated error listing supported directives.

## History API support

Not implemented. Conjur's CLI exposes no per-variable version-history subcommand. The server maintains audit logs; `secretenv registry history <alias>` returns the trait-default "not implemented" until the CLI surfaces revision metadata.

## Limitations

- **No variable deletion.** `delete()` clears the value (empty string); the variable remains defined. Remove via policy reload only.
- **Go v8 CLI only.** The PyPI `conjur` package (Ruby v7) is EOL and rejected at startup. Use `cyberark/conjur-cli:8` Docker image or native v8 builds.
- **HTTP/HTTPS choice is yours.** Set `conjur_appliance_url` with the correct scheme; local dev uses HTTP, production uses HTTPS.

## Examples

### Single instance, local dev

```toml
[backends.conjur-local]
type                 = "conjur"
conjur_appliance_url = "http://localhost:8083"
conjur_account       = "myorg"

[registries.default]
sources = ["conjur-local://secretenv/registry"]
```

```bash
conjur init --url http://localhost:8083 --account myorg
conjur login
secretenv doctor
secretenv run -- npm start
```

### Multi-account setup

```toml
[backends.conjur-eng]
type                 = "conjur"
conjur_appliance_url = "https://conjur.company.com"
conjur_account       = "engineering"

[backends.conjur-payments]
type                 = "conjur"
conjur_appliance_url = "https://conjur.company.com"
conjur_account       = "payments"

[registries.eng]
sources = ["conjur-eng://secretenv/registry"]

[registries.payments]
sources = ["conjur-payments://secretenv/registry"]
```

Deploy with: `secretenv run --registry payments -- ./deploy.sh`

### As registry source

Variable `prod/secretenv/registry` holds:

```json
{
  "stripe-key": "conjur-prod://prod/stripe/live-key",
  "db-url": "conjur-prod://prod/db/connection-string#json-key=url",
  "slack-token": "conjur-prod://prod/integrations/slack#json-key=token"
}
```

## Troubleshooting

**"not authenticated — session expired"**
Run `conjur login` (or `conjur init` then `conjur login` on first setup). The CLI persists sessions in your OS keystore automatically.

**"conjur: 'variable' is not a conjur command"**
You're running Conjur v7 (Ruby). SecretEnv requires v8 (Go). Uninstall `pip install conjur` and use the official `cyberark/conjur-cli:8` Docker image instead.

**"HTTP 403 Forbidden" or "Variable not found"**
Check your policy grants `read` (or `read, execute`) privilege on the target variable. Use `conjur resource check conjur:variable:prod/your-var read` to verify.

## See Also

- [`secretenv doctor`](../../README.md#operational-health-secretenv-doctor) — health checks for all backends
- [Alias registry concepts](../reference/registry.md) — how registry sources resolve aliases
- [Fragment vocabulary](../reference/fragment-vocabulary.md) — `#json-key`, `#version`, etc.
- [Vault backend](vault.md) — alternative: KV-mount-based secrets management
- [OpenBao backend](openbao.md) — alternative: Vault-compatible, open-source
- [All backends](README.md) — pick a different backend
- [Main README](../../README.md) — overview + workflows
