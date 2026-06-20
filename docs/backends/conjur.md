# CyberArk Conjur

- **Type:** `conjur`
- **CLI required:** [`conjur`](https://github.com/cyberark/conjur-cli-go)
- **CLI version:** Go-based v8+ (v7 Ruby line is rejected at startup)
- **URI scheme:** `<instance-name>://<variable-id>[#json-key=<field>]`
- **Platform:** all (macOS, Linux, Windows)
- **Tested:** `Conjur CLI v8.1.3-879b90b` on macOS Darwin 25.4 (SecretEnv v0.19.0)

> SecretEnv injects secrets from any backend as environment variables. This page covers the `conjur` backend. New here? See the [overview](/).

CyberArk Conjur is the open-source PAM secrets store (Apache-2.0, same protocol across OSS and Enterprise). Unlike Vault's mount-and-path model, Conjur uses **resource-graph identity**. Every secret is a `variable` with policy-mediated access. SecretEnv treats the variable ID as the URI path. The v8 CLI is Go-based (`cyberark/conjur-cli:8` Docker image); the PyPI `conjur` package (Ruby v7) is rejected.

## When to pick this

- **Conjur Enterprise or OSS:** native integration, shared policy/audit
- **Complex permissions:** resource-graph model for fine-grained access
- **Containerized CI:** official v8 Docker image available

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
| `conjur_appliance_url` | Yes | Conjur server URL (HTTP or HTTPS). Local dev: `http://localhost:8083`. |
| `conjur_account` | Yes | Top-level account namespace (multi-tenant). Every variable under one account. |
| `conjur_authn` | No | Authenticator name. Default: `"authn"` (API-key). Other: `authn-jwt`, `authn-oidc`, `authn-iam`, `authn-k8s`, `authn-azure`, `authn-gcp`. Surfaced in `doctor` output. |
| `conjur_unsafe_set` | No | Opt into argv-based `-v <value>`. Default `false`; safe `/dev/stdin` used always. |
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

Conjur variables have no mount concept. The entire URI path IS the variable ID. SecretEnv strips a leading `/` and passes the rest to `conjur variable get -i <variable-id>`.

### `#json-key=<field>` fragment

When a variable holds a JSON object, extract a top-level scalar field:

```toml
db_password = "conjur-prod://prod/db/credentials#json-key=password"
db_username = "conjur-prod://prod/db/credentials#json-key=username"
```

The fragment is recognized on `get` only. `set`, `delete`, `list`, and `history` reject any fragment.

**Verify your setup with:** `secretenv doctor`. Green output means you're ready to run `secretenv run -- <your command>`.

## Authentication

SecretEnv delegates to the `conjur` CLI. The CLI's pre-established session controls actual auth. SecretEnv does not take credentials directly. Set `conjur_authn` to surface the configured authenticator in `secretenv doctor`:

- **API key** (`authn`, default), `conjur login -i <user>`. Session persisted in OS keystore (Keychain / Secret Service / Credential Manager) by default.
- **JWT** (`authn-jwt`), for CI / Kubernetes. Operator pre-establishes via `conjur login --jwt-from-file <path>`.
- **OIDC** (`authn-oidc`), browser / device-code flow.
- **Cloud-native** (`authn-iam`, `authn-azure`, `authn-gcp`, `authn-k8s`), workload identity flows. SecretEnv trusts the CLI's session.

### Set safety (no argv)

`set` uses `-f /dev/stdin` to pipe the value (safe; bytes never touch disk or argv). Switching to `-v <value>` argv requires `conjur_unsafe_set = true` (rare; only if `/dev/stdin` unavailable).

### Delete semantics

Conjur has **no `conjur variable delete` command**. Variables are policy-defined. SecretEnv's `delete()` implements **clear** semantics: it sets the value to the empty string via the safe stdin path. The variable retains its policy definition; only the value is emptied.

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
  ✗ not authenticated. session expired
      → run: conjur login  (or 'conjur init' then 'conjur login' if first-time)
```

CLI not found (v7 Ruby or not installed):

```
conjur-prod                                                      (conjur)
  ✗ conjur CLI not found
      → install: docker pull cyberark/conjur-cli:8 (alias `conjur` to a docker-run wrapper)
        see https://github.com/cyberark/conjur-cli-go for native builds
```

## Fragment directives

| Directive | Effect | Example |
|---|---|---|
| `json-key=<field>` | Extract top-level JSON field from variable value | `conjur-prod://prod/db/creds#json-key=password` |

Other fragments are rejected with an enumerated error listing supported directives.

## History API support

Not implemented. The CLI has no per-variable version-history subcommand. Server maintains audit logs; CLI support pending.

## Limitations

- **No variable deletion:** `delete()` clears the value (empty string); variable persists. Remove via policy reload only.
- **Go v8 CLI required:** PyPI `conjur` (Ruby v7) is EOL and rejected. Use `cyberark/conjur-cli:8` Docker image.
- **Scheme selection manual:** set correct scheme in `conjur_appliance_url` (HTTP dev, HTTPS prod).

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

**"not authenticated, session expired"**
Run `conjur login` (or `conjur init` then `conjur login` on first setup). The CLI persists sessions in your OS keystore automatically.

**"conjur: 'variable' is not a conjur command"**
You're running Conjur v7 (Ruby). SecretEnv requires v8 (Go). Uninstall `pip install conjur` and use the official `cyberark/conjur-cli:8` Docker image instead.

**"HTTP 403 Forbidden" or "Variable not found"**
Check your policy grants `read` (or `read, execute`) privilege on the target variable. Use `conjur resource check conjur:variable:prod/your-var read` to verify.

## See Also

- [`secretenv doctor`](/reference/cli-reference-full#secretenv-doctor), health checks for all backends
- [Alias registry concepts](../reference/registry.md), how registry sources resolve aliases
- [Fragment vocabulary](../reference/fragment-vocabulary.md), `#json-key`, `#version`, etc.
- [Vault backend](vault.md), alternative: KV-mount-based secrets management
- [OpenBao backend](openbao.md), alternative: Vault-compatible, open-source
- [All backends](README.md), pick a different backend
- [Overview](/), overview + workflows
