# Infisical

**Type:** `infisical`
**CLI required:** [`infisical`](https://infisical.com/docs/cli/overview) v0.43+
**URI scheme:** `<instance-name>:///<project-id>/<env>/<secret>` (full) or `<instance-name>:///<secret>` (short, when config supplies defaults). Nested folders fold into middle segments: `<project-id>/<env>/<folder1>/<folder2>/<secret>`.
**Platform:** all (macOS, Linux, Windows)
**Tested:** `infisical 0.43.79` on macOS Darwin 25.4 (SecretEnv v0.13.0, 2026-05-07)

> SecretEnv injects secrets from any backend as environment variables. This page covers the `infisical` backend. New here? See the [main README](../../README.md).

Infisical is an open-source secrets manager available as SaaS or self-hosted. Pick Infisical when you want a Doppler-like experience without vendor lock-in, with support for nested folder scoping and self-hosting. The `infisical` CLI wraps the API with a clean `secrets get / set / delete` surface.

## When to pick this

- **Self-hosted option:** run your own instance; Infisical Cloud (`app.infisical.com`) is also available
- **Folder-scoped secrets:** organize secrets in nested paths (`/api/stripe`, `/database/replica`)
- **Open source first:** MPL-2.0 license, community-driven governance
- **Team collaboration:** built-in role-based access, audit logging, secret rotation

## Configuration

```toml
[backends.infisical-prod]
type                  = "infisical"
infisical_project_id  = "abc-123-xyz"     # optional — short-form default
infisical_environment = "prod"            # optional — short-form default (both-or-neither)
infisical_secret_path = "/api"            # optional — default folder path (default: /)
infisical_domain      = "https://infisical.acme.com"  # optional — self-hosted domain
```

### Fields

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Must be `"infisical"` |
| `infisical_project_id` | No | Default project UUID for short-form URIs. Must pair with `infisical_environment` (both or neither). |
| `infisical_environment` | No | Default environment slug (`dev`, `staging`, `prod`, or custom). Must pair with `infisical_project_id`. |
| `infisical_secret_path` | No | Default folder path (e.g., `/api`, `/database`). Defaults to `/` when unset. |
| `infisical_domain` | No | Self-hosted instance URL. Passed via `INFISICAL_API_URL` env (never argv). Default: `https://app.infisical.com/api`. |
| `infisical_token` | No | Per-instance token override. Passed via `INFISICAL_TOKEN` env (never argv). Prefer env var in CI. |
| `infisical_unsafe_set` | No | Defense-in-depth opt-in for `set`. Defaults to `false`. |
| `timeout_secs` | No | Per-instance fetch timeout. Default: 30s. |

### Self-hosted domain trust

`infisical_domain` accepts any URL. A typo or lookalike domain routes credentials to an attacker. Before committing a self-hosted domain:

- Verify it matches your org's canonical Infisical install
- Pin HTTPS with a trusted cert (avoid `http://` except loopback)
- Confirm the TLS cert belongs to your org (inspect with `openssl s_client -connect ...`)
- Avoid registries pointing at domains you don't control

See [security.md#self-hosted-domains](../security.md#self-hosted-domains) for the full disclosure discipline.

### Multi-account setups

```toml
[backends.infisical-acme]
type             = "infisical"
infisical_token  = "st.xxx.ACME_TOKEN"

[backends.infisical-consulting]
type             = "infisical"
infisical_token  = "st.xxx.CONSULTING_TOKEN"
```

## URI Format

```
infisical-prod:///abc-123/prod/STRIPE_API_KEY
└────────────┘    └─────┘ └──┘ └────────────┘
instance name     project env  secret name
```

Full form: `<project-id>/<env>/<secret>`. Nested folders fold into middle segments: `abc-123/prod/api/stripe/KEY` → project=`abc-123`, env=`prod`, path=`/api/stripe`, secret=`KEY`. Short form (one segment) requires both project-id and environment in config.

**Verify your setup with:** `secretenv doctor` — green output means you're ready to run `secretenv run -- <your command>`.

## Authentication

Precedence (highest wins):

1. **`infisical_token` config field** — instance-scoped, via `INFISICAL_TOKEN` env
2. **`$INFISICAL_TOKEN` env var** — from parent shell
3. **`infisical login` local cache** — browser-based login, cached locally

Service tokens (`st.*`) are scoped to a project + environment + path at mint time. Ensure your token's scope matches the URI you're reading. Machine identities (via identity exchange) are also supported.

## doctor Output

Healthy (SaaS):

```
infisical-prod                                              (infisical)
  ✓ infisical CLI v0.43.79
  ✓ authenticated  domain=https://app.infisical.com/api
```

Healthy (self-hosted):

```
infisical-prod                                              (infisical)
  ✓ infisical CLI v0.43.79
  ✓ authenticated  domain=https://infisical.acme.com
```

Not authenticated:

```
infisical-prod                                              (infisical)
  ✓ infisical CLI v0.43.79
  ✗ not authenticated
      → run: infisical login  OR  export INFISICAL_TOKEN=<your-token>
```

## Fragment directives

No fragment directives. Any `#...` fragment is rejected at URI-parse time.

## History API support

Not implemented. The `infisical` CLI (v0.43.79) has no per-secret version-history subcommand; version history is available in the Infisical Dashboard and REST API. Open the secret in the dashboard to view its version history.

## Limitations

- **`doctor` pipe-deadlock fix in v0.13.** Earlier releases occasionally false-reported "not authenticated" because `Stdio::piped()` + `.status()` left stderr undrained when the upgrade-banner payload exceeded the OS pipe buffer. v0.13 uses `Stdio::null()`. No action needed when upgrading.
- **No stdin set form.** `infisical secrets set` requires `--file <path>`. The backend writes to a mode-0600 tempfile and passes `--type shared` to avoid personal-override scope corruption.
- **Self-hosted domain validation.** Domain trust is on the operator — a typo or lookalike routes all credentials to an attacker.

## Examples

### Single dev instance

```toml
[backends.infisical-dev]
type                  = "infisical"
infisical_project_id  = "abc-123"
infisical_environment = "dev"

[registries.default]
sources = ["infisical-dev:///REGISTRY"]
```

```bash
secretenv run -- npm start
```

### Multi-environment with folders

```toml
[backends.infisical-staging]
type                  = "infisical"
infisical_project_id  = "abc-123"
infisical_environment = "staging"
infisical_secret_path = "/api"

[backends.infisical-prod]
type                  = "infisical"
infisical_project_id  = "abc-123"
infisical_environment = "prod"
infisical_secret_path = "/api"
```

### As registry source

Project `abc-123`, env `prod`, path `/registry` holds:

```json
{
  "stripe_key": "infisical-prod:///abc-123/prod/api/stripe/STRIPE_KEY",
  "db_url": "vault-prod:///secret/db"
}
```

Then: `secretenv run --registry infisical-prod:///abc-123/prod/registry/REGISTRY -- npm start`

## Troubleshooting

**"error reading secret: invalid request body"**
Check that `infisical_secret_path` matches the folder where the secret exists. Use `infisical secrets list --path /...` to verify.

**"401 Unauthorized"**
Token is invalid, expired, or scoped to a different project/env. Run `infisical export` to test the token; it should succeed.

**"secret not found"**
The secret doesn't exist in the scoped project + env + path. Verify all three with `secretenv doctor` and `infisical secrets list`.

## See Also

- [`secretenv doctor`](../../README.md#operational-health-secretenv-doctor) — health checks for all backends
- [Alias registry concepts](../reference/registry.md) — how registry sources resolve aliases
- [Fragment vocabulary](../reference/fragment-vocabulary.md) — `#json-key`, `#version`, etc. on other backends
- [Self-hosted domain trust](../security.md#self-hosted-domains) — `infisical_domain` disclosure discipline
- [Infisical CLI reference](https://infisical.com/docs/cli/overview) — authoritative Infisical docs
- [All backends](README.md) — pick a different backend
- [Main README](../../README.md) — overview + workflows
