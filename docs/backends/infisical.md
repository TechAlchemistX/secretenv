# Infisical

- **Type:** `infisical`
- **CLI required:** [`infisical`](https://infisical.com/docs/cli/overview)
- **CLI version:** v0.43+
- **URI scheme:** `<instance-name>:///<project-id>/<env>/<secret>` (full) or `<instance-name>:///<secret>` (short, when config supplies defaults). Nested folders fold into middle segments: `<project-id>/<env>/<folder1>/<folder2>/<secret>`.
- **Platform:** all (macOS, Linux, Windows)
- **Tested:** `infisical 0.43.79` on macOS Darwin 25.4 (SecretEnv v0.19.0)

> SecretEnv injects secrets from any backend as environment variables. This page covers the `infisical` backend. New here? See the [overview](/).

Infisical is an open-source secrets manager available as SaaS or self-hosted, with nested folder scoping and a clean CLI (`secrets get / set / delete`).

## When to pick this

- **Self-hosted option:** run your own instance or use Infisical Cloud (`app.infisical.com`)
- **Folder-scoped secrets:** organize in nested paths (`/api/stripe`, `/database/replica`)
- **Open source:** MPL-2.0 license, community-driven
- **Team collaboration:** role-based access, audit logging, secret rotation

## Configuration

```toml
[backends.infisical-prod]
type                  = "infisical"
infisical_project_id  = "abc-123-xyz"     # optional, short-form default
infisical_environment = "prod"            # optional, short-form default (both-or-neither)
infisical_secret_path = "/api"            # optional, default folder path (default: /)
infisical_domain      = "https://infisical.acme.com"  # optional, self-hosted domain
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

`infisical_domain` accepts any URL. A typo or lookalike routes credentials to an attacker. Before committing:

- Verify it matches your org's canonical Infisical install
- Pin HTTPS with trusted cert (avoid `http://` except loopback)
- Confirm TLS cert belongs to your org (`openssl s_client -connect ...`)

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

Full form: `<project-id>/<env>/<secret>`. Nested folders fold into middle segments: `abc-123/prod/api/stripe/KEY` → project=`abc-123`, env=`prod`, path=`/api/stripe`, secret=`KEY`. Short form (one segment) requires both in config.

**Verify your setup with:** `secretenv doctor`. Green output means you're ready to run `secretenv run -- <your command>`.

## Authentication

Precedence (highest wins):

1. **`infisical_token` config field**, via `INFISICAL_TOKEN` env
2. **`$INFISICAL_TOKEN` env var**, from parent shell
3. **`infisical login` local cache**, browser-based login

Service tokens (`st.*`) are scoped to project + environment + path at mint. Verify token scope matches the URI. Machine identities (via identity exchange) also supported.

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

Not implemented. The `infisical` CLI has no per-secret version-history subcommand. Open the secret in the dashboard to view history.

## Limitations

- **`doctor` pipe-deadlock fix in v0.13.** Earlier releases false-reported "not authenticated" due to undrained stderr. v0.13 uses `Stdio::null()`. No action needed upgrading.
- **No stdin set.** `infisical secrets set` requires `--file <path>`. Backend writes to mode-0600 tempfile + `--type shared` to avoid personal-override corruption.
- **Self-hosted domain validation.** Domain trust is on the operator; typos or lookalikes route credentials to attackers.

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
Check that `infisical_secret_path` matches the folder. Use `infisical secrets list --path /...` to verify.

**"401 Unauthorized"**
Token is invalid, expired, or scoped to a different project/env. Run `infisical export` to test.

**"secret not found"**
Secret doesn't exist in the scoped project + env + path. Verify with `secretenv doctor` and `infisical secrets list`.

## See Also

- [`secretenv doctor`](/reference/cli-reference-full#secretenv-doctor), health checks for all backends
- [Alias registry concepts](../reference/registry.md), how registry sources resolve aliases
- [Fragment vocabulary](../reference/fragment-vocabulary.md), `#json-key`, `#version`, etc. on other backends
- [Self-hosted domain trust](../security.md#self-hosted-domains), `infisical_domain` disclosure discipline
- [Infisical CLI reference](https://infisical.com/docs/cli/overview), authoritative Infisical docs
- [All backends](README.md), pick a different backend
- [Overview](/), overview + workflows
