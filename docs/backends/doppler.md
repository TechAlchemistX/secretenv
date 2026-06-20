# Doppler

- **Type:** `doppler`
- **CLI required:** [`doppler`](https://docs.doppler.com/docs/install-cli)
- **CLI version:** v3+
- **URI scheme:** `<instance-name>:///<project>/<config>/<secret>` (full) or `<instance-name>:///<secret>` (short, when config supplies defaults). No fragment directives supported.
- **Platform:** all (macOS, Linux, Windows)
- **Tested:** `doppler v3.76.0` on macOS Darwin 25.4 (SecretEnv v0.19.0)

> SecretEnv injects secrets from any backend as environment variables. This page covers the `doppler` backend. New here? See the [overview](/).

Doppler is a SaaS secrets manager with a clean CLI. The `doppler` CLI resolves auth from `DOPPLER_TOKEN` env var, `doppler login` keychain, or config-scoped token.

## When to pick this

- **Multi-project workflows:** named projects + environments scope one machine to different teams
- **Developer-friendly dashboard:** interactive UI exploration
- **Audit + rotation:** tracks changes, supports scheduled rotation
- **CI/CD:** mint scoped service tokens per pipeline, no keychain needed

## Configuration

```toml
[backends.doppler-prod]
type             = "doppler"
doppler_project  = "acme"           # optional, short-form default
doppler_config   = "prd"            # optional, short-form default (both-or-neither)
doppler_token    = "dp.st.prd.…"    # optional, override $DOPPLER_TOKEN
```

### Fields

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Must be `"doppler"` |
| `doppler_project` | No | Default project for short-form URIs. Must pair with `doppler_config` (both or neither). |
| `doppler_config` | No | Default Doppler config (environment slug like `dev`, `stg`, `prd`). Must pair with `doppler_project`. |
| `doppler_token` | No | Per-instance token override. Passed via `DOPPLER_TOKEN` env (never argv). Prefer `$DOPPLER_TOKEN` in CI; use config only for multi-account routing. |
| `doppler_unsafe_set` | No | Defense-in-depth opt-in for argv-based `set`. Defaults to `false`; `set` is refused without it. |
| `timeout_secs` | No | Per-instance fetch timeout. Default: 30s. |

### Multiple Doppler accounts

```toml
[backends.doppler-acme]
type           = "doppler"
doppler_token  = "dp.st.prd.ACME_TOKEN"

[backends.doppler-consulting]
type           = "doppler"
doppler_token  = "dp.st.prd.CONSULTING_TOKEN"
```

## URI Format

```
doppler-prod:///acme/prd/STRIPE_API_KEY
└──────────┘    └──┘ └─┘ └────────────┘
instance name   proj cfg secret name
```

Full form requires three segments: `<project>/<config>/<secret>`. Short form (one segment) requires both `doppler_project` and `doppler_config` in config. Secret names follow `[A-Z_][A-Z0-9_]*` (all-caps, underscores).

**Verify your setup with:** `secretenv doctor`. Green output means you're ready to run `secretenv run -- <your command>`.

## Authentication

Precedence (highest wins):

1. **`doppler_token` config field**, via `DOPPLER_TOKEN` env
2. **`$DOPPLER_TOKEN` env var**, from parent shell
3. **`doppler login` keychain**, cached login token

Service tokens (`dp.st.<config>.*`) are scoped to a project + config at mint. Verify token scope matches the URI.

## doctor Output

Healthy:

```
doppler-prod                                                  (doppler)
  ✓ doppler CLI v3.76.0
  ✓ authenticated  account=alice-mbp  workplace=TechAlchemist
```

Not authenticated (expired session or missing token):

```
doppler-prod                                                  (doppler)
  ✓ doppler CLI v3.76.0
  ✗ not authenticated
      → run: doppler login  OR  export DOPPLER_TOKEN=<your-token>
```

## Fragment directives

No fragment directives. Any `#...` fragment is rejected at URI-parse time.

## History API support

Not implemented. The `doppler` CLI has no per-secret version-history subcommand. Open the secret in the dashboard to view history.

## Limitations

- **No stdin set.** `doppler secrets set` reads the value through argv. Gated behind `doppler_unsafe_set = true`.
- **`list()` synthetic keys filtered.** `doppler secrets download` injects `DOPPLER_PROJECT`, `DOPPLER_CONFIG`, `DOPPLER_ENVIRONMENT` keys. Automatically filtered from registry-source enumerations.
- **No folder scoping.** Doppler organizes by project + config only. Use naming conventions (underscores) for nested structure.

## Examples

### Single dev instance

```toml
[backends.doppler-dev]
type             = "doppler"
doppler_project  = "acme"
doppler_config   = "dev"

[registries.default]
sources = ["doppler-dev:///REGISTRY"]
```

```bash
secretenv run -- npm start
```

### Multi-environment

```toml
[backends.doppler-staging]
type             = "doppler"
doppler_project  = "acme"
doppler_config   = "stg"

[backends.doppler-prod]
type             = "doppler"
doppler_project  = "acme"
doppler_config   = "prd"

[registries.staging]
sources = ["doppler-staging:///REGISTRY"]

[registries.prod]
sources = ["doppler-prod:///REGISTRY"]
```

Deploy with: `secretenv run --registry prod -- ./deploy.sh`

### As registry source

Doppler secret `REGISTRY` holds:

```json
{
  "stripe_key": "doppler-prod:///acme/prd/STRIPE_API_KEY",
  "db_url": "vault-prod:///secret/db",
  "api_token": "doppler-prod:///acme/prd/API_TOKEN"
}
```

Then: `secretenv run --registry doppler-prod:///acme/prd/REGISTRY -- npm start`

## Troubleshooting

**"Doppler Error: Unauthorized: token not found"**
Token is malformed, revoked, or workspace changed. Run `doppler me --json` to verify.

**"Could not find requested secret: <name>"**
Secret doesn't exist in the scoped project + config. Verify via `secretenv doctor`.

**"Unexpected HTTP response 401 Unauthorized"**
Token scope mismatch. Service tokens lock to a project + config at mint. Verify scope with `doppler me --json`.

## See Also

- [`secretenv doctor`](/reference/cli-reference-full#secretenv-doctor), health checks for all backends
- [Alias registry concepts](../reference/registry.md), how registry sources resolve aliases
- [Fragment vocabulary](../reference/fragment-vocabulary.md), `#json-key`, `#version`, etc. on other backends
- [Doppler CLI reference](https://docs.doppler.com/docs/cli), authoritative Doppler docs
- [All backends](README.md), pick a different backend
- [Overview](/), overview + workflows
