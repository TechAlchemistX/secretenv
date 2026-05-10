# GCP Secret Manager

**Type:** `gcp`
**CLI required:** [`gcloud`](https://cloud.google.com/sdk/docs/install) (Google Cloud SDK 380+)
**URI scheme:** `<instance>:///<secret-name>[#version=<n>]`
**Platform:** all (macOS, Linux, Windows)
**Tested:** `Google Cloud SDK 560.0.0` on macOS Darwin 25.4 (SecretEnv v0.13.0, 2026-05-07)

> SecretEnv injects secrets from any backend as environment variables. This page covers the `gcp` backend. New here? See the [overview](/).

GCP Secret Manager is Google Cloud's native secrets store, deeply integrated with GCP identity and access management. It offers fine-grained IAM roles, version management, and seamless authentication on GCP compute (Workload Identity on GKE, instance metadata on Compute Engine). Pick Secret Manager when you're on Google Cloud and want the simplest, tightest integration path.

## When to pick this

- **You're on Google Cloud:** native integration, automatic credential discovery via ADC
- **Workload Identity (GKE):** Pod-mounted service account tokens; zero config
- **Service account impersonation:** Optional per-operation impersonation for privilege escalation
- **Version management:** Pin to specific secret versions for canary testing or rollbacks

## Configuration

```toml
[backends.gcp-prod]
type        = "gcp"
gcp_project = "my-project-prod"
# Optional — impersonate a service account on every call:
# gcp_impersonate_service_account = "secretenv-reader@my-project-prod.iam.gserviceaccount.com"
```

### Fields

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Must be `"gcp"` |
| `gcp_project` | Yes | GCP project ID where secrets live |
| `gcp_impersonate_service_account` | No | Service account email to impersonate. Caller must have `roles/iam.serviceAccountTokenCreator` on this SA. |
| `timeout_secs` | No | Per-instance fetch timeout override. Default: 30s. |

## URI Format

```
gcp-prod:///stripe_api_key
└────────┘   └─────────────┘
instance     secret name
```

Use triple-slash (`gcp-prod:///secret-name`) — the project is always in config, never in the URI. Secret names follow GCP rules: `[a-zA-Z0-9_-]{1,255}`.

For version pinning:

```
gcp-prod:///stripe_api_key#version=5          # Pin to version 5
gcp-prod:///stripe_api_key#version=latest     # Explicit latest (same as omitting)
gcp-prod:///stripe_api_key                    # Default: latest enabled version
```

**Verify your setup with:** `secretenv doctor` — green output means you're ready to run `secretenv run -- <your command>`.

## Authentication

SecretEnv delegates entirely to the `gcloud` CLI. All of these work:

- **Application Default Credentials (ADC):** `gcloud auth application-default login` or automatic on GCP compute
- **User account:** `gcloud auth login` (browser OAuth)
- **Service account key file:** `gcloud auth activate-service-account --key-file /path/to/key.json`
- **Workload Identity (GKE):** Pod-mounted service account tokens; zero config
- **Compute Engine metadata:** VM-attached service account; zero config
- **Cloud Shell:** Pre-authenticated

If `gcloud <any-command>` works in your shell, the backend will too.

## IAM Permissions

### Read-only (for `secretenv run`)

Grant `roles/secretmanager.secretAccessor` at the secret or project level:

```bash
gcloud secrets add-iam-policy-binding stripe_api_key \
  --role=roles/secretmanager.secretAccessor \
  --member=user:alice@example.com
```

### Read-write (for `registry set` / `delete`)

Grant `roles/secretmanager.admin` OR a custom role with:

- `secretmanager.versions.add` (for `set`)
- `secretmanager.secrets.delete` (for `delete`)

**Note on `set`:** the secret must exist first. Create with `gcloud secrets create <name>` once; afterwards `registry set` adds versions.

### Impersonation

If `gcp_impersonate_service_account` is configured, the caller needs `roles/iam.serviceAccountTokenCreator` on the target SA:

```bash
gcloud iam service-accounts add-iam-policy-binding \
  secretenv-reader@my-project-prod.iam.gserviceaccount.com \
  --role=roles/iam.serviceAccountTokenCreator \
  --member=user:alice@example.com
```

The impersonated SA then needs the accessor role on the secrets.

## doctor Output

Healthy state:

```
gcp-prod                                                          (gcp)
  ✓ gcloud CLI v560.0.0
  ✓ authenticated  account=alice@example.com  project=my-project-prod
```

With impersonation:

```
gcp-prod                                                          (gcp)
  ✓ gcloud CLI v560.0.0
  ✓ authenticated  account=alice@example.com  project=my-project-prod  impersonate=secretenv-reader@my-project.iam.gserviceaccount.com
```

## Fragment directives

`#version=<n>` pins a specific version. Version IDs are positive integers:

| Directive | Effect | Example |
|---|---|---|
| `#version=5` | Fetch version 5 explicitly | `gcp-prod:///stripe_key#version=5` |
| `#version=latest` | Explicit latest (same as omitting) | `gcp-prod:///stripe_key#version=latest` |
| (no fragment) | Fetch the latest enabled version | `gcp-prod:///stripe_key` |

Shorthand fragments and non-integer versions are rejected with a migration hint.

## History API support

Partial. `secretenv registry history <alias>` surfaces version number and creation timestamp via `gcloud secrets versions list`. Actor name and change descriptions are not available via the `gcloud` CLI.

## Limitations

- **Update-only `set`.** The secret must exist before `registry set` can add a version. Create with `gcloud secrets create <name>` first.
- **Delete removes entire secret.** `secretenv registry delete` removes all versions. Use `gcloud secrets versions destroy` for per-version destruction.
- **Secret names are case-sensitive.** `stripe-key` ≠ `stripe-Key`.
- **No regional secrets.** Regional secrets (launched late 2024) require `--location <region>`; v0.13 always uses multi-region (the default).
- **No binary secret support.** GCP Secret Manager stores bytes; the `gcloud` CLI decodes on read. Strings only for v0.13.

## Examples

### Single project, local development

```toml
[backends.gcp-dev]
type        = "gcp"
gcp_project = "my-project-dev"

[registries.default]
sources = ["gcp-dev:///myapp_registry"]
```

```bash
secretenv run -- npm start
```

### Multi-project with impersonation

```toml
[backends.gcp-prod-ci]
type        = "gcp"
gcp_project = "my-project-prod"
gcp_impersonate_service_account = "ci-runner@my-project-prod.iam.gserviceaccount.com"

[registries.prod]
sources = ["gcp-prod-ci:///myapp_registry"]
```

### Version pinning for canary testing

Pin a specific version via the registry:

```bash
secretenv registry set db-pass "gcp-prod:///db_password#version=3"
```

## Troubleshooting

**"NOT_FOUND: Secret [...]"**
Verify the secret exists and is in the correct project. Use `gcloud secrets list --project <project>` to list all secrets.

**"PERMISSION_DENIED"**
Check your IAM role. Run `gcloud projects get-iam-policy <project>` to see your current roles, and grant `roles/secretmanager.secretAccessor` if needed.

**"NotAuthenticated" on `secretenv doctor`**
Run `gcloud auth login` or `gcloud auth activate-service-account --key-file <path>` to set up credentials.

## See Also

- [`secretenv doctor`](/reference/cli-reference-full#secretenv-doctor) — health checks for all backends
- [Alias registry concepts](../reference/registry.md) — how registry sources resolve aliases
- [Fragment vocabulary](../reference/fragment-vocabulary.md) — `#version` directive reference
- [GCP Secret Manager documentation](https://cloud.google.com/secret-manager/docs) — permissions, versions, replication
- [All backends](README.md) — pick a different backend
- [Overview](/) — overview + workflows
