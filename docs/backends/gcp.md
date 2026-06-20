# GCP Secret Manager

- **Type:** `gcp`
- **CLI required:** [`gcloud`](https://cloud.google.com/sdk/docs/install)
- **CLI version:** Google Cloud SDK 380+
- **URI scheme:** `<instance>:///<secret-name>[#version=<n>]`
- **Platform:** all (macOS, Linux, Windows)
- **Tested:** `Google Cloud SDK 560.0.0` on macOS Darwin 25.4 (SecretEnv v0.19.0)

> SecretEnv injects secrets from any backend as environment variables. This page covers the `gcp` backend. New here? See the [overview](/).

GCP Secret Manager is Google Cloud's native secrets store with fine-grained IAM, version management, and seamless authentication on GCP compute (Workload Identity on GKE, instance metadata on Compute Engine).

## When to pick this

- **On Google Cloud:** native integration, automatic credential discovery via ADC
- **Workload Identity (GKE):** Pod-mounted service account tokens; zero config
- **Service account impersonation:** for privilege escalation
- **Version pinning:** canary testing or rollbacks

## Configuration

```toml
[backends.gcp-prod]
type        = "gcp"
gcp_project = "my-project-prod"
# Optional, impersonate a service account on every call:
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

Use triple-slash (`gcp-prod:///secret-name`). Secret names follow GCP rules: `[a-zA-Z0-9_-]{1,255}`.

For version pinning:

```
gcp-prod:///stripe_api_key#version=5          # Pin to version 5
gcp-prod:///stripe_api_key#version=latest     # Explicit latest (same as omitting)
gcp-prod:///stripe_api_key                    # Default: latest enabled version
```

**Verify your setup with:** `secretenv doctor`. Green output means you're ready to run `secretenv run -- <your command>`.

## Authentication

SecretEnv delegates to the `gcloud` CLI. Any credential method the CLI supports works automatically:

- **Application Default Credentials (ADC)**, `gcloud auth application-default login` or automatic on GCP compute
- **User account**, `gcloud auth login` (browser OAuth)
- **Service account key**, `gcloud auth activate-service-account --key-file /path/to/key.json`
- **Workload Identity (GKE)**, Pod-mounted tokens; zero config
- **Compute Engine metadata**, VM-attached service account; zero config
- **Cloud Shell**, Pre-authenticated

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

`#version=<n>` pins specific versions (positive integers):

| Directive | Effect | Example |
|---|---|---|
| `#version=5` | Version 5 | `gcp-prod:///stripe_key#version=5` |
| `#version=latest` | Latest (same as omitting) | `gcp-prod:///stripe_key#version=latest` |
| (no fragment) | Latest enabled version | `gcp-prod:///stripe_key` |

## History API support

Not implemented. The backend returns the trait-default "not implemented" error. GCP Secret Manager exposes version lists via `gcloud secrets versions list` and the REST API, but this backend does not yet call that surface. Version history is available in the GCP Console or via `gcloud` directly.

## Limitations

- **Update-only `set`.** Secret must exist before `registry set` can add versions. Create with `gcloud secrets create <name>` first.
- **Delete removes entire secret.** `registry delete` removes all versions. Use `gcloud secrets versions destroy` per-version.
- **Secret names are case-sensitive:** `stripe-key` ≠ `stripe-Key`.
- **No regional secrets.** Regional secrets require `--location <region>`; v0.13 uses multi-region (default).
- **Strings only.** v0.13 doesn't support binary secrets.

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
Secret doesn't exist in the project. Use `gcloud secrets list --project <project>` to verify.

**"PERMISSION_DENIED"**
Check IAM role with `gcloud projects get-iam-policy <project>`. Grant `roles/secretmanager.secretAccessor` if needed.

**"NotAuthenticated"**
Run `gcloud auth login` or `gcloud auth activate-service-account --key-file <path>`.

## See Also

- [`secretenv doctor`](/reference/cli-reference-full#secretenv-doctor), health checks for all backends
- [Alias registry concepts](../reference/registry.md), how registry sources resolve aliases
- [Fragment vocabulary](../reference/fragment-vocabulary.md), `#version` directive reference
- [GCP Secret Manager documentation](https://cloud.google.com/secret-manager/docs), permissions, versions, replication
- [All backends](README.md), pick a different backend
- [Overview](/), overview + workflows
