# GCP Secret Manager

**Type:** `gcp`  
**CLI required:** `gcloud` (Google Cloud SDK 380+)  
**URI scheme:** `<instance-name>:///<secret-name>[#version=<n>]`

---

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
| `gcp_project` | Yes | GCP project ID where the secrets live |
| `gcp_impersonate_service_account` | No | Service account email to impersonate for every operation. Requires `roles/iam.serviceAccountTokenCreator` on the target SA. |

---

## URI Format

```
gcp-prod:///stripe_api_key
└────────┘   └───────────┘
instance      secret name
```

Use triple-slash (`gcp-prod:///stripe_key`) — the project is always in config, never the URI. This matches the convention across all cloud backends.

### Fragment directives

Append `#version=<n>` to pin a specific secret version:

```
gcp-prod:///stripe_api_key#version=5          # Pin to version 5
gcp-prod:///stripe_api_key#version=latest     # Explicit latest (same as omitting)
gcp-prod:///stripe_api_key                    # Default: latest enabled version
```

| URI | Result |
|---|---|
| `gcp-prod:///my-secret` | Latest enabled version |
| `gcp-prod:///my-secret#version=latest` | Same as above |
| `gcp-prod:///my-secret#version=5` | Version 5 explicitly |
| `gcp-prod:///my-secret#version=abc` | **Rejected** — version must be a positive integer or `latest` |
| `gcp-prod:///my-secret#secret` | **Rejected** — legacy shorthand; use `#version=...` |
| `gcp-prod:///my-secret#scope=ro` | **Rejected** — `scope` is not a gcp directive |

`version` is the only fragment directive the gcp backend recognizes. See [../fragment-vocabulary.md](../fragment-vocabulary.md) for the full grammar.

---

## Authentication

secretenv delegates entirely to the `gcloud` CLI. All of these work:

- **User account** — `gcloud auth login` (browser OAuth).
- **Service account key file** — set `GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json`, or run `gcloud auth activate-service-account --key-file /path/to/key.json`.
- **Workload Identity (GKE)** — pod-mounted credentials; zero config.
- **Compute Engine metadata** — VM-attached service account; zero config.
- **Cloud Shell** — pre-authenticated.
- **Impersonation** — set `gcp_impersonate_service_account` in the backend config; every call adds `--impersonate-service-account`.

secretenv has zero auth code. If `gcloud <any-command>` works in your shell, the backend will too.

---

## IAM Permissions

### Read-only (for `secretenv run`)

Grant `roles/secretmanager.secretAccessor` at the secret or project level.

Per-secret (least privilege):

```bash
gcloud secrets add-iam-policy-binding stripe_api_key \
  --role=roles/secretmanager.secretAccessor \
  --member=user:alice@example.com
```

Project-wide:

```bash
gcloud projects add-iam-policy-binding my-project-prod \
  --role=roles/secretmanager.secretAccessor \
  --member=user:alice@example.com
```

### Read-write (for `registry set` / `delete`)

Grant `roles/secretmanager.admin` OR a custom role with:

- `secretmanager.versions.add` (for `set`)
- `secretmanager.secrets.delete` (for `delete`)
- `secretmanager.secrets.get` + `secretmanager.versions.access` (for read, inherited from accessor)

**Note on `set`:** secretenv's `set` is **update-only** — it adds a new version to an existing secret. Create the secret first with `gcloud secrets create <name>` (one-time setup); afterwards `registry set` adds versions.

### Impersonation

If `gcp_impersonate_service_account` is configured, the CALLER needs `roles/iam.serviceAccountTokenCreator` on the target SA:

```bash
gcloud iam service-accounts add-iam-policy-binding \
  secretenv-reader@my-project-prod.iam.gserviceaccount.com \
  --role=roles/iam.serviceAccountTokenCreator \
  --member=user:alice@example.com
```

The impersonated SA then needs the accessor role on the secrets.

---

## How `secretenv doctor` reports GCP status

```
├── gcp-prod [gcp]
│   ✓ ready
│     cli:      Google Cloud SDK 458.0.1
│     identity: account=alice@example.com project=my-project-prod
```

With impersonation:

```
├── gcp-prod [gcp]
│   ✓ ready
│     cli:      Google Cloud SDK 458.0.1
│     identity: account=alice@example.com project=my-project-prod impersonate=secretenv-reader@my-project-prod.iam.gserviceaccount.com
```

If not authenticated:

```
├── gcp-prod [gcp]
│   ✗ not authenticated
│     run: gcloud auth login  OR  gcloud auth activate-service-account --key-file <path>
```

---

## Known Limitations

- **Update-only `set`.** The secret must exist before `registry set` can add a version. Create with `gcloud secrets create <name>` first.
- **Delete removes the whole secret.** No soft-delete / recovery window (matches aws-secrets and vault). All versions are destroyed.
- **Multi-region only.** Regional secrets (launched late 2024) require `--location <region>`; not supported in v0.3. Will add in a follow-up.
- **`latest` is a keyword.** `#version=latest` behaves identically to omitting the fragment. Future-proofs readability in registry documents.
- **No binary secret support.** GCP Secret Manager stores bytes; the `gcloud` CLI decodes on read. Strings only for v0.3.

---

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `NOT_FOUND: Secret [...]` | Secret doesn't exist or typo'd | Check `gcloud secrets list --project <p>` |
| `PERMISSION_DENIED` | Missing accessor role | `gcloud secrets add-iam-policy-binding ... --role=roles/secretmanager.secretAccessor` |
| `FAILED_PRECONDITION: ... DESTROYED` | Version explicitly destroyed | Access a different version or restore |
| `NotAuthenticated` on `doctor` | `gcloud` session expired | `gcloud auth login` |
| `strict-mock-no-match` in unit tests | Developer-facing — see [../fragment-vocabulary.md](../fragment-vocabulary.md) |
