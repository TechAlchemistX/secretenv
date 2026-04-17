# GCP Secret Manager

**Type:** `gcp`  
**CLI required:** `gcloud` (Google Cloud SDK)  
**URI scheme:** `<instance-name>://project-id/secret-name`

---

## Configuration

```toml
[backends.gcp-prod]
type        = "gcp"
gcp_project = "my-project-prod"   # required
```

### Fields

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Must be `"gcp"` |
| `gcp_project` | Yes | GCP project ID where secrets live |

---

## URI Format

```
gcp-prod://my-project-prod/stripe_api_key
└────────┘  └─────────────┘ └─────────────┘
instance    project id       secret name
```

secretenv always fetches the latest enabled version. Version pinning is not currently supported.

---

## Authentication

secretenv delegates to the `gcloud` CLI. Supported mechanisms:

- Application Default Credentials (`gcloud auth application-default login`)
- Service account key file (`GOOGLE_APPLICATION_CREDENTIALS`)
- Workload Identity (GKE)
- Cloud Shell credentials

---

## IAM Permissions

The identity accessing secrets needs `roles/secretmanager.secretAccessor` on the specific secrets or the project.

---

# Local File

**Type:** `local`  
**CLI required:** None  
**URI scheme:** `<instance-name>:///path/to/file.toml`

---

## Configuration

```toml
[backends.local]
type = "local"
```

No credential fields. Reads from the local filesystem directly.

---

## URI Format

```
local:///Users/yourname/.config/secretenv/local-registry.toml
```

The file at the path must be a flat TOML key-value document.

---

## Use Cases

- Solo developers who want zero-infrastructure local workflow
- Development environments where cloud backends are overkill
- Offline development
- Testing secretenv itself

---

## Local Registry File Format

```toml
# ~/.config/secretenv/local-registry.toml

stripe-key  = "keychain://secretenv/stripe-key"
dev-db-url  = "keychain://secretenv/dev-db-url"
api-key     = "keychain://secretenv/api-key"
```

The local backend is typically used as a registry source pointing to keychain entries, not as a secret store itself (though it can store plaintext values for non-sensitive defaults).

---

## Security Note

If the local registry file contains actual secret values rather than pointers to a credential store, ensure it is `chmod 600` and excluded from any backup solutions that sync to cloud storage.
