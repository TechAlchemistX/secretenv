# Azure Key Vault

**Type:** `azure`  
**CLI required:** `az` (Azure CLI 2.55+)  
**URI scheme:** `<instance-name>:///<secret-name>[#version=<id>]`

---

## Configuration

```toml
[backends.azure-prod]
type            = "azure"
azure_vault_url = "https://my-kv-prod.vault.azure.net/"
# Optional:
# azure_tenant       = "contoso.onmicrosoft.com"
# azure_subscription = "00000000-0000-0000-0000-000000000000"
```

### Fields

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Must be `"azure"` |
| `azure_vault_url` | Yes | Fully-qualified Key Vault HTTPS URL. Each Key Vault has its own endpoint — there is no global Azure endpoint. |
| `azure_tenant` | No | Tenant ID or domain. Needed for multi-tenant service principals. |
| `azure_subscription` | No | Subscription ID or name. Useful when your identity has many subscriptions. |

**Sovereign clouds** are supported via the native vault hostname:

- Public cloud: `https://<vault>.vault.azure.net/`
- China: `https://<vault>.vault.azure.cn/`
- US Gov: `https://<vault>.vault.usgovcloudapi.net/`
- Germany (legacy): `https://<vault>.vault.microsoftazure.de/`

---

## URI Format

```
azure-prod:///stripe-api-key
└──────────┘   └───────────┘
instance        secret name
```

Secret names follow Azure Key Vault's naming rules: alphanumerics and hyphens, 1–127 characters. Underscores, slashes, and other symbols are rejected.

### Fragment directives

Append `#version=<id>` to pin a specific version:

```
azure-prod:///stripe-api-key#version=abc123deadbeef...     # Pin to that 32-char hex version ID
azure-prod:///stripe-api-key                                # Default: latest enabled version
```

| URI | Result |
|---|---|
| `azure-prod:///my-secret` | Latest enabled version |
| `azure-prod:///my-secret#version=<32-char-hex>` | That specific version |
| `azure-prod:///my-secret#version=latest` | Same as omitting the fragment |
| `azure-prod:///my-secret#version=5` | **Rejected** — Azure version IDs are 32-char hex, not integers |
| `azure-prod:///my-secret#secret` | **Rejected** — legacy shorthand; use `#version=...` |
| `azure-prod:///my-secret#tenant=contoso` | **Rejected** — `tenant` is not an azure directive |

`version` is the only fragment directive the azure backend recognizes. See [../fragment-vocabulary.md](../fragment-vocabulary.md) for the grammar.

To find a version ID:

```bash
az keyvault secret list-versions \
  --vault-name my-kv-prod \
  --name stripe-api-key \
  --query '[].id' -o tsv
```

---

## Authentication

secretenv delegates to the `az` CLI. All of these work:

- **User interactive** — `az login` (device code or browser).
- **Service principal (password)** — `az login --service-principal --tenant <t> --username <client-id> --password <secret>`, OR env vars `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET`.
- **Service principal (certificate)** — `az login --service-principal --username <client-id> --tenant <t> --password <cert-path>`.
- **Managed identity** — on Azure compute (VM, App Service, Functions, AKS Workload Identity): `az login --identity`.
- **Federated credentials** — GitHub Actions `azure/login@v1` + Workload Identity Federation.
- **Azure Cloud Shell** — pre-authenticated.

secretenv has zero auth code. If `az <any-command>` works in your shell, the backend will too.

---

## IAM Permissions

Azure Key Vault has two permission models. A vault uses one or the other — check with:

```bash
az keyvault show --name my-kv-prod --query 'properties.enableRbacAuthorization'
# true  → RBAC model
# false → access policies (legacy)
```

### RBAC model (modern, default for new vaults)

**Read-only** (for `secretenv run`):

```bash
az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee alice@contoso.com \
  --scope "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/my-kv-prod"
```

**Read-write** (for `registry set` / `delete`):

```bash
az role assignment create \
  --role "Key Vault Secrets Officer" \
  --assignee alice@contoso.com \
  --scope "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/my-kv-prod"
```

### Access policies (legacy)

**Read-only:**

```bash
az keyvault set-policy \
  --name my-kv-prod \
  --upn alice@contoso.com \
  --secret-permissions get list
```

**Read-write:**

```bash
az keyvault set-policy \
  --name my-kv-prod \
  --upn alice@contoso.com \
  --secret-permissions get list set delete recover
```

**Recommendation:** use RBAC for new deployments. Access policies work but are harder to audit and don't integrate with Azure AD Privileged Identity Management.

---

## How `secretenv doctor` reports Azure status

```
├── azure-prod [azure]
│   ✓ ready
│     cli:      azure-cli 2.57.0
│     identity: user=alice@contoso.com tenant=00000000-0000-0000-0000-000000000000 subscription=Production vault=my-kv-prod
```

If not authenticated:

```
├── azure-prod [azure]
│   ✗ not authenticated
│     run: az login  OR  az login --service-principal --tenant <t> --username <client-id> --password <secret>
```

---

## Known Limitations

- **Soft-delete, not purge.** `secretenv registry unset` / delete operations call `az keyvault secret delete`, which soft-deletes the secret (default 90-day retention). The secret is RECOVERABLE for that window. To fully remove, run `az keyvault secret purge --name <name> --vault-name <vault>` manually. This **differs from aws-secrets** (which purges immediately) — it's an Azure-platform reality; soft-delete is not optional on vaults created after Feb 2025.
- **Text secrets only.** Key Vault supports `certificates` as a distinct resource type; v0.3 targets `secrets` only. A secret bound to a certificate returns with a `kid` field and the backend surfaces an error.
- **No Managed HSM support.** Azure's FIPS 140-3 Level 3 HSM uses a different CLI surface (`--hsm-name` not `--vault-name`). Not in v0.3.
- **Version IDs are opaque 32-char hex.** Operators typically copy-paste from the Azure portal or from `az keyvault secret list-versions`. Unlike GCP's integer versions, these are not human-memorable.
- **`--encoding utf-8` is always applied on `set`.** Azure CLI's default is `base64`; the backend forces `utf-8` to match what users expect. Binary secrets → not supported.

---

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `SecretNotFound` | Secret doesn't exist or typo'd | `az keyvault secret list --vault-name <v>` |
| `Forbidden` | Missing RBAC role / access policy | See IAM section; check `az keyvault show --query properties.enableRbacAuthorization` |
| `Could not find a vault with name` | `azure_vault_url` points at a deleted or typo'd vault | Verify with `az keyvault list` |
| `Conflict: secret has been deleted but not purged` | Soft-deleted; recovery window active | `az keyvault secret recover --name <n> --vault-name <v>` or wait/purge |
| `NotAuthenticated` on `doctor` | `az` session expired | `az login` |
| `Could not find key vault ... in tenant` | SP registered in a different tenant than configured | Set `azure_tenant` explicitly |

---

## `registry set` — Creating a new secret

Unlike aws-secrets / gcp, Azure `set` **auto-creates** the secret if it doesn't exist. A single `secretenv registry set <alias> 'azure-prod:///<name>'` works on both existing and new secrets. The behavior matches `az keyvault secret set`.
