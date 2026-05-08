# Azure Key Vault

**Type:** `azure`
**CLI required:** [`az`](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) (Azure CLI 2.55+)
**URI scheme:** `<instance>:///<secret-name>[#version=<id>]`
**Platform:** all (macOS, Linux, Windows)
**Tested:** `azure-cli 2.85.0` on macOS Darwin 25.4 (SecretEnv v0.13.0, 2026-05-07)

> SecretEnv injects secrets from any backend as environment variables. This page covers the `azure` backend. New here? See the [main README](../../README.md).

Azure Key Vault is Microsoft Azure's native secrets store, offering centralized credential management with fine-grained RBAC and comprehensive audit logging. Key Vault integrates seamlessly with Azure Managed Identities, allowing pods and VMs to authenticate without managing credentials. Pick Key Vault when you're on Azure or need a multi-cloud strategy with an Azure anchor.

## When to pick this

- **You're on Azure:** native integration, Managed Identity automatic credential discovery
- **RBAC / audit compliance:** Fine-grained roles per secret; full audit trail of access
- **Sovereign clouds:** Support for Azure Commercial, China, US Government, and legacy Germany clouds
- **Soft-delete recovery:** Secrets are recoverable for 90 days (customizable) after deletion

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
| `azure_vault_url` | Yes | Fully-qualified Key Vault HTTPS URL. Each vault has its own unique endpoint. |
| `azure_tenant` | No | Tenant ID or domain. Required for multi-tenant service principals. |
| `azure_subscription` | No | Subscription ID or name. Useful when your identity has many subscriptions. |
| `timeout_secs` | No | Per-instance fetch timeout override. Default: 30s. |

**Sovereign cloud URLs:**
- Public cloud: `https://<vault>.vault.azure.net/`
- China: `https://<vault>.vault.azure.cn/`
- US Government: `https://<vault>.vault.usgovcloudapi.net/`
- Germany (legacy): `https://<vault>.vault.microsoftazure.de/`

## URI Format

```
azure-prod:///stripe-api-key
└──────────┘   └───────────┘
instance       secret name
```

Use triple-slash (`azure-prod:///secret-name`) — the vault URL is in config, never the URI. Secret names follow Azure rules: `[a-zA-Z0-9-]{1,127}` (alphanumerics and hyphens only, no underscores).

For version pinning:

```
azure-prod:///stripe-api-key#version=abc123deadbeef0123456789abcdef01
azure-prod:///stripe-api-key                  # Default: latest enabled version
```

**Verify your setup with:** `secretenv doctor` — green output means you're ready to run `secretenv run -- <your command>`.

## Authentication

SecretEnv delegates to the `az` CLI. All of these work:

- **User interactive:** `az login` (device code or browser)
- **Service principal (password):** `az login --service-principal --tenant <t> --username <client-id> --password <secret>`
- **Service principal (certificate):** `az login --service-principal --username <client-id> --tenant <t> --password <cert-path>`
- **Managed Identity:** `az login --identity` (on Azure compute: VMs, App Service, AKS, Functions)
- **Federated credentials:** GitHub Actions `azure/login@v1` + Workload Identity Federation
- **Azure Cloud Shell:** Pre-authenticated

If `az <any-command>` works in your shell, the backend will too.

## IAM Permissions

Azure Key Vault uses two permission models. Check which your vault uses:

```bash
az keyvault show --name my-kv-prod --query 'properties.enableRbacAuthorization'
# true  → RBAC model
# false → access policies (legacy)
```

### RBAC model (modern, default for new vaults)

Read-only (for `secretenv run`):

```bash
az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee alice@contoso.com \
  --scope "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/my-kv-prod"
```

Read-write (for `registry set` / `delete`):

```bash
az role assignment create \
  --role "Key Vault Secrets Officer" \
  --assignee alice@contoso.com \
  --scope "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/my-kv-prod"
```

### Access policies (legacy)

```bash
# Read-only
az keyvault set-policy --name my-kv-prod --upn alice@contoso.com --secret-permissions get list

# Read-write
az keyvault set-policy --name my-kv-prod --upn alice@contoso.com --secret-permissions get list set delete recover
```

## doctor Output

Healthy state:

```
azure-prod                                                       (azure)
  ✓ az CLI v2.85.0
  ✓ authenticated  user=alice@contoso.com  tenant=22222222-2222-2222-2222-222222222222  subscription=Production  vault=my-kv-prod
```

Not authenticated:

```
azure-prod                                                       (azure)
  ✓ az CLI v2.85.0
  ✗ not authenticated
      → run: az login
```

## Fragment directives

`#version=<id>` pins a specific secret version. Version IDs are 32-character lowercase hex strings generated by Azure:

| Directive | Effect | Example |
|---|---|---|
| `#version=0123456789abcdef...` | Fetch that specific version | `azure-prod:///stripe-key#version=0123456789abcdef0123456789abcdef` |
| `#version=latest` | Same as omitting (latest version) | `azure-prod:///stripe-key#version=latest` |
| (no fragment) | Fetch latest enabled version | `azure-prod:///stripe-key` |

To find a version ID:

```bash
az keyvault secret list-versions \
  --vault-name my-kv-prod \
  --name stripe-api-key \
  --query '[].id' -o tsv
```

## History API support

Not implemented. The `az` CLI does not expose per-secret version-history metadata, so historical revisions cannot be retrieved programmatically.

## Limitations

- **Soft-delete, not purge.** `secretenv registry delete` soft-deletes the secret (recoverable for 90 days default). Fully remove it with `az keyvault secret purge --name <name> --vault-name <vault>`. This differs from aws-secrets and gcp (which delete immediately) — it's an Azure platform default.
- **Text secrets only.** Key Vault supports `certificates` as a distinct resource type. v0.13 targets `secrets` only. A secret bound to a certificate returns with a `kid` field and the backend surfaces an error.
- **Version IDs are opaque hex.** Unlike GCP's integer versions, Azure version IDs are 32-char hex strings — not human-memorable. Operators typically copy-paste from the portal or `az keyvault secret list-versions`.
- **Auto-create on `set`.** Unlike gcp (update-only), `secretenv registry set` auto-creates the secret if it doesn't exist. This matches `az keyvault secret set` behavior.
- **No Managed HSM support.** Azure's FIPS 140-3 Level 3 HSM uses a different CLI surface (`--hsm-name` not `--vault-name`). Not in v0.13.

## Examples

### Single vault, local development

```toml
[backends.azure-dev]
type            = "azure"
azure_vault_url = "https://my-kv-dev.vault.azure.net/"

[registries.default]
sources = ["azure-dev:///myapp-registry"]
```

```bash
secretenv run -- npm start
```

### Multi-vault RBAC setup

```toml
[backends.azure-staging]
type            = "azure"
azure_vault_url = "https://my-kv-staging.vault.azure.net/"
azure_tenant    = "contoso.onmicrosoft.com"

[backends.azure-prod]
type            = "azure"
azure_vault_url = "https://my-kv-prod.vault.azure.net/"
azure_tenant    = "contoso.onmicrosoft.com"

[registries.staging]
sources = ["azure-staging:///myapp-registry"]

[registries.prod]
sources = ["azure-prod:///myapp-registry"]
```

### As registry source

```bash
secretenv run --registry azure-prod:///myapp-registry -- ./deploy.sh
```

## Troubleshooting

**"SecretNotFound"**
Verify the secret exists in the vault. Use `az keyvault secret list --vault-name my-kv-prod` to list all secrets.

**"Forbidden"**
Check your RBAC role or access policy. Run `az keyvault show --name my-kv-prod --query properties.enableRbacAuthorization` to see which permission model is in use, then grant the appropriate role or policy.

**"Could not find a vault with name"**
Verify `azure_vault_url` points to an existing vault. Use `az keyvault list` to list vaults in your subscription.

**"secret has been deleted but not purged"**
The secret is soft-deleted and recoverable. Either recover with `az keyvault secret recover --name <n> --vault-name <v>` or wait for the recovery window to expire.

## See Also

- [`secretenv doctor`](../../README.md#operational-health-secretenv-doctor) — health checks for all backends
- [Alias registry concepts](../reference/registry.md) — how registry sources resolve aliases
- [Fragment vocabulary](../reference/fragment-vocabulary.md) — `#version` directive reference
- [Azure Key Vault documentation](https://learn.microsoft.com/en-us/azure/key-vault/) — permissions, soft-delete, RBAC
- [All backends](README.md) — pick a different backend
- [Main README](../../README.md) — overview + workflows
