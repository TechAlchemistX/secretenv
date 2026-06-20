# Azure Key Vault

- **Type:** `azure`
- **CLI required:** [`az`](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli)
- **CLI version:** Azure CLI 2.55+
- **URI scheme:** `<instance>:///<secret-name>[#version=<id>]`
- **Platform:** all (macOS, Linux, Windows)
- **Tested:** `azure-cli 2.85.0` on macOS Darwin 25.4 (SecretEnv v0.19.0)

> SecretEnv injects secrets from any backend as environment variables. This page covers the `azure` backend. New here? See the [overview](/).

Azure Key Vault is Microsoft Azure's native secrets store with fine-grained RBAC, audit logging, and Managed Identity integration for zero-credential pod/VM authentication.

## When to pick this

- **On Azure:** native integration, Managed Identity automatic credential discovery
- **RBAC and audit:** Fine-grained roles; full access trail
- **Sovereign clouds:** Azure Commercial, China, US Government, Germany
- **Soft-delete recovery:** 90-day recovery window (customizable)

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

Use triple-slash (`azure-prod:///secret-name`). Secret names follow Azure rules: `[a-zA-Z0-9-]{1,127}` (alphanumerics and hyphens only).

For version pinning:

```
azure-prod:///stripe-api-key#version=abc123deadbeef0123456789abcdef01
azure-prod:///stripe-api-key                  # Default: latest enabled version
```

**Verify your setup with:** `secretenv doctor`. Green output means you're ready to run `secretenv run -- <your command>`.

## Authentication

SecretEnv delegates to the `az` CLI. Any credential method the CLI supports works automatically:

- **User interactive**: `az login` (device code or browser)
- **Service principal (password)**: `az login --service-principal --tenant <t> --username <client-id> --password <secret>`
- **Service principal (certificate)**: `az login --service-principal --username <client-id> --tenant <t> --password <cert-path>`
- **Managed Identity**: `az login --identity` (VMs, App Service, AKS, Functions)
- **Federated credentials**: GitHub Actions `azure/login@v1` + Workload Identity Federation
- **Azure Cloud Shell**: Pre-authenticated

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

`#version=<id>` pins specific versions (32-character hex strings):

| Directive | Effect | Example |
|---|---|---|
| `#version=0123...` | Specific version | `azure-prod:///stripe-key#version=0123456789abcdef0123456789abcdef` |
| `#version=latest` | Latest (same as omitting) | `azure-prod:///stripe-key#version=latest` |
| (no fragment) | Latest enabled version | `azure-prod:///stripe-key` |

Find version IDs with: `az keyvault secret list-versions --vault-name my-kv-prod --name stripe-api-key --query '[].id' -o tsv`

## History API support

Not implemented. The `az` CLI does not expose per-secret version-history metadata.

## Limitations

- **Soft-delete only.** `registry delete` soft-deletes (recoverable for 90 days). Use `az keyvault secret purge` for immediate deletion. Differs from AWS/GCP default.
- **Text secrets only.** v0.13 targets `secrets`; certificates not supported.
- **Opaque version IDs.** Azure uses 32-char hex (not human-memorable, unlike GCP). Copy-paste from portal or `az keyvault secret list-versions`.
- **Auto-create on `set`.** Unlike GCP, `registry set` creates the secret if it doesn't exist.
- **No Managed HSM.** FIPS 140-3 Level 3 HSM requires `--hsm-name` (not `--vault-name`). Not in v0.13.

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
Verify the secret exists with `az keyvault secret list --vault-name my-kv-prod`.

**"Forbidden"**
Check RBAC role with `az keyvault show --name my-kv-prod --query properties.enableRbacAuthorization`. Grant appropriate role or policy.

**"Could not find a vault with name"**
Verify `azure_vault_url` exists with `az keyvault list`.

**"secret has been deleted but not purged"**
Recover with `az keyvault secret recover --name <n> --vault-name <v>` or wait for recovery window to expire.

## See Also

- [`secretenv doctor`](/reference/cli-reference-full#secretenv-doctor), health checks for all backends
- [Alias registry concepts](../reference/registry.md), how registry sources resolve aliases
- [Fragment vocabulary](../reference/fragment-vocabulary.md), `#version` directive reference
- [Azure Key Vault documentation](https://learn.microsoft.com/en-us/azure/key-vault/), permissions, soft-delete, RBAC
- [All backends](README.md), pick a different backend
- [Overview](/), overview + workflows
