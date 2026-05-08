# Supported Backends

SecretEnv supports 15 secret backends. Every backend page follows the same structure: **header** (type, CLI, URI, tested version) → **Configuration** → **URI Format** → **Authentication** → **doctor Output** → **Examples** → **See Also**.

> **Try any of these:** copy the configuration block into `~/.config/secretenv/config.toml`, then run `secretenv doctor` to verify auth + reachability. No commitment.

---

## Quick Reference

| Backend | Type | Platform | Tested CLI version | Status | Docs |
|---|---|---|---|---|---|
| Local file | `local` | all | (uses `std::fs`) | Available | [local.md](local.md) |
| AWS SSM Parameter Store | `aws-ssm` | all | aws-cli/2.34.35 | Available | [aws-ssm.md](aws-ssm.md) |
| AWS Secrets Manager | `aws-secrets` | all | aws-cli/2.34.35 | Available | [aws-secrets.md](aws-secrets.md) |
| 1Password | `1password` | all | op 2.34.0 | Available | [1password.md](1password.md) |
| HashiCorp Vault | `vault` | all | vault v2.0.0 | Available | [vault.md](vault.md) |
| GCP Secret Manager | `gcp` | all | Google Cloud SDK 560.0.0 | Available | [gcp.md](gcp.md) |
| Azure Key Vault | `azure` | all | azure-cli 2.85.0 | Available | [azure.md](azure.md) |
| macOS Keychain | `keychain` | macOS only | macOS Darwin 25.4 | Available | [keychain.md](keychain.md) |
| Doppler | `doppler` | all | doppler v3.76.0 | Available | [doppler.md](doppler.md) |
| Infisical | `infisical` | all | infisical 0.43.79 | Available | [infisical.md](infisical.md) |
| Keeper | `keeper` | all | Commander 17.2.13 | Available | [keeper.md](keeper.md) |
| Cloudflare Workers KV | `cf-kv` | all | wrangler 4.85.0 | Available | [cf-kv.md](cf-kv.md) |
| OpenBao | `openbao` | all | bao v2.5.3 | Available | [openbao.md](openbao.md) |
| CyberArk Conjur | `conjur` | all | conjur v8.1.3 (Go) | Available | [conjur.md](conjur.md) |
| Bitwarden Secrets Manager | `bitwarden-sm` | all | bws 2.0.0 | Available | [bitwarden-sm.md](bitwarden-sm.md) |
| Delinea Secret Server | `delinea` | all | `tss` | Coming Soon | — |

All "tested CLI version" entries reflect the operator's local matrix at v0.13.0 release time (2026-05-07). The minimum-supported versions are noted on each backend page.

---

## Choosing a Backend

- **Already on AWS?** [aws-ssm](aws-ssm.md) is the lowest-overhead option. [aws-secrets](aws-secrets.md) adds rotation orchestration.
- **Cross-cloud or self-hosted secrets platform?** [vault](vault.md) (HashiCorp) or [openbao](openbao.md) (LF MPL fork).
- **Identity-platform with policy engine?** [vault](vault.md) (Enterprise) or [conjur](conjur.md) (CyberArk).
- **Team password manager you already use?** [1password](1password.md), [bitwarden-sm](bitwarden-sm.md), [keeper](keeper.md).
- **Developer-first secrets SaaS?** [doppler](doppler.md), [infisical](infisical.md).
- **Edge / serverless workloads?** [cf-kv](cf-kv.md).
- **Local dev only?** [keychain](keychain.md) (macOS) or [local](local.md).

For deeper trade-off analysis: [Tool Comparisons](../comparisons/README.md).

---

## Documentation Structure

Every backend page is shaped the same way so you can switch between them without re-orienting:

1. **Header block** — type slug, CLI, URI scheme, platform, tested CLI version
2. **Configuration** — the `[backends.<instance>]` block + field table
3. **URI Format** — canonical example with labeled parts
4. **Authentication** — credential mechanisms in precedence order
5. **doctor Output** — what success and common-failure states look like
6. **Limitations / Known Issues** — what the backend can't do (set, history, fragments)
7. **Examples** — real config snippets for typical patterns
8. **See Also** — cross-links to related backends, registry concepts, fragment grammar

---

## Adding a Backend

Backends are independent Rust crates implementing two traits. See [reference/adding-a-backend.md](../reference/adding-a-backend.md) for the trait interface and step-by-step walkthrough.

---

## See Also

- [Main README](../../README.md) — overview + workflows
- [Tool comparisons](../comparisons/README.md) — SecretEnv vs `.env` / fnox / direnv / op-run / etc.
- [Threat model](../security.md) — 14-category honest security comparison
- [CI/CD patterns](../ci-cd.md) — using SecretEnv in CI pipelines
