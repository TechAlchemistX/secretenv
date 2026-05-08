# SecretEnv vs sops

**TL;DR.** [sops](https://github.com/getsops/sops) (Mozilla / CNCF) is the canonical tool for **encrypted-file-at-rest in git**. It encrypts YAML/JSON/dotenv/binary files using KMS, age, GPG, or HashiCorp Vault transit; the encrypted blob lives in your repo. SecretEnv is a runtime-injection tool that stores nothing. **They solve different problems and can be used together.**

---

## sops at a glance

- File-level encryption (whole file or per-key for structured formats)
- Key sources: AWS KMS, GCP KMS, Azure Key Vault, age, GPG, HashiCorp Vault transit
- Encrypted file is committed to git; reviewers see the structure but not the values
- `sops decrypt` returns plaintext; `sops exec-env` runs a command with decrypted env
- Standard for gitops-style secret management (Flux, ArgoCD via sops integration)

If your workflow needs **encrypted secrets in git** (the gitops pattern), sops is the right answer.

---

## Comparison

| Property | sops | SecretEnv |
|---|---|---|
| Where secrets live | Encrypted file in your repo | In your existing backends |
| Repo contains secret material | Yes (ciphertext) | No (alias only) |
| Backend topology in repo | Yes (KMS key ARN, sops metadata) | No |
| Multi-backend orchestration in one invocation | No (one sops file = one set of recipients) | Yes (15 backends) |
| Cross-backend migration | Re-encrypt the file with the new recipients | One `registry set` |
| Offboarding (specific user) | Re-encrypt every sops file without the ex-member's recipient key | Revoke registry-backend access |
| Centrally-shared mutable alias registry | None | Yes |
| Network required to read | Only for KMS modes | Yes (every read) |
| Gitops-friendly (encrypted file in git) | ✓ (its primary use case) | ✗ (not the model) |

---

## They're complementary

A common pattern:

- **sops** handles encrypted-config-in-git for things that genuinely should be versioned with the code (e.g., per-environment K8s manifest secrets, deployment configs that reference external secrets)
- **SecretEnv** handles runtime secret injection for dev + CI + general-purpose workloads

These don't conflict. sops controls "what config did this deployment use, encrypted in git." SecretEnv controls "fetch fresh secrets from authoritative backends and inject at runtime."

---

## When to pick which

**Pick sops if:**
- You need ciphertext-in-git for gitops auditability
- Your workflow is built around per-file encryption (Flux, ArgoCD, K8s manifests)
- You want a discrete encrypted file that travels with the code

**Pick SecretEnv if:**
- Your secrets live in backends, not in files
- You want runtime fetch + injection, not commit-time encryption
- You want backend migration to be a one-line registry update, not a per-file re-encryption

**Use both if:**
- You have gitops-managed K8s deployments (sops for the manifests) AND a separate dev/CI workflow (SecretEnv for runtime injection)
