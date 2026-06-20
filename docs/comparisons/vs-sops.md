# SecretEnv vs sops

**TL;DR.** [sops](https://github.com/getsops/sops) encrypts files in git (KMS, age, GPG, Vault transit). SecretEnv injects secrets at runtime. **Different problems, complementary tools.**

---

## sops at a glance

- File-level encryption (whole file or per-key in structured formats)
- Key sources: AWS KMS, GCP KMS, Azure Key Vault, age, GPG, Vault transit
- Encrypted file lives in git; structure visible, values encrypted
- `sops decrypt` returns plaintext; `sops exec-env` runs commands with decrypted env
- Standard for gitops workflows (Flux, ArgoCD)

Use sops if you need encrypted secrets in git.

---

## Comparison

| Property | SecretEnv | sops |
|---|---|---|
| Where secrets live | In your existing backends | Encrypted file in your repo |
| Repo contains secret material | No (alias only) | Yes (ciphertext) |
| Backend topology in repo | No | Yes (KMS key ARN, sops metadata) |
| Multi-backend orchestration in one invocation | Yes (15 backends) | No (one sops file = one set of recipients) |
| Cross-backend migration | One `registry set` | Re-encrypt the file with the new recipients |
| Offboarding (specific user) | Revoke registry-backend access | Re-encrypt every sops file without the ex-member's recipient key |
| Centrally-shared mutable alias registry | Yes | None |
| Network required to read | Yes (every read) | Only for KMS modes |
| Gitops-friendly (encrypted file in git) | ✗ (not the model) | ✓ (its primary use case) |

---

## They're complementary

A common pattern:

- **sops** for encrypted config in git (per-environment K8s manifests, deployment configs)
- **SecretEnv** for runtime injection in dev + CI + general workloads

sops controls versioned, encrypted config. SecretEnv fetches fresh secrets from backends at runtime.

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
