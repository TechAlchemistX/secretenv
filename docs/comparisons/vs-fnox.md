# SecretEnv vs fnox

**TL;DR.** [fnox](https://github.com/jdx/fnox) handles client-side encryption (age + KMS providers) and cloud secret references. **In KMS modes, fnox closes persistent-key and offboarding concerns.** SecretEnv's distinction is **orthogonal**: an alias-registry layer that decouples repos from backend URIs. fnox requires editing every `fnox.toml` to migrate. SecretEnv: one `registry set`. Both valid; they layer cleanly together.


---

## fnox at a glance

fnox supports several modes:

- **Encryption providers** (ciphertext in `fnox.toml`): `age`, `aws-kms`, `azure-kms`, `gcp-kms`
- **Cloud secret-storage** (references only): `aws-sm`, `azure-sm`, `gcp-sm`, `bitwarden-sm`, `vault`
- **Password managers**: `1password`, `bitwarden`, `infisical`
- **Local storage**: `keychain`, `keepass`, `password-store`, `plain`

[fnox README](https://github.com/jdx/fnox/blob/main/README.md) · [AWS KMS docs](https://fnox.jdx.dev/providers/aws-kms) · [Azure KMS docs](https://fnox.jdx.dev/providers/azure-kms).

---

## Mode-by-mode comparison

### fnox (age) vs SecretEnv

| Property | SecretEnv | fnox (age) |
|---|---|---|
| Persistent decryption key on disk | None, no decryption surface | ✓ age private key |
| Offboarding | Revoke registry-backend access; covers every repo | Re-encrypt every secret without ex-member's recipient key |
| Re-encryption needed on team change | n/a (no encryption) | Yes |
| Network required to read | Yes (backend fetch on every run) | No (offline OK) |
| Secret material in repo | Nothing (alias only) | Ciphertext (committed) |
| Backend topology in repo | No (alias only) | Yes (provider + path) |

**fnox-age wins on:** offline-first workflows, gitops with encrypted blobs in git, no cloud dependency.

**SecretEnv wins on:** no re-encryption sweeps on team changes; offboarding is one IAM operation; repo doesn't reveal topology.

### fnox (KMS, aws-kms / azure-kms / gcp-kms) vs SecretEnv

| Property | SecretEnv | fnox (KMS mode) |
|---|---|---|
| Persistent decryption key on disk | None, no decryption surface | None, IAM-gated KMS calls |
| Offboarding | Revoke registry-backend access (one operation) | IAM revoke on the KMS key (one operation) |
| Re-encryption needed on KMS key rotation | n/a | Yes (manual re-encrypt all secrets) |
| Network required to read | Yes (backend fetch on every run) | Yes (every read = live KMS API call) |
| Secret material in repo | Nothing (alias only) | Ciphertext (committed) |
| Backend topology in repo | No (alias only) | Yes (provider name, KMS key id, region) |
| Cross-backend migration (e.g., move from `aws-sm` to `vault`) | One `registry set`; every repo inherits on next run | Edit every `fnox.toml`; if from KMS mode, re-encrypt |
| Centrally-shared mutable alias registry | Yes, registry lives in your backend | None, config IS source of truth, per-repo |
| Same alias name routes per environment | Registry cascade routes per env (registry change, not config change) | Profiles override per env in config |

**fnox-KMS wins on:** ciphertext-in-repo (gitops auditability); offline read after key cache; committed history of encrypted values.

**SecretEnv wins on:** cross-backend migration is one line, not repo-wide edits; repo doesn't reveal backend choice; registry is a single source of truth.

### fnox (cloud-reference modes, aws-sm / vault / 1password etc.) vs SecretEnv

In these modes fnox stores references like `aws-sm://...` directly in `fnox.toml`. There's no encryption involved.

| Property | SecretEnv | fnox (reference mode) |
|---|---|---|
| Persistent decryption key on disk | None | None |
| Offboarding | Revoke registry-backend access (covers every repo) | Revoke backend access (covers every repo using that backend) |
| Backend topology in repo | No (alias only) | Yes (the reference URI) |
| Cross-backend migration | One `registry set` | Edit every `fnox.toml` to change the reference |
| Centrally-shared mutable alias registry | Yes | None |

**fnox-reference-mode wins on:** simpler mental model for public topology (small teams); no registry to manage.

**SecretEnv wins on:** indirection makes migration cheap; aliases route per-env via `--registry`.

---

## What's actually different

The distinction is **not encryption posture**. It's **alias indirection**.

In fnox, `fnox.toml` is source of truth. It says "this secret is `aws-sm://prod-account/myapp/stripe`" (or KMS ciphertext). To move Stripe, edit every repo's `fnox.toml`.

In SecretEnv, `secretenv.toml` says "this secret is `secretenv://stripe-key`." The location lives in a separate registry. To move Stripe, run `secretenv registry set stripe-key <new-uri>` once. Every repo picks it up.

**Architecture difference, not security difference.** You can layer them:
- SecretEnv for org-level alias-to-URI mapping
- fnox locally for offline-first dev with ciphertext-in-repo

---

## Maintainer correspondence

An earlier version of this comparison modelled only fnox-age and missed fnox-KMS. The @jdx (fnox maintainer) clarified:

> "This is only true if you use the encryption providers. Your doc doesn't account for KMS-mode, which solves many problems mentioned."

@TechAlchemistX's reply:

> "Fair point. KMS-mode closes offboarding via IAM revocation, no persistent key on disk, transparent rotation. SecretEnv's registry indirection is orthogonal. Cross-backend migration is one line vs editing every fnox.toml."

If anything here misrepresents fnox, please open an issue: [TechAlchemistX/secretenv issues](https://github.com/TechAlchemistX/secretenv/issues). Accuracy matters more.

---

## When to pick which

**Pick fnox if:**
- You want client-side encryption (committed ciphertext)
- You want gitops auditability of encrypted secrets
- You're in the `mise` ecosystem
- KMS-mode IAM revocation matches your security model

**Pick SecretEnv if:**
- You want to remove backend topology from repos
- You expect cross-backend secret migration
- You manage a centrally-shared alias registry
- Repos should never know which backend holds a secret

**Pick both if:**
- You want fnox's local encryption + SecretEnv's org-wide registry; they layer cleanly.

---

