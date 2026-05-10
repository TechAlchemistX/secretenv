# SecretEnv vs fnox

**TL;DR.** [fnox](https://github.com/jdx/fnox) is a thoughtful multi-mode secrets tool that handles client-side encryption (age + KMS providers), cloud secret references, and password managers. **In KMS modes, fnox closes the persistent-key and offboarding concerns at the KMS-key level.** SecretEnv's distinction is **orthogonal to encryption**: an alias-registry layer above the backend that decouples every repo from backend URIs entirely. Migrating a secret in fnox (any mode) means editing every `fnox.toml`. In SecretEnv, it's one `registry set`. Both are valid approaches; they solve different problems and can be used together.

---

## fnox at a glance

fnox is itself multi-backend. It supports several distinct modes:

- **Encryption providers** (ciphertext stored in committed `fnox.toml`):
  - `age` — local symmetric encryption; private key on disk
  - `aws-kms` — ciphertext in fnox.toml; **decryption gated by IAM on the KMS key**; no persistent key on disk
  - `azure-kms` — same model via Azure Key Vault Crypto User role
  - `gcp-kms` — same model via GCP KMS
- **Cloud secret-storage providers** (references stored, fetched at runtime): `aws-ps`, `aws-sm`, `azure-sm`, `gcp-sm`, `bitwarden-sm`, `vault`
- **Password managers** (references stored): `1password`, `bitwarden`, `infisical`
- **Local storage**: `keychain`, `keepass`, `password-store`, `plain`

Sources: [fnox README](https://github.com/jdx/fnox/blob/main/README.md), [fnox AWS KMS provider docs](https://fnox.jdx.dev/providers/aws-kms), [fnox Azure KMS provider docs](https://fnox.jdx.dev/providers/azure-kms).

---

## Mode-by-mode comparison

### fnox (age) vs SecretEnv

| Property | fnox (age) | SecretEnv |
|---|---|---|
| Persistent decryption key on disk | ✓ age private key | None — no decryption surface |
| Offboarding | Re-encrypt every secret without ex-member's recipient key | Revoke registry-backend access; covers every repo |
| Re-encryption needed on team change | Yes | n/a (no encryption) |
| Network required to read | No (offline OK) | Yes (backend fetch on every run) |
| Secret material in repo | Ciphertext (committed) | Nothing (alias only) |
| Backend topology in repo | Yes (provider + path) | No (alias only) |

**Where fnox-age wins:** offline-first workflows, gitops where the encrypted blob travels with the code, environments with no cloud dependency.

**Where SecretEnv wins:** team changes don't trigger re-encryption sweeps; offboarding is one IAM operation; nothing in the repo reveals topology.

### fnox (KMS — aws-kms / azure-kms / gcp-kms) vs SecretEnv

| Property | fnox (KMS mode) | SecretEnv |
|---|---|---|
| Persistent decryption key on disk | None — IAM-gated KMS calls | None — no decryption surface |
| Offboarding | IAM revoke on the KMS key (one operation) | Revoke registry-backend access (one operation) |
| Re-encryption needed on KMS key rotation | Yes (manual re-encrypt all secrets) | n/a |
| Network required to read | Yes (every read = live KMS API call) | Yes (backend fetch on every run) |
| Secret material in repo | Ciphertext (committed) | Nothing (alias only) |
| Backend topology in repo | Yes (provider name, KMS key id, region) | No (alias only) |
| Cross-backend migration (e.g., move from `aws-sm` to `vault`) | Edit every `fnox.toml`; if from KMS mode, re-encrypt | One `registry set`; every repo inherits on next run |
| Centrally-shared mutable alias registry | None — config IS source of truth, per-repo | Yes — registry lives in your backend |
| Same alias name routes per environment | Profiles override per env in config | Registry cascade routes per env (registry change, not config change) |

**Where fnox-KMS wins:** ciphertext-in-repo property (gitops-friendly auditability of which secrets exist); offline read once ciphertext is fetched (after key cache; not the default); committed history of encrypted secret values.

**Where SecretEnv wins:** cross-backend migration is one line, not a repo-wide edit; nothing in the repo reveals the backend choice; the alias registry is a single source of truth that mutates without any config change in any repo.

### fnox (cloud-reference modes — aws-sm / vault / 1password etc.) vs SecretEnv

In these modes fnox stores references like `aws-sm://...` directly in `fnox.toml`. There's no encryption involved.

| Property | fnox (reference mode) | SecretEnv |
|---|---|---|
| Persistent decryption key on disk | None | None |
| Offboarding | Revoke backend access (covers every repo using that backend) | Revoke registry-backend access (covers every repo) |
| Backend topology in repo | Yes (the reference URI) | No (alias only) |
| Cross-backend migration | Edit every `fnox.toml` to change the reference | One `registry set` |
| Centrally-shared mutable alias registry | None | Yes |

**Where fnox-reference-mode wins:** simpler mental model when topology is intentionally public (small teams, internal-only repos); no extra registry to manage.

**Where SecretEnv wins:** the same indirection point that makes migration cheap (registry set); aliases are environment-agnostic, routed per-env via `--registry`.

---

## What's actually different (the orthogonal claim)

The distinction between SecretEnv and fnox is **not encryption posture**. It's **alias indirection**.

In fnox, the `fnox.toml` in each repo is the source of truth. It says "this secret comes from `aws-sm://prod-account/myapp/stripe`" (or, in KMS mode, "this is the ciphertext, decrypt it via this KMS key"). When you want to change where Stripe lives, you edit every `fnox.toml` in every repo that mentions it.

In SecretEnv, the `secretenv.toml` says "this secret is `secretenv://stripe-key`." That's all. The actual location lives in a separate registry document, in a backend you control. When you want to change where Stripe lives, you run `secretenv registry set stripe-key <new-uri>` once. Every repo picks it up on the next run.

This is a difference in **architecture**, not in security. It's why you might choose to use both:
- SecretEnv to manage the alias-to-URI mapping at the org level
- fnox locally for offline-first dev workflows where the developer wants ciphertext-in-repo

They are layered, not competing.

---

## Operator's correspondence with the fnox maintainer

For accurate context: the @TechAlchemistX's exchange with @jdx (fnox maintainer) on a prior version of this comparison surfaced that the v1 SecretEnv README modelled only fnox-age mode and missed fnox-KMS. The maintainer's clarification:

> "I am the maintainer of fnox. This is only true if you use the encryption providers. If you don't, nothing is encrypted obviously. Your doc also doesn't seem to take into account my preferred way of using it with KMS that solves a lot of the problems mentioned."

TechAlchemistX's reply:

> "Fair point, the table only models age-mode and that's a real miss. KMS-mode closes a lot of what I flagged (offboarding via IAM revocation on the KMS key, no persistent decryption key on disk, transparent rotation through aws-sm). Separately, I still do think secretenv's registry indirection adds something orthogonal to encryption (cross-backend migration is one line vs editing every fnox.toml), but that's a different conversation."

This page is the corrected version. If anything here misrepresents fnox in any mode, please open an issue against [TechAlchemistX/secretenv](https://github.com/TechAlchemistX/secretenv/issues) — accuracy matters more than rhetoric.

---

## When to pick which

**Pick fnox if:**
- You want client-side encryption with secrets-in-config (committed ciphertext)
- You want gitops auditability of which encrypted secret existed when
- You're already in the `mise` ecosystem and value tight integration
- KMS-mode offboarding via IAM revocation matches your security model

**Pick SecretEnv if:**
- You want to remove backend topology from every repo
- You expect to migrate secrets across backends and want a one-line operation
- You manage a centrally-shared alias registry across many teams / repos
- Your `secretenv.toml` should never know which backend a secret lives in

**Pick both if:**
- You want fnox's encryption-in-config locally + SecretEnv's registry indirection for org-wide routing — they layer cleanly.

---

## Sources

- fnox README: https://github.com/jdx/fnox/blob/main/README.md
- fnox AWS KMS provider: https://fnox.jdx.dev/providers/aws-kms
- fnox Azure KMS provider: https://fnox.jdx.dev/providers/azure-kms
- fnox GCP KMS provider: https://fnox.jdx.dev/providers/gcp-kms
