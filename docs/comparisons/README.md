# Tool Comparisons

How SecretEnv fits into your ecosystem. One page per alternative. Each page includes cases where the alternative is the right answer.

For the compact comparison matrix: [Comparisons](/comparisons/).

---

- **[vs `.env` files](vs-dotenv.md)**, the incumbent default; SecretEnv is the direct replacement
- **[vs fnox](vs-fnox.md)**, multi-mode tool (age + KMS + cloud refs); honest mode-by-mode breakdown including the maintainer's correspondence
- **[vs direnv](vs-direnv.md)**, shell hook for env vars; complementary, not competing
- **[vs single-backend wrappers (`op run`, `doppler run`, `infisical run`)](vs-op-run.md)**, wrappers vs multi-backend orchestration
- **[vs Pulumi ESC](vs-pulumi-esc.md)**, multi-backend with SaaS dependency vs local-first
- **[vs External Secrets Operator](vs-external-secrets-operator.md)**, Kubernetes-native vs CLI-first; complementary
- **[vs sops](vs-sops.md)**, encrypted-files-in-git vs runtime injection; different problems
- **[vs Vault Enterprise / CyberArk Conjur](vs-vault-and-conjur.md)**, identity platforms; SecretEnv routes to them as backends

---

For SecretEnv's security threat model against these tools (14 categories): [../security.md](../security.md).

For the full backend list with tested CLI versions: [../backends/README.md](../backends/README.md).
