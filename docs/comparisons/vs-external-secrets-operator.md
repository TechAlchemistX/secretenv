# SecretEnv vs External Secrets Operator (ESO)

**TL;DR.** [External Secrets Operator](https://external-secrets.io/) is the Kubernetes-native multi-backend bridge. It runs in-cluster, syncing secrets into K8s `Secret` resources. SecretEnv runs as a CLI on laptops, in CI, and as a `secretenv run` wrapper for non-K8s workloads. **Complementary, not competing.**

---

## ESO at a glance

- Kubernetes operator pattern (controllers + CRDs)
- `ExternalSecret` and `ClusterSecretStore` CRDs
- Pulls from AWS SSM/SM, GCP SM, Azure KV, Vault, 1Password Connect, Doppler, Infisical, etc.
- Materializes into K8s `Secret` resources
- Webhook + push-based sync modes
- CNCF Sandbox project

Use ESO if your entire deployment is Kubernetes.

---

## Where ESO doesn't fit

- **Local development.** ESO doesn't help `npm start` on a laptop.
- **Non-K8s CI/CD.** GitHub Actions, GitLab CI, Jenkins, BuildKite: ESO doesn't run there.
- **Non-K8s production.** Lambda, ECS Fargate, Cloud Run, VMs, Heroku-style PaaS: no ESO story.

For these, use a CLI-first tool like SecretEnv.

---

## Comparison

| Property | SecretEnv | ESO |
|---|---|---|
| Runtime model | CLI (local + CI + general-purpose runtime) | Kubernetes operator (in-cluster) |
| Multi-backend | ✓ (15 backends) | ✓ (broad provider list) |
| Local dev | ✓ | ✗ |
| GitHub Actions / GitLab / Jenkins | ✓ | ✗ (you'd run something else) |
| In-cluster sync to K8s `Secret` | ✗ (use ESO for this) | ✓ (its primary purpose) |
| Centrally-shared mutable alias registry | ✓ | ✗ (config-as-code via CRDs) |
| Backend migration | One `registry set` | Edit every `ExternalSecret` CRD |
| Repo contains backend topology | No (alias only) | Yes (provider name in CRD `spec.dataFrom.extract.key`) |

---

## Running both

A common K8s pattern:

- **ESO in-cluster** for production Pods
- **SecretEnv on dev laptops + CI** for local dev parity and non-K8s components

Both pull from the same backends (AWS SSM, Vault, 1Password, etc.). Each handles its workflow.

---

## When to pick which

**Pick ESO (alone) if:**
- 100% of your workload is Kubernetes
- You don't have a meaningful local-dev or non-K8s CI flow
- You want native `Secret` resource integration

**Pick SecretEnv (alone) if:**
- You're not on Kubernetes
- Your dev + CI + production are a mix of laptops, ephemeral CI, persistent CI, VMs, FaaS

**Run both if:**
- Your production is K8s but local dev / CI / build / other components aren't
- You want consistent backends across all environments with the right tool for each surface
