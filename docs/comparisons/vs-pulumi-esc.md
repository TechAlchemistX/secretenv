# SecretEnv vs Pulumi ESC

**TL;DR.** [Pulumi ESC](https://www.pulumi.com/docs/esc/) (Environments, Secrets, and Configuration) is the closest architectural cousin to SecretEnv: both are multi-backend, both abstract storage from consumption, both let you compose secrets across providers. **The differentiator is local-first vs SaaS-first.** Pulumi ESC requires a Pulumi Cloud account and runs orchestration through Pulumi's hosted service. SecretEnv runs entirely on your machine — no SaaS gate, no external dependency for a core workflow tool.

---

## Pulumi ESC at a glance

- Multi-backend abstraction (AWS, Azure, GCP, Vault, 1Password, Doppler, ...)
- Hosted environment definitions in Pulumi Cloud
- Policy-as-code via Pulumi's policy engine
- Hosted audit log
- Drift detection across environments
- Tight integration with Pulumi IaC

It is genuinely well-architected. If your org is already deep in the Pulumi ecosystem, ESC is a natural extension.

---

## The SaaS dependency

Pulumi ESC's environment definitions live in Pulumi Cloud. To use it you need:
- A Pulumi Cloud account (free tier exists; usage-priced beyond)
- Network access to `api.pulumi.com` from every machine that resolves secrets
- Trust in Pulumi as a service-availability dependency for your local-dev workflow

For some teams that's fine. For others — especially security-conscious teams that won't add SaaS for a core workflow tool, or air-gapped environments — it's a non-starter.

---

## Comparison

| Property | Pulumi ESC | SecretEnv |
|---|---|---|
| Multi-backend orchestration | ✓ | ✓ |
| Local-first | ✗ (requires Pulumi Cloud) | ✓ |
| Backend topology hidden from repos | ✓ (via ESC environment refs) | ✓ (via alias registry) |
| Policy engine (policy-as-code) | ✓ | ✗ (delegate to backend's IAM/ACLs) |
| Hosted audit log | ✓ | ✗ (delegate to backend) |
| Drift detection across environments | ✓ | ✗ |
| UI for managing environments | ✓ (Pulumi Cloud UI) | ✗ (config files + CLI only) |
| Cost | Free tier; paid above | Free (AGPL) |
| Network required to read | Yes (Pulumi Cloud + backend) | Yes (backend only) |
| Pulumi IaC integration | ✓ (native) | None |

---

## When to pick which

**Pick Pulumi ESC if:**
- You're already in the Pulumi ecosystem (Pulumi IaC, Pulumi Cloud)
- You want hosted policy-as-code, hosted audit, hosted drift detection
- A SaaS dependency is acceptable for this workflow
- You value the UI for managing environments

**Pick SecretEnv if:**
- You don't want to add a SaaS dependency for a core workflow tool
- You're not in the Pulumi ecosystem and don't want to be
- You're air-gapped or have strict egress controls
- You prefer config-files + CLI over hosted UIs
- You want a tool that works the same locally, in CI, and on disconnected dev machines
