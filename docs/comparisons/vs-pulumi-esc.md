# SecretEnv vs Pulumi ESC

**TL;DR.** [Pulumi ESC](https://www.pulumi.com/docs/esc/) is the closest cousin: both multi-backend, both abstract storage from consumption. **The differentiator: local-first vs SaaS-first.** ESC requires Pulumi Cloud. SecretEnv runs on your machine: no SaaS gate for core workflows.

---

## Pulumi ESC at a glance

- Multi-backend abstraction (AWS, Azure, GCP, Vault, 1Password, Doppler, ...)
- Hosted environment definitions in Pulumi Cloud
- Policy-as-code engine, hosted audit log, drift detection
- Tight Pulumi IaC integration

If your org uses Pulumi extensively, ESC is a natural extension.

---

## The SaaS dependency

ESC environment definitions live in Pulumi Cloud. You need:
- A Pulumi Cloud account (free tier + usage-based pricing)
- Network access to `api.pulumi.com` from every machine
- Trust in Pulumi's availability for your local-dev workflow

Some teams accept this. Others, especially security-conscious or air-gapped teams, won't add SaaS to core workflows.

---

## Comparison

| Property | SecretEnv | Pulumi ESC |
|---|---|---|
| Multi-backend orchestration | ✓ | ✓ |
| Local-first | ✓ | ✗ (requires Pulumi Cloud) |
| Backend topology hidden from repos | ✓ (via alias registry) | ✓ (via ESC environment refs) |
| Policy engine (policy-as-code) | ✗ (delegate to backend's IAM/ACLs) | ✓ |
| Hosted audit log | ✗ (delegate to backend) | ✓ |
| Drift detection across environments | ✗ | ✓ |
| UI for managing environments | ✗ (config files + CLI only) | ✓ (Pulumi Cloud UI) |
| Cost | Free (AGPL) | Free tier; paid above |
| Network required to read | Yes (backend only) | Yes (Pulumi Cloud + backend) |
| Pulumi IaC integration | None | ✓ (native) |

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
