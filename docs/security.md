# Security

secretenv is not a security product. It is a workflow product that eliminates a class of workflow-driven security failures.

**secretenv does not make your secrets more secure. It makes your team less likely to handle them insecurely. For most teams, habits are where the actual breaches happen.**

---

## The Model

secretenv is a coat of paint. If the walls aren't strong, the paint is useless. The walls are your backends.

secretenv's security posture is entirely inherited from the backends it wraps. It adds no authentication surface, stores no credentials, and makes no access control decisions. What it does is remove the workflow layer where secrets most commonly leak — `.env` files, hardcoded paths in repos, manual sharing, and offboarding gaps.

**secretenv doesn't replace good tools. It replaces bad habits.**

---

## Threat Model Comparison

The table below maps 14 threat categories across common secrets workflows. The goal is not to show secretenv wins everywhere — it doesn't. The goal is an honest map of where risks move.

| Threat | .env files | direnv | op run | doppler run | fnox (age) | **secretenv** |
|---|---|---|---|---|---|---|
| **Secrets committed to git** | 🔴 High — files exist to be committed | 🔴 High — `.envrc` can contain secrets | 🟡 Medium — 1Password URIs committed, not values | 🟢 Low — no secrets in repo | 🟢 Low — encrypted at rest | 🟢 **Eliminated** — aliases only |
| **Secrets on disk in plaintext** | 🔴 High — that's the entire model | 🔴 High — reads from local files | 🟢 Low — runtime fetch | 🟢 Low — runtime fetch | 🟡 Medium — encrypted, key required | 🟢 **Eliminated** — nothing written |
| **Infrastructure paths in repos** | 🔴 High — paths are the config | 🔴 High — paths in `.envrc` | 🔴 High — `op://` URIs committed | 🟢 Low — project name only | 🟡 Medium — paths present, encrypted | 🟢 **Eliminated** — aliases only |
| **New engineer onboarding** | 🔴 High — manual credential ceremony | 🔴 High — write custom `.envrc` per project | 🟡 Medium — 1Password access + `op` CLI | 🟡 Medium — Doppler token + CLI | 🟡 Medium — age key ceremony + backend setup | 🟢 **One command** |
| **Offboarding a departing engineer** | 🔴 High — manual, slow, cached copies unknown | 🔴 High — manual, files may be cached | 🟡 Medium — remove from 1Password vault | 🟡 Medium — remove from Doppler | 🔴 High — re-encryption required across all repos | 🟢 **One operation** — revoke registry backend access |
| **Backend migration** | 🔴 High — update every `.env` everywhere | 🔴 High — rewrite `.envrc` everywhere | 🔴 Critical — locked to 1Password | 🔴 Critical — locked to Doppler | 🔴 High — re-encrypt everything | 🟢 **One registry update** — all repos inherit |
| **Machine compromise** | 🔴 Plaintext files directly readable | 🔴 Same as `.env` | 🔴 Active sessions exploitable | 🔴 Active sessions + Doppler token at risk | 🔴 Active sessions + **age private key theft** — offline decryption survives re-image | 🔴 Active sessions exploitable — **no persistent key**, breach contained after re-image |
| **Registry document compromise** | 🟢 Does not exist | 🟢 Does not exist | 🟢 Does not exist | 🟢 Does not exist | 🟢 Does not exist | 🟡 **New** — path topology exposed. Requires authenticated backend access. |
| **Post-injection process exposure** | 🔴 Universal | 🔴 Universal | 🔴 Universal | 🔴 Universal | 🔴 Universal | 🔴 **Universal** — property of env var model, not the tool |
| **Audit trail** | 🔴 None | 🔴 None | 🟡 1Password activity log | 🟢 Doppler audit log | 🟡 Backend-dependent | 🟡 **Delegated to backends** — CloudTrail, Vault audit, 1Password activity |
| **Supply chain risk** | 🟢 None | 🟢 Low | 🟡 `op` CLI binary trust | 🟡 Doppler CLI + SaaS | 🟡 age tooling | 🟡 **Install script** — mitigated by signed binaries |
| **SaaS dependency** | 🟢 None | 🟢 None | 🟢 None | 🔴 Hard — Doppler is the backend | 🟢 None | 🟢 **None** — no secretenv service |
| **Secret rotation visibility** | 🔴 None — files go stale silently | 🔴 None — `.envrc` goes stale | 🟢 Automatic — runtime fetch | 🟢 Automatic — Doppler manages rotation | 🔴 Manual — re-encrypt with new value | 🟢 **Automatic** — runtime fetch, rotation transparent |
| **Multi-backend coordination** | 🔴 Manual copy-paste across tools | 🔴 Manual shell glue per project | 🔴 Single backend only | 🔴 Single backend only | 🟡 Possible but complex at scale | 🟢 **Native** — registry abstracts all backends |

---

## Reading the Table

### What secretenv Eliminates

The threats secretenv turns green are the high-frequency failures — the ones that happen not because attackers are sophisticated, but because developers are human, in a hurry, and doing the expedient thing under deadline pressure. Accidental commits. Stale files. Paths in repos. Manual offboarding. Backend lock-in. Rotation blindness.

These are the failures that actually cost organizations. Eliminating them is real, meaningful security improvement.

### What Stays Red Everywhere

**Post-injection process exposure** is a property of environment variables, not of any tool. Once a secret is injected as an env var, it is readable by any process running as the same user. On Linux, `/proc/<pid>/environ` exposes it to same-user processes. The fix is OS or container-level process isolation — not a different secrets tool.

**Machine compromise** is universal. When a machine is owned, the attacker inherits whatever the user had — active cloud sessions, active Vault tokens, active 1Password sessions. The tool choice does not change this.

What the tool choice *does* affect is the blast radius and post-incident containment:

- **.env files:** Plaintext on disk, immediately readable, breach is permanent regardless of what you do next.
- **fnox:** Active sessions inherited *plus* the age private key is now in attacker hands. That key decrypts repo secrets offline, after the machine is re-imaged, after credentials are rotated. The breach outlives the machine.
- **secretenv:** Active sessions inherited. No persistent decryption key exists anywhere. Re-image the machine, rotate backend credentials — the breach is contained. It dies with the session.

The real defense against machine compromise is credential scoping at the backend level — IAM policies with least privilege, Vault policies with bounded paths, short-lived session tokens. A compromised machine with narrowly scoped credentials has a bounded blast radius regardless of which secrets tool is running. If a machine is fully compromised, you have an incident response problem. The secrets tool is irrelevant at that point.

### The One New Yellow Cell

secretenv introduces one artifact that doesn't exist in any other workflow: the registry document. This document maps alias names to backend paths and is stored in a backend you control.

The honest characterization: if an attacker can access the registry document, they have already authenticated to your backend — the same backend your security team controls, your IAM policies govern, and your audit logs track. At that point they have demonstrated they are past your real defenses. The path topology in the registry is the least valuable thing they now have access to. If they're already inside your SSM with read permissions, the registry tells them paths they could find by listing parameters anyway.

**Treat the registry document's access controls the same as your most sensitive secret.** SSM SecureString with KMS, Vault KV with tight policy, 1Password with restricted sharing. Not a public SSM String parameter.

---

## Shell Injection

Every backend plugin constructs CLI commands using values from the registry. If the registry were compromised, a malicious registry entry could attempt to inject shell commands via the path component of a URI.

secretenv prohibits this structurally. All plugins use argument passing, not shell interpolation:

```rust
// Always — each argument is a separate string, shell never parses it
Command::new("aws")
    .args(["ssm", "get-parameter", "--name", &uri.path])

// Never — shell interpolation, injectable
Command::new("sh").arg("-c")
    .arg(format!("aws ssm get-parameter --name {}", uri.path))
```

This is enforced in the plugin development guide and verified in CI for all first-party backends. Third-party backend authors are required to follow the same pattern.

---

## What secretenv Does Not Solve

**Machine compromise.** If the machine is owned, the attacker runs secretenv themselves, reads the config, watches the CLI invocations. The tool is irrelevant.

**Post-injection secret protection.** Once the process has the env var, secretenv is out of the picture. The process can log it, write it to disk, pass it in an HTTP request. This is outside secretenv's scope and always will be.

**Production runtime security.** secretenv is a developer tool. ECS, Lambda, and Kubernetes have native secret injection mechanisms that are the right answer for production. secretenv is not a runtime secret delivery mechanism.

**Secret rotation enforcement.** secretenv fetches whatever the backend has, rotated or not. Rotation policy is the backend's concern.

**Insider threats with backend access.** An authorized user with registry access and backend access can read anything they're authorized to read. secretenv doesn't add a meaningful barrier to that.

---

## Audit Trail

secretenv has no central audit log. Audit capability depends on each backend:

| Backend | Audit mechanism |
|---|---|
| AWS SSM | CloudTrail logs every `GetParameter` and `PutParameter` call with caller identity, timestamp, and parameter name |
| AWS Secrets Manager | CloudTrail, same coverage |
| HashiCorp Vault | Audit device logs every operation — configurable to file, syslog, or socket |
| 1Password | Admin console activity log |
| GCP Secret Manager | Cloud Audit Logs |
| Azure Key Vault | Azure Monitor diagnostic logs |

For organizations that need to answer "who fetched the production database password last Tuesday" — check CloudTrail or your Vault audit log, not secretenv. The audit trail is there. It lives in your backend.

---

## Supply Chain

secretenv distributed binaries are signed. Checksums are published with every release. The install script verifies checksums before executing.

For high-security environments:

```bash
# Verify checksum before installing
curl -sfS https://secretenv.io/secretenv-linux-amd64.tar.gz -o secretenv.tar.gz
curl -sfS https://secretenv.io/checksums.txt | grep secretenv-linux-amd64 | sha256sum -c

# Or build from source
cargo install secretenv
```

---

## Responsible Disclosure

Security vulnerabilities can be reported to security@secretenv.io. Please do not open public GitHub issues for security vulnerabilities.
