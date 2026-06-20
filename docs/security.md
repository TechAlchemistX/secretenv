# Security

**secretenv is not a security product. It is a workflow product** that eliminates a class of workflow-driven security failures. It doesn't make your secrets more secure. It makes your team less likely to handle them insecurely, and for most teams, habits are where the breaches actually happen.

---

## The Model

secretenv is a coat of paint: if the walls aren't strong, the paint is useless, and the walls are your backends. Its security posture is entirely inherited from the backends it wraps: it adds no authentication surface, stores no credentials, and makes no access-control decisions. What it removes is the workflow layer where secrets most commonly leak: `.env` files, hardcoded paths in repos, manual sharing, and offboarding gaps.

**It doesn't replace good tools. It replaces bad habits.**

---

## A Note on fnox

**fnox is multi-mode**, and the columns below are split accordingly. It supports age-encryption (private key on disk), KMS-gated encryption (`aws-kms` / `azure-kms` / `gcp-kms`, no persistent disk key, decryption gated on IAM), and pure cloud-reference modes (`aws-sm`, `vault`, `1password`, etc., no encryption involved). **In KMS modes, fnox closes the persistent-key and offboarding concerns at the KMS-key level**, and the threat model reflects that. Full mode-by-mode breakdown: [comparisons/vs-fnox.md](comparisons/vs-fnox.md).

---

## Threat Model Comparison

The table below maps 14 threat categories across common secrets workflows. The goal is not to show secretenv wins everywhere. It doesn't. The goal is an honest map of where risks move.

| Threat | **secretenv** | .env files | fnox (KMS) | direnv | op run | doppler run | fnox (age) |
|---|---|---|---|---|---|---|---|
| **Secrets committed to git** | **Eliminated**, aliases only | High, files exist to be committed | Low, ciphertext or reference-only | High, `.envrc` can contain secrets | Medium, 1Password URIs committed, not values | Low, no secrets in repo | Low, encrypted at rest |
| **Secrets on disk in plaintext** | **Eliminated**, nothing written | High, that's the entire model | Low, runtime KMS decrypt or reference fetch | High, reads from local files | Low, runtime fetch | Low, runtime fetch | Medium, encrypted, key required |
| **Infrastructure paths in repos** | **Eliminated**, aliases only | High, paths are the config | High, provider + path/KMS-key-id committed | High, paths in `.envrc` | High, `op://` URIs committed | Low, project name only | Medium, paths present, encrypted |
| **New engineer onboarding** | **One command** | High, manual credential ceremony | Low, IAM grant on KMS / backend access | High, write custom `.envrc` per project | Medium, 1Password access + `op` CLI | Medium, Doppler token + CLI | Medium, age key ceremony + backend setup |
| **Offboarding a departing engineer** | **One operation**, revoke registry backend access | High, manual, slow, cached copies unknown | Low, IAM revoke on KMS key / backend | High, manual, files may be cached | Medium, remove from 1Password vault | Medium, remove from Doppler | High, re-encryption required across all repos |
| **Backend migration** | **One registry update**, all repos inherit | High, update every `.env` everywhere | High, edit every `fnox.toml` (KMS modes also re-encrypt) | High, rewrite `.envrc` everywhere | Critical, locked to 1Password | Critical, locked to Doppler | High, re-encrypt everything |
| **Machine compromise** | Active sessions exploitable, **no persistent key**, breach contained after re-image | Plaintext files directly readable | Active sessions exploitable, no persistent key; bounded by KMS / backend policy | Same as `.env` | Active sessions exploitable | Active sessions + Doppler token at risk | Active sessions + **age private key theft**, offline decryption survives re-image |
| **Registry document compromise** | **New**: path topology exposed. Requires authenticated backend access. | Does not exist | Does not exist | Does not exist | Does not exist | Does not exist | Does not exist |
| **Post-injection process exposure** | **Universal**, property of env var model, not the tool | Universal | Universal | Universal | Universal | Universal | Universal |
| **Audit trail** | **Delegated to backends**: CloudTrail, Vault audit, 1Password activity | None | KMS CloudTrail / backend audit | None | 1Password activity log | Doppler audit log | Backend-dependent |
| **Supply chain risk** | **Install script**, mitigated by signed binaries | None | fnox binary + cloud SDK trust | Low | `op` CLI binary trust | Doppler CLI + SaaS | age tooling |
| **SaaS dependency** | **None**, no secretenv service | None | Cloud KMS / backend reachability required | None | None | Hard, Doppler is the backend | None |
| **Secret rotation visibility** | **Automatic**, runtime fetch, rotation transparent | None, files go stale silently | Automatic in reference modes; manual on KMS-key rotation | None, `.envrc` goes stale | Automatic, runtime fetch | Automatic, Doppler manages rotation | Manual, re-encrypt with new value |
| **Multi-backend coordination** | **Native**, registry abstracts all backends | Manual copy-paste across tools | fnox supports many providers; per-repo config | Manual shell glue per project | Single backend only | Single backend only | Possible but complex at scale |

---

## Reading the Table

### What secretenv Eliminates

The threats secretenv eliminates (the cells marked **Eliminated**, **One command**, or **One operation** in its column) are the high-frequency failures, the ones that happen not because attackers are sophisticated, but because developers are human, in a hurry, and doing the expedient thing under deadline pressure. Accidental commits. Stale files. Paths in repos. Manual offboarding. Backend lock-in. Rotation blindness.

These are the failures that actually cost organizations. Eliminating them is real, meaningful security improvement.

### What No Tool Solves

**Post-injection process exposure** (marked **Universal** for every tool in the table) is a property of environment variables, not of any tool. Once a secret is injected as an env var, it is readable by any process running as the same user. On Linux, `/proc/<pid>/environ` exposes it to same-user processes. The fix is OS or container-level process isolation, not a different secrets tool.

**Machine compromise** is universal. When a machine is owned, the attacker inherits whatever the user had: active cloud sessions, active Vault tokens, active 1Password sessions. The tool choice does not change this.

What the tool choice *does* affect is the blast radius and post-incident containment:

- **`.env` files:** Plaintext on disk, immediately readable, breach is permanent regardless of what you do next.
- **fnox (age mode):** Active sessions inherited *plus* the age private key is now in attacker hands. That key decrypts repo ciphertext offline, after the machine is re-imaged, after credentials are rotated. The breach outlives the machine.
- **fnox (KMS / cloud-reference modes):** Active sessions inherited. No persistent decryption key on disk. Decryption (KMS modes) and reference resolution (`aws-sm`, `vault`, etc.) are gated by IAM / backend policy. Re-image the machine, rotate or revoke the IAM principal, and the breach is contained. Same containment shape as secretenv.
- **secretenv:** Active sessions inherited. No persistent decryption key exists anywhere; secretenv has nothing encrypted to decrypt. Re-image the machine, rotate backend credentials, and the breach is contained. It dies with the session.

The real defense against machine compromise is credential scoping at the backend level: IAM policies with least privilege, Vault policies with bounded paths, short-lived session tokens. A compromised machine with narrowly scoped credentials has a bounded blast radius regardless of which secrets tool is running. If a machine is fully compromised, you have an incident response problem. The secrets tool is irrelevant at that point.

### The One New Risk secretenv Introduces

secretenv introduces one artifact that doesn't exist in any other workflow: the registry document (the **Registry document compromise** row, marked **New** in secretenv's column and "Does not exist" for every other tool). This document maps alias names to backend paths and is stored in a backend you control.

The honest characterization: if an attacker can access the registry document, they have already authenticated to your backend, the same backend your security team controls, your IAM policies govern, and your audit logs track. At that point they have demonstrated they are past your real defenses. The path topology in the registry is the least valuable thing they now have access to. If they're already inside your SSM with read permissions, the registry tells them paths they could find by listing parameters anyway.

**Treat the registry document's access controls the same as your most sensitive secret.** SSM SecureString with KMS, Vault KV with tight policy, 1Password with restricted sharing. Not a public SSM String parameter.

---

## Shell Injection

Every backend plugin constructs CLI commands using values from the registry. If the registry were compromised, a malicious registry entry could attempt to inject shell commands via the path component of a URI.

secretenv prohibits this structurally. All plugins use argument passing, not shell interpolation:

```rust
// Always: each argument is a separate string, shell never parses it
Command::new("aws")
    .args(["ssm", "get-parameter", "--name", &uri.path])

// Never: shell interpolation, injectable
Command::new("sh").arg("-c")
    .arg(format!("aws ssm get-parameter --name {}", uri.path))
```

This is enforced in the plugin development guide and verified in CI for all first-party backends. Third-party backend authors are required to follow the same pattern.

---

## What secretenv Does Not Solve

- **Machine compromise** and **post-injection secret protection**, covered under [Reading the Table](#reading-the-table). Both are universal: machine compromise inherits whatever the user had (any tool), and once a secret is an env var the process can log it, write it, or send it anywhere (a property of env vars, not the tool).
- **Production runtime security.** secretenv is a developer tool. ECS, Lambda, and Kubernetes have native secret injection that is the right answer for production.
- **Encryption at rest.** secretenv stores no secret values, so it provides none. That belongs to the backend (Vault storage encryption, SSM SecureString + KMS, 1Password's E2E vault). Tools like fnox (age + KMS modes) and sops provide ciphertext-in-repo if that's the property you need.
- **Secret rotation enforcement.** secretenv fetches whatever the backend has, rotated or not. Rotation policy is the backend's concern.
- **Insider threats with backend access.** An authorized user with registry and backend access reads anything they're authorized to read. secretenv adds no barrier there.

---

## Audit Trail

secretenv has no central audit log. Audit capability depends on each backend:

| Backend | Audit mechanism |
|---|---|
| AWS SSM | CloudTrail logs every `GetParameter` and `PutParameter` call with caller identity, timestamp, and parameter name |
| AWS Secrets Manager | CloudTrail, same coverage |
| HashiCorp Vault | Audit device logs every operation, configurable to file, syslog, or socket |
| 1Password | Admin console activity log |
| GCP Secret Manager | Cloud Audit Logs |
| Azure Key Vault | Azure Monitor diagnostic logs |

For organizations that need to answer "who fetched the production database password last Tuesday". Check CloudTrail or your Vault audit log, not secretenv. The audit trail is there. It lives in your backend.

---

## Self-hosted Domains

Four backends accept a user-supplied endpoint:

- **Infisical**: `infisical_domain` (defaults to `app.infisical.com`).
- **Vault**: `vault_address` (no default; required).
- **OpenBao**: `bao_address` (no default; required). Same threat model as Vault, routes via `BAO_ADDR`.
- **CyberArk Conjur**: `conjur_url` (no default; required). Routes via `CONJUR_APPLIANCE_URL`.

The domain IS the trust boundary. A hostile endpoint receives every token and URI the backend routes through it: for Infisical that includes `$INFISICAL_TOKEN` on every CLI invocation; for Vault it includes every request to `/v1/...` carrying the client token.

Discipline that applies to both:

1. **Verify the domain belongs to your organization.** Typos (`infisical.acne.com` vs. `infisical.acme.com`) + attacker-controlled lookalike registrations silently drain credentials. Compare the domain against your IaC repo / provisioning scripts, not a dashboard screenshot someone sent in chat.
2. **Pin HTTPS with a cert you trust.** `http://` is accepted by both CLIs but leaks the token to anyone on-path, only acceptable for loopback dev (`http://127.0.0.1:<port>`).
3. **Confirm the TLS cert chain.** For BYO-CA / internal-PKI setups, the issuing CA must be in the system trust store of every machine running `secretenv`. Test with `openssl s_client -connect <host>:443 -servername <host> </dev/null`. Inspect the `Verify return code: 0 (ok)` line and the presented chain.
4. **Don't inherit a domain from an untrusted registry.** A compromised registry can set `infisical_domain` / `vault_address` in downstream configs and redirect every resolve through an attacker-owned endpoint. Only accept these fields in config files your team owns.
5. **Rotate tokens after suspected exposure.** If you discover the domain was wrong, even briefly, assume every token + secret URI that routed through it is compromised. Rotate immediately.

Per-backend specifics:

- [backends/infisical.md](backends/infisical.md), Infisical's `infisical_domain` threat model.
- [backends/vault.md](backends/vault.md), Vault's `vault_address` and namespace scoping.
- [backends/openbao.md](backends/openbao.md), OpenBao's `bao_address`.
- [backends/conjur.md](backends/conjur.md), Conjur's `conjur_url`.

---

## Redaction (v0.14+)

`secretenv run` redacts resolved values from the child's stdout and stderr **by default** (an Aho-Corasick scan substitutes each match with `[redacted:<alias>]`), and `secretenv redact <path>` scrubs existing files post-hoc. This catches the most common accidental-leak class: an application or CI step printing a resolved env-var value into logs that land in a shared artifact store. The full operator reference (both modes, flags, safety guards, substitution token) is at [reference/redact.md](reference/redact.md).

### Limits: what redaction does NOT catch

Redaction is **defense-in-depth, not complete protection.** These escape the pipe entirely or sit outside SecretEnv's view:

- **Writes to `/dev/tty`**: bypass the parent process's pipe entirely.
- **`syslog(3)` / `journald` / kernel logging**: kernel writes never traverse the parent stdio pipes.
- **`mmap`'d output**: file-backed shared memory; the parent never sees the bytes.
- **Core dumps and post-mortem analysis**: process memory at fault time holds the unwrapped values.
- **Interactive TTY children**: `Auto` mode falls back to `exec()` and forwards the raw stdio without redaction, because a pipe would break the PTY contract.
- **Children that re-fetch values via a cloud SDK directly**: bypass SecretEnv entirely.
- **Values shorter than 8 bytes**: skipped, because shorter substrings false-positive across normal text and destroy log readability. An 8-byte API key is a vendor problem; rotate to a longer credential.

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
