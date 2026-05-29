<div align="center">

# secretenv

<!-- MEDIA: badges-row-extended
     Add when available: tests-count, contributors, downloads, last-release-date, MSRV
-->
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![Crates.io](https://img.shields.io/crates/v/secretenv.svg)](https://crates.io/crates/secretenv)
[![Build](https://img.shields.io/github/actions/workflow/status/TechAlchemistX/secretenv/ci.yml?branch=main)](https://github.com/TechAlchemistX/secretenv/actions)
[![Backends](https://img.shields.io/badge/backends-15-green)](#supported-backends)
[![Smoke](https://img.shields.io/badge/live--smoke-508_assertions-brightgreen)](#stability-proof)

### One registry. Every repo. Every backend. Migrate without touching a single repo.

*No SaaS. No re-encryption. No lock-in. No .env files.*

**Multi-backend secrets orchestration via an alias registry that lives in your own backend.**

[Quick Start](#quick-start) · [How It Works](#the-three-file-model) · [Workflows](#concrete-workflows) · [Backends](#supported-backends) · [CLI Reference](#cli-reference) · [Compare](#how-secretenv-compares) · [Security](#security) · [Docs](docs/)

</div>

---

## The Problem

Your org uses AWS SSM for infra credentials, 1Password for team secrets, and Vault for service tokens. Every developer has a slightly different `.env` file assembled from manual fetches across all three. New engineers spend their first day asking where things live. Offboarding is a manual checklist nobody fully trusts. Migrating from one backend to another means touching every repo.

Every existing tool assumes it is your only secrets backend. You have three. Or four. Or five.

---

## What SecretEnv Does

SecretEnv runs any command with secrets injected as environment variables, sourced from whatever combination of backends your team already uses — without storing, encrypting, or managing any secrets itself. Instead, it orchestrates your existing backends through an **alias registry that lives in your own backend**: name your secrets once in the project manifest, change where the alias points to update every repo on its next run. No PRs. No re-encryption. No coordination.

```bash
secretenv run -- npm start
secretenv run --registry dev -- python manage.py runserver
secretenv run --registry staging -- docker compose up
```

Secrets are fetched at runtime, injected into the child process, and gone when it exits. **No secret values written to disk.**

> **SecretEnv is a coat of paint. If the walls aren't strong, the paint is useless. The walls are your backends.** SecretEnv is not a security product — it's a workflow product that removes the most common vectors for secrets-in-git and secrets-on-disk. Auth, encryption, and storage stay where they already are.


---

## The Three-File Model

SecretEnv separates three things every other tool conflates. **Three files, three owners, three lifecycles.**

| File | Lives where | Who owns it | What it contains | Committed to git? |
|---|---|---|---|---|
| `secretenv.toml` | Repo root | Developer | Alias names + static defaults | **Yes** — contains nothing sensitive |
| `~/.config/secretenv/config.toml` | Machine XDG dir | Each developer (or platform team via profiles) | Backend instances + registry sources | **No** — machine-specific |
| Alias registry document | Inside a backend you already control | Platform / security team | `alias-name → backend-URI` map | **No** — lives in your backend |

The manifest tells SecretEnv **what** is needed. The registry tells SecretEnv **where** things live. The machine config tells SecretEnv **which backends** exist on this machine. Reading the repo teaches you nothing about backend topology, because topology never enters the repo.

For the file-by-file breakdown with full schemas, see [docs/reference/three-file-model-deep.md](docs/reference/three-file-model-deep.md).

### File 1 — The Project Manifest (`secretenv.toml`)

Every repo commits a `secretenv.toml` declaring which secrets it needs — using alias names, not backend paths. Zero infrastructure information.

```toml
# secretenv.toml — committed to git
[secrets]
STRIPE_KEY      = { from = "secretenv://stripe-key" }
DATABASE_URL    = { from = "secretenv://db-url" }
DATADOG_API_KEY = { from = "secretenv://datadog-api-key" }
LOG_LEVEL       = { default = "info" }
```

Two value shapes only — `secretenv://` aliases or static defaults. Direct backend URIs are a hard error.

### File 2 — The Alias Registry

A document stored in any backend your team already controls, mapping alias names to fully-qualified backend URIs:

```toml
# stored in aws-ssm-platform:///secretenv/registry
# managed via: secretenv registry set/unset/list

stripe-key      = "1password-work://payments/stripe/api_key"
db-url          = "aws-ssm-dev:///myapp/dev/db_url"
datadog-api-key = "1password-work://engineering/datadog/api_key"
redis-url       = "aws-ssm-dev:///myapp/dev/redis_url"
```

Change a backend? Update one line in the registry. Every repo picks it up automatically on the next run. The registry lives in a backend **you already control** so you can manage it with the access controls, audit trails, and versioning you already trust — no new tool, no new infrastructure.

### File 3 — The Machine Config

Each developer's machine holds the credential topology — which named backend instances exist, where each registry lives. This file never touches a repo.

```toml
# ~/.config/secretenv/config.toml

[registries.default]
sources = ["aws-ssm-platform:///secretenv/org-registry"]

[registries.dev]
sources = [
  "aws-ssm-dev:///secretenv/dev-registry",       # team aliases, checked first
  "aws-ssm-platform:///secretenv/org-registry",  # org-wide fallback
]

[registries.prod]
sources = ["aws-ssm-prod:///secretenv/prod-registry"]

[backends.aws-ssm-platform]
type        = "aws-ssm"
aws_profile = "platform"
aws_region  = "us-east-2"

[backends.aws-ssm-dev]
type        = "aws-ssm"
aws_profile = "dev"
aws_region  = "us-east-1"

[backends.aws-ssm-prod]
type        = "aws-ssm"
aws_profile = "prod"
aws_region  = "us-east-1"

[backends.1password-work]
type       = "1password"
op_account = "company.1password.com"
```

> **This is Workflow 2's wiring.** Same alias names across all three registries. `--registry dev` vs `--registry prod` routes the same `secretenv.toml` to env-specific backend instances. The manifest never sees env-specific paths.

Platform teams distribute this file across an org with [profiles](#profiles) — one HTTPS-hosted TOML, one install command per developer.

### Resolution Flow

```
secretenv run --registry dev -- npm start

  secretenv.toml          alias registry              backends
  ──────────────          ──────────────              ────────
  STRIPE_KEY              stripe-key               1Password (work account)
    └─ secretenv:// ────►   └─ 1password-work:// ──► op read ...
  DATABASE_URL            db-url                   AWS SSM (dev account)
    └─ secretenv:// ────►   └─ aws-ssm-dev://   ──► aws ssm get-parameter --profile dev
  LOG_LEVEL               (static default)
    └─ "info" ──────────────────────────────────────► injected directly

  All resolved → fetched in parallel → injected into process env → npm start
```

Resolution is **all-or-nothing per invocation**: if any required alias fails to resolve, the child process never starts. Partial environments are never injected.

---

## Quick Start

### Install

```bash
# macOS
brew install secretenv

# Linux / macOS (universal)
curl -sfS https://secretenv.io/install.sh | sh

# Cargo
cargo install secretenv
```

### Configure Your Machine

```bash
secretenv setup aws-ssm:///secretenv/registry --region us-east-1

# ✓ Registry configured as [registries.default]
# ✓ Registry reachable: 12 aliases found
# ✓ AWS credentials detected (profile: default)
```

### Check Everything Is Ready

```bash
secretenv doctor

# ── Registries ───────────────────────────────────────────────────────
#   default
#     ✓ aws-ssm:///secretenv/registry    reachable via aws-ssm
#
# ── Backends ─────────────────────────────────────────────────────────
#   aws-ssm             (aws-ssm)
#     ✓ aws CLI v2.34.35
#     ✓ authenticated  profile=default  account=123456789  region=us-east-1
```

### Add a `secretenv.toml` to Your Project

```toml
[secrets]
STRIPE_KEY   = { from = "secretenv://stripe-key" }
DATABASE_URL = { from = "secretenv://db-url" }
LOG_LEVEL    = { default = "info" }
```

### Run

```bash
secretenv run -- npm start
```

---

## Concrete Workflows

These are the day-to-day workflows SecretEnv was built for.

### Workflow 1 — Day 1: a new engineer joins the team

The platform team published `acme-corp.toml` once to an internal HTTPS host. Onboarding is now two commands:

```bash
# 1. Install the binary
brew install secretenv     # or: curl -sfS https://secretenv.io/install.sh | sh

# 2. Install your team's profile (your platform team owns + hosts this)
secretenv profile install acme-corp \
  --url https://internal.acme.com/secretenv/acme-corp.toml

# 3. Verify
secretenv doctor
```

Clone any repo, run `secretenv run -- npm start`. Done. The profile carries every backend instance and registry source the team has converged on — no copy-paste from a wiki page, no Slack thread asking where Stripe lives. **Publish the profile once; every dev gets it via one command.** Updating org-wide credential topology later is `secretenv profile update` on the developer's machine — the platform team never logs into anyone else's laptop.


### Workflow 2 — Multi-environment deployment

Same `secretenv.toml` works across dev, staging, and prod. The registry cascade routes the same alias names to different backend instances per environment.

```bash
# Same project, same manifest, same code path.
# Only the registry selection changes.

secretenv run --registry dev     -- ./deploy.sh
secretenv run --registry staging -- ./deploy.sh
secretenv run --registry prod    -- ./deploy.sh
```

Each registry maps `db-url`, `stripe-key`, `api-key` to env-specific backends. Your repo never knows which AWS account or which Vault namespace it's running against.


### Workflow 3 — Backend migration without touching repos

Stripe key needs to move from 1Password to Vault. One command:

```bash
# Dry-run first — probe both ends, print the plan, mutate nothing.
secretenv registry migrate stripe-key "vault-prod://secret/payments/stripe_key" --dry-run

# Execute: read from 1Password, write to Vault, flip the registry pointer atomically.
secretenv registry migrate stripe-key "vault-prod://secret/payments/stripe_key"

# Every repo picks this up on the next secretenv run.
# No PRs. No re-encryption. No coordination.
```

`secretenv registry migrate` folds the move into one operation — read from the
current backend, write to the destination (where you have write permission),
flip the registry pointer atomically. The source value is **kept by default**;
add `--delete-source` to remove it after a separately-confirmed prompt. Partial
failures never auto-roll-back by deletion — you're given the manual recovery
commands and you decide. Full reference: [docs/reference/migrate.md](docs/reference/migrate.md).

The older two-step flow — move the value with your own tooling, then
`secretenv registry set` to repoint the alias — still works and remains the
fallback when you don't have write access to the destination from the machine
running `secretenv`.


### Workflow 4 — Offboarding an engineer

Revoke the departing engineer's access to the registry backend. **One operation in IAM, Vault, or 1Password. Done.**

They can no longer resolve any alias. They can no longer fetch any secret via SecretEnv. The revocation is immediate and covers every repo simultaneously — no re-encryption, no manual checklist, no "did we get all of them."

---

## Multiple Accounts and Backends

This is where SecretEnv earns its keep. Real organizations have multiple AWS accounts, multiple credential sets, and multiple backend tools. Named backend instances handle this without new plugins or new concepts — just configuration.

```toml
# Three AWS accounts — one plugin, three named instances
[backends.aws-ssm-platform]   # type = "aws-ssm", aws_profile = "platform", aws_region = "us-east-2"
[backends.aws-ssm-dev]        # type = "aws-ssm", aws_profile = "dev",      aws_region = "us-east-1"
[backends.aws-ssm-prod]       # type = "aws-ssm", aws_profile = "prod",     aws_region = "us-east-1"

# Two 1Password accounts
[backends.1password-work]      # type = "1password", op_account = "company.1password.com"
[backends.1password-personal]  # type = "1password", op_account = "personal.1password.com"
```

Registry entries reference named instances as their URI scheme:

```toml
# dev registry — aliases point to dev account
db-url     = "aws-ssm-dev:///myapp/dev/db_url"
stripe-key = "1password-work://payments/stripe/dev_key"

# prod registry — same alias names, different backends
db-url     = "aws-ssm-prod:///myapp/prod/db_url"
stripe-key = "1password-work://payments/stripe/prod_key"
```

Alias names stay identical across environments. The registry routing handles the rest. Same pattern scales to all 15 backends.

---

## Selecting and Cascading Registries

```bash
# Use [registries.default] from config
secretenv run -- npm start

# Use a named registry from config
secretenv run --registry dev -- npm start

# Use a direct URI — single source, no cascade
secretenv run --registry aws-ssm-dev:///secretenv/registry -- npm start
```

The `--registry` flag accepts either a name (looks up `[registries.<name>]` in config) or a direct URI (uses that document, no cascade). The same disambiguation applies to the `SECRETENV_REGISTRY` environment variable — the canonical mechanism for CI.

**Registry selection precedence:**

```
1. --registry <name-or-uri>          ← explicit per-invocation
2. SECRETENV_REGISTRY=<name-or-uri>  ← CI / shell-session override
3. [registries.default] in config    ← machine default
4. hard error                        ← no assumption made
```

### Cascading

A named registry can cascade across multiple sources. **First match wins.** Use this for team-specific aliases that shadow org-wide defaults.

```toml
[registries.dev]
sources = [
  "aws-ssm-dev:///secretenv/dev-registry",       # team aliases — checked first
  "aws-ssm-platform:///secretenv/org-registry",  # org-wide fallback
]
```

`stripe-key` in the dev registry shadows `stripe-key` in the org registry. Org-wide entries that exist only in the fallback resolve transparently. Writes always go to `sources[0]`.

---

## CI/CD Integration

SecretEnv works in CI via the `SECRETENV_REGISTRY` environment variable. Set it once at the org or repo level — no config file needed on the runner.

```yaml
# GitHub Actions
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions: { id-token: write }
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/github-actions-role
          aws-region: us-east-1

      - name: Install secretenv
        run: curl -sfS https://secretenv.io/install.sh | sh

      - name: Run with secrets
        env:
          SECRETENV_REGISTRY: aws-ssm:///secretenv/registry
        run: secretenv run -- ./deploy.sh
```

**In CI you're not authenticating SecretEnv** — you're authenticating the backend CLI. Set up the backend CLI's service account credentials the same way you would if you were calling it directly. SecretEnv adds no auth layer.

| CI platform | Runner model | Pattern | Reference |
|---|---|---|---|
| GitHub Actions | Ephemeral | OIDC + `SECRETENV_REGISTRY` | inline above |
| GitLab CI | Ephemeral / persistent | Native Vault JWT or CI variables | [docs/ci-cd.md](docs/ci-cd.md) |
| Jenkins | Persistent | Agent-baked CLIs + global env | [docs/ci-cd.md](docs/ci-cd.md) |
| BuildKite | Persistent | Agent-baked CLIs + hooks | [docs/ci-cd.md](docs/ci-cd.md) |
| CircleCI | Ephemeral | Context vars + OIDC | [docs/ci-cd.md](docs/ci-cd.md) |


---

## Rolling SecretEnv Out Across Your Org

Adopting SecretEnv at scale follows a predictable rollout sequence. Each stage is independently reversible.

1. **Discovery.** Inventory existing secret backends. Identify a registry-host candidate (any backend the platform team controls and every engineer can reach — AWS SSM, Vault, 1Password, Cloudflare KV).
2. **Pilot.** One team, one registry, hand-written `config.toml`. Validate end-to-end with `secretenv doctor --extensive`.
3. **Author the org profile.** Publish a single `acme-defaults.toml` to an HTTPS-reachable host (CDN, internal artifact store, or `secretenv.io/profiles`). Profiles are TOML fragments containing `[registries.*]` and `[backends.*]` blocks.
4. **Org-wide install.** Distribute the one-line installer; new joiners get the correct config from minute one. Local config always wins where keys overlap, so a profile can never silently break a developer's workflow.
5. **CI integration.** Set `SECRETENV_REGISTRY` at org-level CI variable scope. Add `secretenv doctor --json` as a pre-deploy gate.
6. **Offboarding playbook.** Codify "revoke registry-backend access" in your IAM runbook. One operation; covers every repo.

**Profile rollback** is a profile re-publish + `secretenv profile update` on the fleet — there is no server-pushed update channel; the developer pulls.

### Profiles

Profiles are how a platform team converges every dev machine to the team's intent without touching individual machines.

```bash
# Install or re-install with updated metadata
secretenv profile install acme-corp --url https://internal.acme.com/secretenv/acme-corp.toml

# Update — ETag-conditional re-fetch; reports up-to-date or refreshed
secretenv profile update

# List + uninstall
secretenv profile list
secretenv profile uninstall acme-corp
```

Profiles are **additive merges, never overrides** — local `config.toml` always wins. Self-hosted / air-gapped orgs override the canonical base via `SECRETENV_PROFILE_URL`. Hard size cap of 1 MiB per profile guards against compromised distributions. Full guide: [docs/reference/profiles.md](docs/reference/profiles.md).

---

## Operational Health: `secretenv doctor`

`secretenv doctor` is the front door for everything operational — onboarding validation, CI pre-deploy gates, on-call diagnostics. It runs three levels of checks, all in parallel.

| Level | Probe | Default |
|---|---|---|
| **L1** | Is the backend's CLI installed? (`aws --version`, `op --version`, ...) | always |
| **L2** | Is the backend authenticated? (`aws sts get-caller-identity`, `op whoami`, ...) | always |
| **L3** | Can we read each registry source? (counts aliases, reports permission scope) | `--extensive` |

```bash
secretenv doctor              # default (L1 + L2)
secretenv doctor --json       # machine-readable for CI / monitoring
secretenv doctor --fix        # interactive remediation (aws sso login, op signin, vault login, ...)
secretenv doctor --extensive  # deep probe — exercises registry reads
```

Exit code is non-zero if any backend reports anything other than `Ok`. `doctor --json` is designed to run in under 2s wall-clock for a 10-backend topology and is suitable as a CI pre-deploy gate or a per-minute monitoring probe.

### Failure semantics

- **Resolution is all-or-nothing per invocation.** If any required alias fails to resolve, the child process never starts. Partial environments are never injected.
- **No on-disk cache.** Every run hits live backends. Deliberate — no stale-cache class of bug, no key material between runs.
- **Failure modes report cleanly.** `BackendUnauthenticated`, `AliasNotFound`, `RegistryUnreachable`, `BackendCliMissing` are the four operationally interesting failure shapes; each carries enough context to triage without re-running.
- **Logging.** `RUST_LOG=secretenv=debug` emits structured logs to stderr. `--verbose` on `run` emits per-secret fetch progress.

---

## Observability

SecretEnv emits OpenTelemetry traces, metrics, and logs for every resolution, backend probe, MCP tool call, and registry mutation. Telemetry is **opt-in** — set `OTEL_EXPORTER_OTLP_ENDPOINT` to point at any OTLP-compatible collector (Jaeger, Tempo, Honeycomb, Datadog, the OTel collector). With no endpoint configured, SecretEnv installs no exporter and has zero startup overhead.

**Production onramp** — two env vars and you're done:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://collector.internal:4317
export OTEL_SERVICE_NAME=payments-secretenv   # optional; defaults to "secretenv"
secretenv run -- ./deploy.sh
```

The first var turns telemetry on; the second overrides the default `secretenv` service name (useful when multiple teams ship SecretEnv-wrapped CI jobs to a shared collector and want per-project tagging). Every standard `OTEL_*` env var works — exporter protocol, headers, timeout, sampler, resource attributes, propagators — per [`docs/reference/opentelemetry.md`](docs/reference/opentelemetry.md) §7.

The full attribute schema, span topology, metric inventory, and the audit-facing redaction taxonomy are documented in [`docs/reference/opentelemetry.md`](docs/reference/opentelemetry.md). Every emitted attribute is enumerated with an explicit ALLOW/DENY classification, enforced at compile time by the typed `SecretEnvSpan` builder — there is no `set_attribute(key, value)` escape hatch.

For observability without a collector: `secretenv run --verbose` shows per-alias timing, and `secretenv doctor --trace` renders an in-process span table from a dry-run resolution pass.

---

## Stability Proof

Every backend tool claims stability. SecretEnv proves it.

The smoke harness exercises the **real binary** against **real backend CLIs** in **real shells** — not mocks, not contract tests. Every assertion validates: spawn the CLI, route input via tempfile or stdin, parse stdout, handle stderr, observe exit code. **508 assertions across 15 backends as of v0.13.0.**

In the v0.13 cycle, this harness caught a latent pipe-deadlock in the Infisical backend that had survived **15 days and 6 release cycles** since Infisical shipped in v0.7.0. CI was green every release. Unit tests passed. Three-agent audits passed. Only the live-backend smoke — running the real binary against the real CLI in a real shell — surfaced it. The fix was one line; the lesson was the harness.

| Release | Date | Backends | Live-smoke assertions | Notable addition |
|---|---|---|---|---|
| v0.2.0 | 2026-04-18 | 5 | ~90 | First integration smoke |
| v0.3.0 | 2026-04-19 | 7 | 250 | +GCP, +Azure |
| v0.4.0 | 2026-04-21 | 7 | 336 | Functionality cycle (+86) |
| v0.5.0 | 2026-04-22 | 8 | 347 | +Keychain |
| v0.6.0 | 2026-04-22 | 9 | 362 | +Doppler |
| v0.7.0 | 2026-04-22 | 10 | 377 | +Infisical |
| v0.8.0 | 2026-04-23 | 11 | 395 | +Keeper |
| v0.9.0 | 2026-04-24 | 12 | 419 | +Cloudflare KV |
| v0.10.0 | 2026-04-26 | 13 | 452 | +OpenBao |
| v0.11.0 | 2026-04-30 | 14 | 479 | +CyberArk Conjur |
| v0.12.0 | 2026-05-05 | 15 | 508 | +Bitwarden Secrets Manager |
| v0.13.0 | 2026-05-07 | 15 | 508 | Hygiene cycle — caught the v0.7-era pipe-deadlock |

Test surface grew with feature surface across ~3 weeks of single-backend-per-minor-release cadence.

---

## Supported Backends

SecretEnv delegates all authentication to each backend's native CLI. The version column below is what the v0.13.0 release smoke ran against.


| Backend | Type | URI Scheme | Tested CLI version | Status |
|---|---|---|---|---|
| [Local file](docs/backends/local.md) | `local` | `local:///path/to/file.toml` | (uses `std::fs`) | Available |
| [AWS SSM Parameter Store](docs/backends/aws-ssm.md) | `aws-ssm` | `aws-ssm-<instance>:///path` | `aws-cli/2.34.35` | Available |
| [AWS Secrets Manager](docs/backends/aws-secrets.md) | `aws-secrets` | `aws-secrets-<instance>:///<name>[#json-key=<field>]` | `aws-cli/2.34.35` | Available |
| [1Password](docs/backends/1password.md) | `1password` | `1password-<instance>://vault/item/field` | `op 2.34.0` | Available |
| [HashiCorp Vault](docs/backends/vault.md) | `vault` | `vault-<instance>:///<mount>/<path>` | `vault 2.0.0` | Available |
| [GCP Secret Manager](docs/backends/gcp.md) | `gcp` | `gcp-<instance>:///<name>[#version=<n>]` | `gcloud 560.0.0` | Available |
| [Azure Key Vault](docs/backends/azure.md) | `azure` | `azure-<instance>:///<name>[#version=<32-hex>]` | `azure-cli 2.85.0` | Available |
| [macOS Keychain](docs/backends/keychain.md) | `keychain` | `keychain-<instance>:///service/account` | macOS `security` (Darwin 25.4) | Available (macOS only) |
| [Doppler](docs/backends/doppler.md) | `doppler` | `doppler-<instance>:///<project>/<config>/<secret>` | `doppler v3.76.0` | Available |
| [Infisical](docs/backends/infisical.md) | `infisical` | `infisical-<instance>:///<project>/<env>/<secret>` | `infisical 0.43.79` | Available |
| [Keeper](docs/backends/keeper.md) | `keeper` | `keeper-<instance>:///<record>[#field=<name>]` | `keeper Commander 17.2.13` | Available |
| [Cloudflare Workers KV](docs/backends/cf-kv.md) | `cf-kv` | `cf-kv-<instance>:///<namespace-id>/<key>` | `wrangler 4.85.0` | Available |
| [OpenBao](docs/backends/openbao.md) | `openbao` | `openbao-<instance>://mount/path[#json-key=<field>]` | `bao v2.5.3` | Available |
| [CyberArk Conjur](docs/backends/conjur.md) | `conjur` | `conjur-<instance>://<variable-id>[#json-key=<field>]` | `conjur v8.1.3` (Go) | Available |
| [Bitwarden Secrets Manager](docs/backends/bitwarden-sm.md) | `bitwarden-sm` | `bitwarden-sm-<instance>://<uuid>[#json-key=<field>]` | `bws 2.0.0` | Available |
| Delinea Secret Server | `delinea` | `delinea-<instance>://folder/secret` | `tss` | Coming Soon |

**Click any backend** for its per-backend doc page — configuration, URI format, authentication, doctor output, examples. Or browse the [backend index](docs/backends/README.md) for the full table with selection guidance.

The URI scheme is your named instance. Multiple instances of the same backend type — for multiple accounts, multiple vaults, or multiple credential sets — are configured in `config.toml` and referenced by their instance name.

<details>
<summary>URI syntax notes — triple slashes, fragments, json-key extraction</summary>

**Why some URIs have three slashes.** Standard URI grammar is `<scheme>://<authority>/<path>`. SecretEnv URIs have no authority component (the "host" position is empty — the instance is encoded in the scheme), so a leading-slash path produces the triple-slash form `<scheme>:///<path>`. AWS SSM REQUIRES the leading `/` because Parameter Store names begin with `/`. The 1Password row uses the double-slash form because its path tokens are `vault/item/field` segments.

**Fragment directives.** URIs optionally carry a `#key=value[,key=value]*` fragment that each backend interprets per its own registered directives — `#json-key=<field>` to pick a value out of a JSON-shaped secret, `#version=<n>` to pin a version. See [docs/reference/fragment-vocabulary.md](docs/reference/fragment-vocabulary.md) for the full grammar.

</details>

> **SecretEnv never calls cloud APIs directly.** Every fetch is a shell-out to the native CLI. This means SecretEnv inherits your MFA, SSO, biometric unlock, and any other auth your backend requires — with **no new authentication surface to audit.**

---

## CLI Reference

```bash
# run — primary use case
secretenv run [--registry <name-or-uri>] [--dry-run] [--verbose] -- <command>

# registry — alias CRUD + history + onboarding helpers
secretenv registry list    [--registry <name-or-uri>]
secretenv registry get     <alias>  [--registry <name-or-uri>]
secretenv registry set     <alias> <backend-uri>  [--registry <name-or-uri>]
secretenv registry unset   <alias>  [--registry <name-or-uri>]
secretenv registry migrate <alias> <dest-uri>  [--dry-run] [--yes] [--from <uri>] [--delete-source] [--json] [--registry <name-or-uri>]
secretenv registry history <alias>  [--registry <name-or-uri>] [--json]
secretenv registry invite  [--registry <name-or-uri>] [--invitee <id>] [--json]

# profile — distribute team config fragments via HTTPS
secretenv profile install   <name> [--url <url>]
secretenv profile list      [--json]
secretenv profile update    [<name>]
secretenv profile uninstall <name>

# doctor — three-level health checks (L1 CLI + L2 auth + L3 read)
secretenv doctor [--json] [--fix] [--extensive]

# setup — bootstrap config wizard
secretenv setup <registry-uri> [--region R] [--profile P] [--account A] [--vault-address ...] [--force] [--skip-doctor]

# completions, resolve, get
secretenv completions <bash|zsh|fish> [--output <path>]
secretenv resolve <alias> [--registry <name-or-uri>]
secretenv get <alias> [--registry <name-or-uri>] [--yes]
```

**Global flag:** `--config <path>` (defaults to `$XDG_CONFIG_HOME/secretenv/config.toml`)

**Environment variables:**

```bash
SECRETENV_REGISTRY=<name-or-uri>   # registry override — primary CI mechanism
SECRETENV_PROFILE_URL=<base-url>   # override the default profile fetch base
RUST_LOG=secretenv=debug           # structured logging (default: secretenv=warn)
```

All commands are available as of v0.13.0. Full per-flag reference + exit codes: [docs/reference/cli-reference-full.md](docs/reference/cli-reference-full.md).

---

## How SecretEnv Compares

| Property | **SecretEnv** | `.env` | fnox¹ | direnv |
|---|---|---|---|---|
| Multi-backend in one invocation | **✓** | — | ✓ | manual per-project |
| Backend migration without editing repos | **✓** (one `registry set`) | n/a | ✗ (edit every `fnox.toml`) | n/a |
| Infrastructure topology hidden from repos | **✓** (aliases only) | ✗ | ✓ (ciphertext or refs) | ✗ (paths in `.envrc`) |
| Centrally-shared mutable alias registry | **✓** (lives in your backend) | — | — | — |
| One-line offboarding (single revoke covers all repos) | **✓** | ✗ | ✗ (age) / ✓ (KMS — IAM revoke) | ✗ |
| Stores no secret material on disk | **✓** | ✗ | depends¹ | **✓** |
| No SaaS dependency | **✓** | ✓ | ✓ | ✓ |
| Inherits backend MFA / SSO / biometric | **✓** (native CLI) | — | partial | — |

¹ **fnox** is multi-mode. Age mode keeps an age private key on disk; KMS modes (aws-kms / azure-kms / gcp-kms) gate decryption on IAM and have no persistent disk key. SecretEnv's distinction is orthogonal to encryption: the alias-registry layer removes backend topology from every repo. See [docs/comparisons/vs-fnox.md](docs/comparisons/vs-fnox.md) for the mode-by-mode breakdown.

### Why not...

- **`.env` files** — Manual, error-prone, accumulate stale values, get committed accidentally, sit on disk in plaintext, make offboarding a checklist nobody fully trusts. This is the workflow SecretEnv replaces. Full: [docs/comparisons/vs-dotenv.md](docs/comparisons/vs-dotenv.md).
- **fnox** — A thoughtful multi-mode tool covering age-encryption, KMS-gated decryption, and cloud references. **In KMS modes, fnox closes the persistent-key + offboarding concerns at the KMS-key level.** SecretEnv's distinction is orthogonal: an alias-registry layer above the backend that decouples repos from backend URIs entirely. Migrating a secret in fnox (any mode) means editing every `fnox.toml`; in SecretEnv it's one `registry set`. Full: [docs/comparisons/vs-fnox.md](docs/comparisons/vs-fnox.md).
- **`direnv`** — Shell-hook model requires writing custom glue per project. Backend integration is manual scripting. Paths live in `.envrc` files. No standard for what a project needs or where things live. Full: [docs/comparisons/vs-direnv.md](docs/comparisons/vs-direnv.md).

**Per-tool deep dives** for op run / doppler run / Pulumi ESC / External Secrets Operator / sops / Vault Enterprise + Conjur as identity platforms: see the [docs/comparisons/](docs/comparisons/) directory.

---

## Right For You / Not Right For You

**Pick SecretEnv if:**
- Your team uses **2+ secret backends** and wants a unified onboarding/offboarding story
- You want **infrastructure topology hidden** from your repos (no AWS account IDs, no Vault namespaces in code)
- You've experienced backend migrations and want to avoid touching N microservices next time
- You want to avoid SaaS gates for a core workflow tool
- You operate across local dev + ephemeral CI + persistent CI, and want **one tool** for all three

**Pick something else if:**
- You're committed to a single backend long-term — the single-backend wrappers (`op run`, `doppler run`, `infisical run`) are simpler and more deeply integrated with their UIs
- Your entire deployment is Kubernetes — **External Secrets Operator** has tighter in-cluster integration
- You need a hosted policy engine, hosted audit trail, or rotation orchestration as a service — **Pulumi ESC**, **Vault Enterprise**, or **CyberArk Conjur** are purpose-built for that
- You need at-rest file encryption for gitops workflows — **sops** owns that category
- You want client-side encryption with KMS-gated decryption stored in committed config — **fnox** in KMS mode is purpose-built for that

---

## Security

> **SecretEnv is not a security product. It is a workflow product that removes the most common vectors for secrets-in-git and secrets-on-disk — the failures that happen at scale.**

The model is simple: SecretEnv has no credential storage, no login command, and no auth surface of its own. If your backend is authenticated, SecretEnv works. If it isn't, SecretEnv fails with the same error the native CLI would give you. Fix it there.

### What SecretEnv eliminates

- **Secrets committed to git accidentally** — eliminated; nothing to commit.
- **Secret values sitting on disk in plaintext** — eliminated; nothing written.
- **Infrastructure paths exposed in repos** — eliminated; aliases only.
- **Manual offboarding gaps** — one backend access revocation covers everything.
- **Backend lock-in** — registry update migrates every repo simultaneously.
- **Stale secrets** — fetched on every invocation; rotation is transparent on next run (subject to backend caching).

### What SecretEnv deliberately does NOT do

- **Machine compromise** — if the machine is owned, active backend sessions are inherited. This is true for every secrets tool. The real defense is credential scoping at the backend level.
- **Post-injection process exposure** — once secrets are injected as env vars, they are readable by any process running as the same user. This is a property of the env-var model, not a SecretEnv issue.
- **Runtime production injection** — for ECS / Lambda / Kubernetes, the platform-native injection mechanisms are the right answer. SecretEnv is for local dev + CI + general-purpose runtime.
- **Encryption at rest.** SecretEnv stores no secret values, so it provides no encryption-at-rest property. Encryption at rest is the responsibility of whichever backend holds the value (Vault's storage encryption, SSM SecureString + KMS, 1Password's E2E vault). Tools like fnox (KMS modes) and sops *do* provide ciphertext-in-repo and are the right answer if that's the property you need.
- **Policy engines, audit log services, rotation orchestration** — these belong to your backend (or a dedicated identity platform). SecretEnv routes to them; it does not replace them.

### Defensive engineering

- **No decryption surface at all.** SecretEnv neither holds nor needs a decryption key — it has nothing encrypted to decrypt. This is a structural property of being a router, not a security feature we engineered. Tools that gate decryption on cloud IAM (fnox-KMS, op-run, doppler-run) achieve comparable containment a different way.
- **No secret values written to disk.** In-memory secrets use `zeroize::Zeroizing` and are zeroed on drop.
- **No secrets in CLI argv.** Every backend uses safe stdin / tempfile forms (`-f /dev/stdin`, `value=-`, mode-0600 tempfiles). Unsafe argv forms are gated behind opt-in `<backend>_unsafe_set` flags and emit warnings on every use.
- **Control-character validation on URIs.** NUL and ASCII <0x20 (except tab) are rejected at parse time; stops a class of injection-via-registry attacks.
- **Manifest VCS-sentinel boundary.** The upward walk for `secretenv.toml` stops at `.git`/`.hg`/`.svn`/`.secretenv-root`. Prevents a hostile parent directory from hijacking resolution.
- **Registry-write determinism.** Writes use `BTreeMap` ordering — clean diffs make registry tampering reviewable in PRs.
- **CLI version pinning.** Backends validate the wrapped CLI's version (e.g., Conjur v7 is rejected; only v8 accepted) — incompatible CLIs surface as clear errors, not silent corruption.

### Comparison summary (security-relevant axes)

| Property | **SecretEnv** | `.env` | fnox (age) | fnox (KMS / aws-sm / vault) |
|---|---|---|---|---|
| Backend migration without editing repos | **✓** registry update | n/a | ✗ edit every `fnox.toml`; re-encrypt | ✗ edit every `fnox.toml` (no re-encrypt for ref modes) |
| One-revoke offboarding across all repos | **✓** revoke registry-backend access | manual | ✗ re-encrypt without ex-member's recipient | ✓ IAM revoke on the KMS key |
| No persistent decryption key on disk | **✓** no decryption surface | n/a | ✗ age private key on disk | ✓ IAM-gated KMS calls |
| Machine-compromise containment after re-image | **✓** active sessions only; bounded by backend scope | plaintext breach permanent | ✗ age key theft = offline decryption survives re-image | ✓ active sessions only; bounded by KMS key policy |
| Repo contains backend topology | **✓** no — aliases only | ✗ yes (paths) | ✗ yes (provider + path, encrypted) | ✗ yes (provider + path, ciphertext or reference) |

The honest line: **encryption posture is comparable across SecretEnv and fnox-KMS-mode.** The differentiator is alias indirection — SecretEnv's registry decouples the alias from the backend URI so a migration is one `registry set` instead of editing every config. That property is orthogonal to encryption.

### Redaction (v0.14)

SecretEnv redacts resolved values from child-process stdout/stderr **by default**. `secretenv run` pipes the child's stdio through a streaming scrubber that substitutes resolved values with `[redacted:<alias>]`. For post-hoc cleanup of existing files, `secretenv redact <path>` performs the same substitution against a tainted set built from the active registry.

- **Default on** for non-TTY parents (CI, pipelines, scripts). The default invocation requires no flag changes.
- **Auto-fallback to `exec()`** for interactive TTY parents — preserves `psql`, `vim`, `ssh`, and any other PTY-bound child. One-line stderr advisory tells you when fallback fires.
- **`--redact`** forces pipe-based redaction on a TTY (PTY-bound children may misbehave).
- **`--no-redact --i-know`** opts out entirely. The two-flag dance prevents CI typos from accidentally printing values.
- **`secretenv redact <path>`** scrubs an existing file post-hoc. `--in-place` rewrites atomically (sibling tempfile + `rename(2)`); `--backup .bak` keeps the original; `--dry-run` counts without writing.

Defense-in-depth, not a complete protection. The full Limits matrix (writes to `/dev/tty`, `syslog`, `mmap`, core dumps, etc.) lives in [docs/security.md](docs/security.md#redaction-v014); the operator reference for both modes is at [docs/reference/redact.md](docs/reference/redact.md).

### Full threat model + responsible disclosure

A 14-category threat-model comparison across `.env`, `direnv`, `op run`, `doppler run`, `fnox`, and SecretEnv lives in [docs/security.md](docs/security.md). For responsible disclosure, see [SECURITY.md](SECURITY.md).

---

## Plugin Architecture

The core is an SDK. It parses `secretenv.toml`, resolves `--registry` to a source list, fetches registry documents, resolves aliases, fetches secret values in parallel, and injects them into the child process. The core never knows about AWS, Vault, 1Password, or any specific backend — it only speaks the trait interface.

Every backend is an independent Rust crate in `crates/backends/` implementing two traits defined in `secretenv-core`. Adding a new backend is a new crate plus one line of factory registration — never a change to core. All 15 backends compile into the single binary; no feature flags. The presence (or absence) of `[backends.<name>]` in `config.toml` determines which backends are active at runtime.

For the trait interface and step-by-step backend-development guide: [docs/reference/adding-a-backend.md](docs/reference/adding-a-backend.md).

---

## Contributing

SecretEnv is built in Rust and welcomes contributions. The easiest entry point is adding a new backend — each one is a self-contained crate with a focused, well-defined interface.

```bash
git clone https://github.com/TechAlchemistX/secretenv
cd secretenv
cargo build
cargo test
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide. Issues tagged [`good first issue`](https://github.com/TechAlchemistX/secretenv/issues?q=label%3A%22good+first+issue%22) are scoped for first-time contributors.

---

## License

**GNU Affero General Public License v3.0 (AGPL-3.0-only)** — see [LICENSE](LICENSE).

SecretEnv is free to use, modify, and redistribute under AGPLv3. **§13 of the AGPL requires that any network-deployed modified version make its corresponding source code available to its users.** If you fork SecretEnv and operate the fork as a service, you must offer its source to your users. **Using SecretEnv as a CLI inside your organization — even commercially — is unaffected by §13; it triggers only on network-service deployment of a modified fork.**

MIT was the license for v0.1 and v0.2.0. **v0.3.0 onward is AGPL-3.0-only.**

Contributions are welcome under the project's [Contributor License Agreement](CLA.md). The CLA lets the project relicense contributions while keeping your own rights intact. **No CLA = no merge.**

---

<div align="center">

Built with frustration at `.env` files and too many password managers.

**[⭐ Star on GitHub](https://github.com/TechAlchemistX/secretenv)** · **[All docs](docs/README.md)** · **[Threat model](docs/security.md)** · **[Add a backend](docs/reference/adding-a-backend.md)**

</div>
