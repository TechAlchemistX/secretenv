---
layout: home

title: secretenv
titleTemplate: Multi-backend secrets via an alias registry

hero:
  name: secretenv
  text: 'Multi-backend secrets via an <em>alias registry</em>'
  tagline: One registry. Every repo. Every backend. Migrate without touching a single repo.
  actions:
    - theme: brand
      text: Get Started
      link: /#quick-start
    - theme: alt
      text: View on GitHub
      link: https://github.com/TechAlchemistX/secretenv

features:
  - icon: 🗂
    title: Three files, three owners
    details: '<code>secretenv.toml</code> in the repo lists alias names. Machine config names backend instances. The registry — inside a backend you control — maps aliases to backend URIs.'
    link: /reference/three-file-model-deep
    linkText: Read the model

  - icon: 🔌
    title: 15 backends, one binary
    details: AWS SSM, AWS Secrets, 1Password, Vault, GCP, Azure, Doppler, Infisical, Keeper, Cloudflare KV, OpenBao, Conjur, Bitwarden Secrets Manager, macOS Keychain, local files. No plugins. No feature flags.
    link: /backends/
    linkText: All backends

  - icon: 🔁
    title: Migrate without touching repos
    details: 'Move a secret from 1Password to Vault: <code>secretenv registry set</code>. Every repo picks it up on the next run. No PRs, no re-encryption, no coordination.'
    link: /reference/registry
    linkText: Registry workflow

  - icon: ⚙️
    title: CI-first integration
    details: 'Set <code>SECRETENV_REGISTRY</code> once. OIDC patterns for GitHub Actions, GitLab, Jenkins, BuildKite, CircleCI. <code>doctor --json</code> as a pre-deploy gate.'
    link: /ci-cd
    linkText: CI/CD guide

  - icon: 🧭
    title: Honest threat model
    details: A workflow product, not a security product. We document what we eliminate, what we don't, and how the posture compares to .env, fnox, op-run, and direnv.
    link: /security
    linkText: Threat model

  - icon: 📖
    title: No SaaS, no lock-in
    details: 'Open source, AGPLv3. No server. No account. The registry lives in your own backend. AGPL §13 only triggers on network-deployed forks.'
    link: /comparisons/
    linkText: How it compares
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

### Configure your machine

```bash
secretenv setup aws-ssm:///secretenv/registry --region us-east-1
```

Output:

```
✓ Registry configured as [registries.default]
✓ Registry reachable: 12 aliases found
✓ AWS credentials detected (profile: default)
```

### Add a `secretenv.toml` to your project

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

Secrets are fetched from whichever backends the registry points to, injected as env vars into the child process, and gone when it exits. **No secret values written to disk.**

---

## How it fits together

The **manifest** says *what* the project needs. The **machine config** says *which backends* this machine has. The **registry** says *which backend URI* each alias resolves to.

::: tip Why the indirection?
Repos commit alias names like `secretenv://stripe-key`. The registry maps each alias to its current backend location. Migrating from 1Password to Vault becomes one `secretenv registry set` — every repo picks it up on the next run, no PRs.
:::

For the full schemas, validation rules, and 5-phase resolution flow: [The Three-File Model — Deep Reference](/reference/three-file-model-deep).

---

## Where to go next

- [**Backends**](/backends/) — 15 backend pages with config, URI format, examples, tested CLI versions
- [**CLI Reference**](/reference/cli-reference-full) — every command, every flag, every exit code
- [**CI/CD Integration**](/ci-cd) — GitHub Actions, GitLab, Jenkins, BuildKite, CircleCI patterns
- [**Threat Model**](/security) — 14-category honest comparison with `.env`, fnox, op-run, direnv
- [**Comparisons**](/comparisons/) — when to pick secretenv vs. an alternative

::: info Try it now
`secretenv doctor` is the front door for validating your config against any backend. Run it after install, after every config change, and as a CI pre-deploy gate.
:::
