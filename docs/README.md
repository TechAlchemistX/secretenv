# SecretEnv Documentation

The main [README](../README.md) covers the basics — install, configure, and run your first command. This directory holds the deep references that don't belong in the main README.

---

## Getting Started
- **[Quick Start](../README.md#quick-start)** — install, configure, and run your first command
- **[Configuration Reference](reference/configuration.md)** — schema for `secretenv.toml` and machine config
- **[CLI Reference](reference/cli-reference-full.md)** — every command, every flag, every exit code

## Core Concepts
- **[The Three-File Model (Deep)](reference/three-file-model-deep.md)** — full schemas, validation rules, 5-phase resolution flow
- **[Registry Management](reference/registry.md)** — alias registry concepts and CLI commands
- **[Profiles & Distribution](reference/profiles.md)** — how to share org-wide config
- **[Fragment Vocabulary](reference/fragment-vocabulary.md)** — URI `#directive` grammar

## Backends
- **[Supported Backends](backends/README.md)** — 15 backend pages with config, URI format, examples, tested CLI versions
- **[Adding a Backend](reference/adding-a-backend.md)** — trait interface and step-by-step development guide

## How SecretEnv Compares
- **[Tool Comparisons](comparisons/README.md)** — `.env` vs fnox vs direnv vs op-run vs Pulumi ESC vs ESO vs sops vs Vault/Conjur

## Security & Operations
- **[Threat Model & Security](security.md)** — 14-category honest comparison with alternatives
- **[CI/CD Integration](ci-cd.md)** — GitHub Actions, GitLab, Jenkins, BuildKite, CircleCI patterns

---

**Try it now:** `secretenv doctor` — the front door for validating your config against any backend. See [Operational Health](../README.md#operational-health-secretenv-doctor) in the main README.
