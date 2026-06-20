# SecretEnv Documentation

The main [README](../README.md) covers install, configure, and your first command. This directory holds the deep references.

---

## Getting started
- **[Quick Start](../README.md#quick-start)**: install, configure, run
- **[Configuration Reference](reference/configuration.md)**: schema for `secretenv.toml` and machine config
- **[CLI Reference](reference/cli-reference-full.md)**: every command, every flag, every exit code

## Core concepts
- **[The Three-File Model](reference/three-file-model-deep.md)**: full schemas, validation rules, 5-phase resolution flow
- **[Registry Management](reference/registry.md)**: alias registry concepts, cascading, and CLI commands
- **[Migrating a Secret](reference/migrate.md)**: `registry migrate` mechanics and recovery
- **[Profiles & Distribution](reference/profiles.md)**: share org-wide config over HTTPS
- **[Fragment Vocabulary](reference/fragment-vocabulary.md)**: URI `#directive` grammar

## Backends
- **[Supported Backends](backends/README.md)**: 15 backend pages with config, URI format, examples, tested CLI versions
- **[Adding a Backend](reference/adding-a-backend.md)**: trait interface and step-by-step development guide

## Operations
- **[CI/CD Integration](guides/ci-cd.md)**: GitHub Actions, GitLab, Jenkins, BuildKite, CircleCI patterns
- **[Org Rollout](guides/rollout.md)**: the six-stage adoption playbook
- **[OpenTelemetry](reference/opentelemetry.md)**: opt-in traces and metrics; the redaction attribute taxonomy
- **[Redaction](reference/redact.md)**: scrubbing values from output and existing files
- **[MCP Server](reference/mcp.md)**: the Model Context Protocol server and its tools

## Security & comparisons
- **[Threat Model & Security](security.md)**: 14-category honest comparison with alternatives
- **[Tool Comparisons](comparisons/README.md)**: `.env`, fnox, direnv, op run, doppler run, Pulumi ESC, ESO, sops, Vault/Conjur

## Project
- **[Stability & Smoke History](stability.md)**: live-backend assertion count for every release, since v0.2.0

---

**Try it now:** `secretenv doctor` is the front door for validating your config against any backend. See [Health & observability](../README.md#health--observability) in the main README.
