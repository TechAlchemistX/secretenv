# CI/CD Integration

SecretEnv works in CI via the `SECRETENV_REGISTRY` environment variable. No config file is needed on the runner — set the variable once at the org or repo level and every `secretenv run` in every pipeline resolves from the right registry.

The [CI/CD Integration overview](/ci-cd) has the headline GitHub Actions example. This page is the deeper playbook for Jenkins, GitLab, BuildKite, and CircleCI patterns — plus the per-CI-platform runner-lifecycle reasoning that doesn't fit inline in the README.

---

## The Core Pattern

```bash
SECRETENV_REGISTRY=aws-ssm:///secretenv/registry secretenv run -- ./deploy.sh
```

`SECRETENV_REGISTRY` accepts either a registry name (if a `config.toml` exists on the runner) or a direct URI (no config file needed). **For ephemeral CI runners, always use a direct URI.** For persistent agents, you can stage a `config.toml` once and reference it by name.

**You're not authenticating SecretEnv** — you're authenticating the backend CLI. Set up the backend CLI's service account credentials the same way you would if you were calling it directly. SecretEnv adds no auth layer.

---

## GitHub Actions

Ephemeral runners. Each workflow run starts a fresh container. Use OIDC federation for AWS and similar — no static credentials stored in GitHub.

The full inline example lives in the [CI/CD Integration](/ci-cd). Patterns covered there:

- AWS OIDC + `SECRETENV_REGISTRY` env-var pattern
- Org-level `SECRETENV_REGISTRY` variable for cross-repo consistency

### 1Password backend in GitHub Actions

```yaml
- name: Run with 1Password secrets
  env:
    OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
    SECRETENV_REGISTRY: 1password-work://secretenv/registry
  run: secretenv run -- ./deploy.sh
```

`OP_SERVICE_ACCOUNT_TOKEN` is the official 1Password mechanism for non-interactive environments. Service accounts are created in the 1Password admin console — scope them to specific vaults.

### Vault backend via `hashicorp/vault-action`

```yaml
- name: Authenticate to Vault
  uses: hashicorp/vault-action@v3
  with:
    url: https://vault.company.com
    method: jwt
    role: github-actions
    secrets: |
      secret/data/ci/runner-token token | VAULT_TOKEN

- name: Run with Vault secrets
  env:
    SECRETENV_REGISTRY: vault://secret/secretenv/registry
  run: secretenv run -- ./deploy.sh
```

The `vault-action` step exchanges GitHub's OIDC token for a short-lived `VAULT_TOKEN` that `secretenv` then inherits.

---

## Jenkins

Persistent agents — install the backend CLIs and `secretenv` once on the agent image. Set `SECRETENV_REGISTRY` as a global environment variable in **Manage Jenkins → System → Global properties**, scoped per environment if needed.

### Agent provisioning

```bash
# One-time on each Jenkins agent image
brew install secretenv awscli                            # macOS agents
# or:
curl -sfS https://secretenv.io/install.sh | sh           # Linux agents

# Validate
secretenv doctor --json | jq -r '.summary'
```

### Pipeline gate via doctor

```groovy
pipeline {
  agent any
  environment {
    SECRETENV_REGISTRY = 'aws-ssm:///secretenv/registry'
  }
  stages {
    stage('Pre-deploy health check') {
      steps {
        sh 'secretenv doctor --json'
      }
    }
    stage('Deploy') {
      steps {
        sh 'secretenv run -- ./deploy.sh'
      }
    }
  }
}
```

`secretenv doctor` exits non-zero on any backend-Not-Ok state, failing the build before deploy. Use `--json` to feed monitoring stacks if you have a centralized log aggregator.

### AWS auth on Jenkins

Two clean options:

- **EC2 instance role** — the agent assumes an IAM role; no static credentials needed.
- **Credentials Plugin** — store an `AWS Credentials` entry in Jenkins; reference via `withAWS(credentials: 'my-aws-creds') { ... }`.

Avoid static `AWS_ACCESS_KEY_ID` env vars in Jenkins — they're long-lived and a frequent leak source.

---

## GitLab CI

Both ephemeral runner and persistent agent patterns work. GitLab's native Vault integration (via JWT) pairs cleanly with `vault://...` registries.

```yaml
deploy:
  image: ubuntu:24.04
  before_script:
    - apt-get update && apt-get install -y curl jq
    - curl -sfS https://secretenv.io/install.sh | sh
    - curl -sfS https://aws-cli-install-url | sh   # or use a runner image with aws preinstalled
  script:
    - export VAULT_TOKEN=$(vault write -field=token auth/jwt/login role=ci-runner jwt=$CI_JOB_JWT_V2)
    - SECRETENV_REGISTRY="vault://secret/secretenv/registry" secretenv run -- ./deploy.sh
```

`$CI_JOB_JWT_V2` is GitLab's per-job JWT, exchanged for a short-lived Vault token at job start.

---

## BuildKite

Persistent agents. Install once on the agent image; gate via hooks.

```bash
# /etc/buildkite-agent/hooks/pre-command
#!/usr/bin/env bash
set -e
secretenv doctor --json >/dev/null   # fail fast if any backend is broken
export SECRETENV_REGISTRY="aws-ssm:///secretenv/registry"
```

Then in pipeline steps:

```yaml
steps:
  - command: "secretenv run -- ./deploy.sh"
    label: ":rocket: Deploy"
```

The pre-command hook runs `doctor` for every job — cheap (sub-2s) and pre-empts the "fails 30 minutes into deploy" failure mode.

---

## CircleCI

Ephemeral runners. CircleCI's Contexts + OIDC pattern matches GitHub's flow.

```yaml
version: 2.1
jobs:
  deploy:
    docker:
      - image: cimg/base:current
    steps:
      - checkout
      - run:
          name: Install SecretEnv
          command: curl -sfS https://secretenv.io/install.sh | sh
      - run:
          name: Configure AWS via OIDC
          command: |
            aws configure set web_identity_token_file "$CIRCLE_OIDC_TOKEN_FILE"
            aws configure set role_arn "arn:aws:iam::123456789012:role/circleci-role"
      - run:
          name: Deploy with secrets
          environment:
            SECRETENV_REGISTRY: aws-ssm:///secretenv/registry
          command: secretenv run -- ./deploy.sh

workflows:
  deploy-workflow:
    jobs:
      - deploy:
          context: aws-prod   # contexts hold long-lived config
```

---

## Platform Comparison

| Platform | Runner model | Auth pattern | Recommended |
|---|---|---|---|
| GitHub Actions | Ephemeral | OIDC federation | Set `SECRETENV_REGISTRY` at org or repo level |
| GitLab CI | Ephemeral / persistent | Native Vault JWT (`CI_JOB_JWT_V2`) or CI variables | Use Vault JWT for production deploys |
| Jenkins | Persistent | Agent IAM role / Credentials Plugin | Bake CLIs into agent images; use `doctor --json` as a pre-deploy gate |
| BuildKite | Persistent | Agent IAM role / pre-command hooks | Run `doctor` in pre-command hook |
| CircleCI | Ephemeral | Contexts + OIDC | Same shape as GitHub Actions |

---

## Pre-flight: `secretenv doctor` as a Pipeline Gate

Run `secretenv doctor --json` before any deploy step. It catches:

- Backend CLI not installed on the runner
- Backend not authenticated (expired tokens, wrong profile)
- Registry document unreachable (network, IAM, missing path)
- Manifest references an alias that doesn't exist in the registry

Exit code is non-zero on any not-`Ok` state. Average runtime: under 2 seconds for a 10-backend topology. Suitable as a per-job pre-step or a per-minute scheduled probe.

---

## See Also

- [CI/CD overview](/ci-cd) — headline GitHub Actions example
- [`secretenv doctor`](/reference/cli-reference-full#secretenv-doctor) — three-level health checks
- [Backends](/backends/) — per-backend auth patterns
- [Configuration reference](reference/configuration.md) — full schema
