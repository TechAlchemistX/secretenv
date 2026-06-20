# CI/CD Integration

SecretEnv works in CI via the `SECRETENV_REGISTRY` environment variable. No config file needed. Set it once at org or repo level and every `secretenv run` resolves from the right registry.

The [README's CI/CD section](../../README.md#cicd) has the headline GitHub Actions example; this page is the per-platform deep dive.

---

## Core Pattern

```bash
SECRETENV_REGISTRY=aws-ssm:///secretenv/registry secretenv run -- ./deploy.sh
```

`SECRETENV_REGISTRY` accepts a registry name (if `config.toml` exists) or a direct URI (no config needed). **For ephemeral runners, use a direct URI.** Persistent agents can stage `config.toml` once and reference it by name.

**You authenticate the backend CLI, not SecretEnv.** Set up the backend service account the same way you'd use it directly. SecretEnv adds no auth layer.

---

## GitHub Actions

Ephemeral runners use OIDC federation (no static credentials in GitHub).

The full GitHub Actions example is in the [README](../../README.md#cicd). Key patterns:
- AWS OIDC + `SECRETENV_REGISTRY`
- Org-level `SECRETENV_REGISTRY` for consistency

### 1Password in GitHub Actions

```yaml
- name: Run with 1Password secrets
  env:
    OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
    SECRETENV_REGISTRY: 1password-work://secretenv/registry
  run: secretenv run -- ./deploy.sh
```

Create service accounts in the 1Password admin console and scope them to specific vaults.

### Vault via `hashicorp/vault-action`

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

`vault-action` exchanges GitHub's OIDC token for a short-lived `VAULT_TOKEN` that `secretenv` inherits.

---

## Jenkins

Persistent agents. Install backend CLIs and `secretenv` once on the agent image. Set `SECRETENV_REGISTRY` in **Manage Jenkins → System → Global properties**.

### Agent provisioning

```bash
# One-time on each Jenkins agent image
brew install secretenv awscli                            # macOS agents
# or:
curl -sfS https://secretenv.io/install.sh | sh           # Linux agents

# Validate
secretenv doctor --json | jq -r '.summary'
```

### Pipeline with health gate

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

`secretenv doctor` exits non-zero on any backend not-Ok state, failing the build before deploy. Use `--json` for monitoring integration.

### AWS auth on Jenkins

Use **EC2 instance role** (agent assumes IAM role) or **Credentials Plugin** (`withAWS(credentials: 'my-aws-creds') { ... }`). Avoid static `AWS_ACCESS_KEY_ID`. They leak frequently.

---

## GitLab CI

Both ephemeral and persistent agents work. GitLab's Vault JWT integration pairs with `vault://...` registries.

```yaml
deploy:
  image: ubuntu:24.04
  before_script:
    - apt-get update && apt-get install -y curl jq
    - curl -sfS https://secretenv.io/install.sh | sh
    - curl -sfS https://aws-cli-install-url | sh   # or use a prebuilt runner image
  script:
    - export VAULT_TOKEN=$(vault write -field=token auth/jwt/login role=ci-runner jwt=$CI_JOB_JWT_V2)
    - SECRETENV_REGISTRY="vault://secret/secretenv/registry" secretenv run -- ./deploy.sh
```

`$CI_JOB_JWT_V2` is exchanged for a short-lived Vault token at job start.

---

## BuildKite

Persistent agents. Install once, gate via hooks.

```bash
# /etc/buildkite-agent/hooks/pre-command
#!/usr/bin/env bash
set -e
secretenv doctor --json >/dev/null
export SECRETENV_REGISTRY="aws-ssm:///secretenv/registry"
```

Pipeline steps:

```yaml
steps:
  - command: "secretenv run -- ./deploy.sh"
    label: ":rocket: Deploy"
```

The pre-command hook runs `doctor` for every job, cheap (sub-2s) and catches failures before deploy.

---

## CircleCI

Ephemeral runners. Contexts + OIDC pattern similar to GitHub Actions.

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
          context: aws-prod
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

## Pipeline Gate: `secretenv doctor`

Run `secretenv doctor --json` before any deploy step. It catches:
- Backend CLI missing
- Backend not authenticated
- Registry unreachable
- Missing aliases

Exit code is non-zero on any not-Ok state. Avg runtime: under 2s for 10 backends. Use as a per-job pre-step or scheduled probe.

---

## See Also

- [CI/CD overview (README)](../../README.md#cicd)
- [`secretenv doctor`](/reference/cli-reference-full#secretenv-doctor)
- [Backends](/backends/)
- [Configuration reference](../reference/configuration.md)
