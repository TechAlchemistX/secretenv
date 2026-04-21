# CI/CD Integration

secretenv works in CI via the `SECRETENV_REGISTRY` environment variable. No config file is needed on the runner — set the variable once at the org or repo level and every `secretenv run` in every pipeline resolves from the right registry.

---

## The Core Pattern

```bash
SECRETENV_REGISTRY=aws-ssm:///secretenv/registry secretenv run -- ./deploy.sh
```

`SECRETENV_REGISTRY` accepts either a registry name (if a `config.toml` exists on the runner) or a direct URI (no config file needed). For ephemeral CI runners, always use a direct URI.

---

## GitHub Actions

GitHub Actions runners are ephemeral. Each workflow run starts a fresh container. Use OIDC federation for AWS — no static credentials stored in GitHub.

### AWS SSM Backend

```yaml
name: Deploy

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write   # required for OIDC
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials (OIDC)
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/github-actions-deploy
          aws-region: us-east-1

      - name: Install secretenv
        run: curl -sfS https://secretenv.io/install.sh | sh

      - name: Deploy
        env:
          SECRETENV_REGISTRY: aws-ssm:///secretenv/registry
        run: secretenv run -- ./scripts/deploy.sh
```

### 1Password Backend

For 1Password in CI, use a service account token. This is 1Password's official CI mechanism.

```yaml
      - name: Configure 1Password
        env:
          OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
        run: |
          curl -sfS https://cache.agilebits.com/dist/1P/op2/pkg/v2.24.0/op_linux_amd64_v2.24.0.zip -o op.zip
          unzip -d /usr/local/bin op.zip op
          chmod +x /usr/local/bin/op

      - name: Deploy with secrets
        env:
          SECRETENV_REGISTRY: aws-ssm:///secretenv/registry
          OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
        run: secretenv run -- ./scripts/deploy.sh
```

### HashiCorp Vault Backend

```yaml
      - name: Import Vault secrets
        uses: hashicorp/vault-action@v3
        with:
          url: https://vault.company.com
          method: jwt
          role: github-actions
          # vault-action sets VAULT_TOKEN in the environment

      - name: Deploy with secrets
        env:
          SECRETENV_REGISTRY: vault:///secret/secretenv/registry
          VAULT_ADDR: https://vault.company.com
        run: secretenv run -- ./scripts/deploy.sh
```

### Org-Level Registry Variable

Set `SECRETENV_REGISTRY` as an organization-level Actions variable (not a secret — registry URIs are not sensitive) so every repo inherits it automatically:

```
GitHub Org Settings → Secrets and variables → Actions → Variables
Name:  SECRETENV_REGISTRY
Value: aws-ssm:///secretenv/registry
```

Then in any workflow:

```yaml
      - name: Run with secrets
        run: secretenv run -- ./deploy.sh
        # SECRETENV_REGISTRY inherited from org-level variable
```

---

## Jenkins

Jenkins agents are persistent. Configure once per agent type, inherit across all pipelines.

### Agent Setup

Install backend CLIs and secretenv on the agent image or via agent provisioning:

```bash
# Install secretenv
curl -sfS https://secretenv.io/install.sh | sh

# Install backend CLIs (examples)
apt-get install -y awscli
# op CLI: https://developer.1password.com/docs/cli/get-started/
# vault CLI: https://developer.hashicorp.com/vault/install
```

### AWS Authentication

For EC2-based Jenkins agents, attach an IAM instance profile. The `aws` CLI detects instance metadata credentials automatically — no profile configuration needed.

For non-EC2 agents, inject AWS credentials via the Jenkins Credentials Plugin:

```groovy
withCredentials([[
  $class: 'AmazonWebServicesCredentialsBinding',
  credentialsId: 'aws-secretenv-creds',
  accessKeyVariable: 'AWS_ACCESS_KEY_ID',
  secretKeyVariable: 'AWS_SECRET_ACCESS_KEY'
]]) {
  sh 'secretenv run -- ./deploy.sh'
}
```

### Global Environment Variable

Set `SECRETENV_REGISTRY` in Manage Jenkins → Configure System → Global properties → Environment variables:

```
SECRETENV_REGISTRY = aws-ssm:///secretenv/registry
```

### Jenkinsfile Example

```groovy
pipeline {
  agent any

  environment {
    SECRETENV_REGISTRY = 'aws-ssm:///secretenv/registry'
  }

  stages {
    stage('Deploy') {
      steps {
        sh 'secretenv doctor'
        sh 'secretenv run -- ./scripts/deploy.sh'
      }
    }
  }
}
```

---

## GitLab CI

### Docker Runner (Ephemeral)

```yaml
deploy:
  image: ubuntu:22.04
  before_script:
    - apt-get update && apt-get install -y curl awscli
    - curl -sfS https://secretenv.io/install.sh | sh

  script:
    - secretenv run -- ./scripts/deploy.sh

  variables:
    SECRETENV_REGISTRY: aws-ssm:///secretenv/registry
    AWS_DEFAULT_REGION: us-east-1
    # AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY from GitLab CI/CD variables
```

### HashiCorp Vault (GitLab Native Integration)

GitLab CI has native Vault JWT integration. secretenv works cleanly with it:

```yaml
deploy:
  id_tokens:
    VAULT_ID_TOKEN:
      aud: https://vault.company.com

  secrets:
    # GitLab fetches VAULT_TOKEN automatically via JWT
    VAULT_TOKEN:
      vault: auth/jwt/login

  script:
    - secretenv run -- ./scripts/deploy.sh

  variables:
    SECRETENV_REGISTRY: vault:///secret/secretenv/registry
    VAULT_ADDR: https://vault.company.com
```

---

## Key Differences Across Platforms

| | GitHub Actions | Jenkins | GitLab CI |
|---|---|---|---|
| Runner lifecycle | Ephemeral | Persistent | Ephemeral (Docker) or Persistent (shell) |
| AWS auth recommendation | OIDC via `aws-actions/configure-aws-credentials` | IAM instance profile or Credentials Plugin | CI/CD variables or OIDC |
| Vault auth recommendation | `hashicorp/vault-action` | Credentials Plugin | Native JWT integration |
| 1Password auth | `OP_SERVICE_ACCOUNT_TOKEN` env var | `OP_SERVICE_ACCOUNT_TOKEN` in Credentials Plugin | `OP_SERVICE_ACCOUNT_TOKEN` in CI/CD variables |
| secretenv config file needed | No — use `SECRETENV_REGISTRY` | Optional — can use global env var | No — use `SECRETENV_REGISTRY` |

---

## Pre-Flight Check

Add `secretenv doctor` as a pipeline step before any secret-dependent work. It surfaces auth issues before they cause confusing failures mid-deploy:

```yaml
      - name: Validate secretenv setup
        run: secretenv doctor --json | jq '.summary'
        # fails fast if any required backend is unauthenticated
```

---

## Troubleshooting CI

**`error: no registry configured`**
`SECRETENV_REGISTRY` is not set. Set it as a CI variable at the org or repo level.

**`AccessDeniedException` from AWS**
The IAM role or credentials in use don't have permission to read from the SSM path used as the registry, or from the paths the aliases point to. Check IAM policies for the CI role.

**`op: command not found`**
The `op` CLI is not installed on the runner. Add it to the runner's base image or install it in `before_script`.

**`error: alias 'X' not found in registry`**
The alias exists in a registry that requires a different backend instance than what's available in CI. Verify the registry URI and that the CI role has read access to it.
