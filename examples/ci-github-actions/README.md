# CI/CD: GitHub Actions

Reference workflow. Uses OIDC-assumed AWS credentials (no long-lived secrets in GitHub) and `SECRETENV_REGISTRY` for the registry (no `config.toml` on runner).

## When to use

- Deploy jobs on ephemeral GitHub runners
- Any pipeline calling commands with cloud secrets (tests, migrations, smoke tests)
- Stop copy-pasting `with: env:` blocks

## Files

- `deploy.yml`: workflow template; copy to `.github/workflows/deploy.yml`
- `secretenv.toml`: matching project manifest

## Key workflow lines

1. `aws-actions/configure-aws-credentials@v4`: assumes deploy role via OIDC
2. `curl -sfS https://secretenv.io/install.sh | sh`: installs binary
3. `SECRETENV_REGISTRY: aws-ssm:///secretenv/registry`: registry location (no `config.toml` needed)
4. `secretenv run -- ./deploy.sh`: injects secrets as env vars from resolved aliases

## Why not GitHub `secrets.STRIPE_KEY`?

GitHub secrets work. SecretEnv shines when:
- Same values used locally and in CI (one source of truth)
- Multiple deploy jobs sharing 8 secrets (no `env:` copy-paste)
- Rotation in AWS/1Password (GitHub secrets don't update)

## IAM role permissions

`github-actions-deploy` needs:
- `ssm:GetParameter` / `ssm:GetParameters` on `arn:aws:ssm:*:*:parameter/secretenv/*` + prod alias paths
- Whatever your deploy script needs (ECS, S3, etc.)

No SecretEnv-specific IAM: just "can this role read the parameters the aliases point to?"
