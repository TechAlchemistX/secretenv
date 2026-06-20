# Multi-cloud: AWS SSM + 1Password

Real-team pattern. Infra secrets in AWS SSM (ops-managed), human secrets in 1Password (eng-managed). Registry in 1Password so the team reads it without SSM IAM access.

## When to use

- Mid-migration from 1Password to SSM
- Ops/dev split (separate IAM for infra vs human secrets)
- Multiple AWS accounts with one 1Password account

## Files

- `config.toml`: three AWS SSM instances (platform/dev/prod) + two 1Password instances (work/personal). Shows the plumbing; real orgs use 2-3 backends total.
- `secretenv.toml`: project manifest with infra + human-managed aliases

## Running

```sh
# Prereqs:
aws sso login --profile platform
op signin --account company.1password.com
secretenv --config examples/multi-cloud-aws-and-1password/config.toml doctor

# Run:
cd examples/multi-cloud-aws-and-1password
secretenv run -- ./app
```

## Registry layout

Registry in 1Password at `1password-work://Engineering/SecretEnv Registry/notesPlain`:

```toml
# infra, owned by platform team, lives in SSM
database-url       = "aws-ssm-prod:///myapp/prod/database-url"
redis-url          = "aws-ssm-prod:///myapp/prod/redis-url"

# third-party APIs, owned by engineering, lives in 1Password
stripe-key         = "1password-work://Engineering/Stripe/key"
datadog-api-key    = "1password-work://Engineering/Datadog/api-key"
figma-plugin-token = "1password-work://Engineering/Figma/plugin-token"
```

Alias names are identical across environments; registry routing picks the right backend per env.
