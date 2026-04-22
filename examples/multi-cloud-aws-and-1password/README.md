# Multi-cloud: AWS SSM + 1Password

Real-team pattern where infrastructure secrets live in AWS SSM
(managed by ops, per-environment paths) and human-managed secrets
(third-party API tokens, shared credentials) live in 1Password
(managed by engineering). The registry lives in 1Password so the whole
team can read it without needing IAM access to the SSM registry path.

## When to use this

- Mid-migration teams: came from 1Password, moving infra stuff into
  SSM/Secrets Manager, but don't want to churn.
- Ops + dev split: separate IAM posture for "the database URL" vs "the
  Figma plugin API token".
- Multiple AWS accounts (platform + dev + prod) with one 1Password
  account for humans.

## What's in this directory

- `config.toml` — three AWS SSM instances (platform/dev/prod) + two
  1Password instances (work/personal). Real orgs usually stop at 2-3
  backends total — this example shows named instances so you see the
  plumbing.
- `secretenv.toml` — project manifest with infra + human-managed
  aliases side by side.

## Running it

```sh
# Prereqs:
aws sso login --profile platform      # or whatever your auth is
op signin --account company.1password.com
secretenv --config examples/multi-cloud-aws-and-1password/config.toml doctor

# Run:
cd examples/multi-cloud-aws-and-1password
secretenv run -- ./app
```

## Registry layout assumed

Registry document stored in 1Password at
`1password-work://Engineering/SecretEnv Registry/notesPlain`:

```toml
# infra — owned by platform team, lives in SSM
database-url       = "aws-ssm-prod:///myapp/prod/database-url"
redis-url          = "aws-ssm-prod:///myapp/prod/redis-url"

# third-party APIs — owned by engineering, lives in 1Password
stripe-key         = "1password-work://Engineering/Stripe/key"
datadog-api-key    = "1password-work://Engineering/Datadog/api-key"
figma-plugin-token = "1password-work://Engineering/Figma/plugin-token"
```

Notice the alias names are identical across environments — the registry
routing picks the right backend per env.
