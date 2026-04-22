# Single-backend: AWS SSM Parameter Store

Typical AWS-native team layout: both the alias registry and every
secret live in AWS SSM Parameter Store. One AWS account, one region,
one set of IAM permissions — no cross-vendor auth juggling.

## When to use this

- All-in on AWS and happy to stay there.
- Per-environment SSM paths (`/myapp/prod/`, `/myapp/staging/`) are
  already your convention.
- SSM's free tier + parameter-history audit trail fits your needs.

## What's in this directory

- `config.toml` — one `aws-ssm` backend instance (`aws-ssm-main`),
  configured with an AWS profile and region.
- `secretenv.toml` — project manifest referencing three aliases.

## Running it

```sh
# Prerequisites: aws CLI installed + authenticated against the target account.
aws sso login --profile my-team          # or whatever your auth is
aws configure list --profile my-team     # verify identity

# Verify secretenv sees it:
secretenv --config examples/single-backend-aws-ssm/config.toml doctor

# Run a command with secrets injected:
cd examples/single-backend-aws-ssm
secretenv run -- npm start
```

## Registry layout assumed

The registry document at `aws-ssm-main:///secretenv/registry` is a
plain SSM parameter whose value is TOML:

```toml
stripe-key      = "aws-ssm-main:///myapp/prod/stripe-key"
database-url    = "aws-ssm-main:///myapp/prod/database-url"
datadog-api-key = "aws-ssm-main:///myapp/prod/datadog-api-key"
```

Manage it with `secretenv registry set/unset/list` rather than editing
the SSM parameter directly.
