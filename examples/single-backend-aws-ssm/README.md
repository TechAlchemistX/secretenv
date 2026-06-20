# Single-backend: AWS SSM Parameter Store

Typical AWS-native setup. Registry and secrets in SSM. One account, one region, one IAM posture.

## When to use

- All-in on AWS
- Per-environment paths (`/myapp/prod/`, `/myapp/staging/`) already your pattern
- SSM free tier + parameter history fits your audit needs

## Files

- `config.toml`: `aws-ssm` backend (`aws-ssm-main`) with profile and region
- `secretenv.toml`: project manifest with three aliases

## Running

```sh
# Prerequisites: aws CLI + account auth
aws sso login --profile my-team
aws configure list --profile my-team

# Verify secretenv:
secretenv --config examples/single-backend-aws-ssm/config.toml doctor

# Run with secrets:
cd examples/single-backend-aws-ssm
secretenv run -- npm start
```

## Registry layout

Registry at `aws-ssm-main:///secretenv/registry` is a plain SSM parameter with TOML value:

```toml
stripe-key      = "aws-ssm-main:///myapp/prod/stripe-key"
database-url    = "aws-ssm-main:///myapp/prod/database-url"
datadog-api-key = "aws-ssm-main:///myapp/prod/datadog-api-key"
```

Use `secretenv registry set/unset/list` to manage it, not direct SSM edits.
