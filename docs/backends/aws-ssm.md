# AWS SSM Parameter Store

**Type:** `aws-ssm`
**CLI required:** [`aws`](https://aws.amazon.com/cli/) (AWS CLI v2)
**URI scheme:** `<instance-name>:///path/to/parameter`
**Platform:** all (macOS, Linux, Windows)
**Tested:** `aws-cli/2.34.35` on macOS Darwin 25.4 (SecretEnv v0.13.0, 2026-05-07)

> SecretEnv injects secrets from any backend as environment variables. This page covers the `aws-ssm` backend. New here? See the [main README](../../README.md).

AWS Systems Manager (SSM) Parameter Store is AWS's native secrets store — built-in, region-scoped, and integrated with KMS for SecureString encryption. Pick SSM when you're already on AWS and want the simplest path: no new service account, no new CLI, no API tokens. The `aws` CLI wraps the Parameter Store API and resolves credentials from your ambient AWS configuration (profiles, IAM roles, SSO, environment variables).

## When to pick this

- **You're on AWS:** native integration, no new authentication layer
- **Short-term secrets:** Parameter Store suits dev/test values well; consider AWS Secrets Manager if you need automatic rotation or cross-service replication
- **Team workflows:** named profiles let multiple accounts/contexts live in one config
- **Air-gapped automation:** IAM roles on EC2/ECS/Lambda require zero external secrets

## Configuration

```toml
[backends.aws-ssm-dev]
type        = "aws-ssm"
aws_region  = "us-east-1"
aws_profile = "dev"         # optional — omit to use ambient credentials
```

### Fields

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Must be `"aws-ssm"` |
| `aws_region` | Yes | AWS region where parameters live |
| `aws_profile` | No | Named profile from `~/.aws/config`. Omit to use ambient credentials (env vars, instance metadata, SSO default) |
| `timeout_secs` | No | Per-instance fetch timeout override. Default: 30s. |

### Multiple Accounts

Create one named instance per account or environment:

```toml
[backends.aws-ssm-dev]
type        = "aws-ssm"
aws_region  = "us-east-1"
aws_profile = "dev"

[backends.aws-ssm-staging]
type        = "aws-ssm"
aws_region  = "us-east-1"
aws_profile = "staging"

[backends.aws-ssm-prod]
type        = "aws-ssm"
aws_region  = "us-east-1"
aws_profile = "prod"
```

## URI Format

```
aws-ssm-dev:///myapp/prod/stripe_key
└──────────┘   └──────────────────┘
instance name  SSM parameter path
```

Parameter names must exist as `SecureString` type. `String` and `StringList` types are supported but **not recommended for secrets** — they lack envelope encryption. The leading `/` is automatic; both `aws-ssm-dev:///myapp/key` and `aws-ssm-dev://myapp/key` resolve to the parameter `/myapp/key`.

**Verify your setup with:** `secretenv doctor` — green output means you're ready to run `secretenv run -- <your command>`.

## Authentication

SecretEnv delegates authentication entirely to the `aws` CLI. Any credential mechanism the CLI supports works automatically:

- Named profiles (via `aws_profile` field)
- Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)
- IAM instance/task roles (EC2, ECS, Lambda, AppRunner)
- AWS SSO / IAM Identity Center
- `credential_process` custom providers
- Cross-account role assumption via `role_arn` in profile config

## IAM Permissions

Minimum permissions required:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParameterHistory"
      ],
      "Resource": "arn:aws:ssm:us-east-1:123456789012:parameter/secretenv/*"
    },
    {
      "Effect": "Allow",
      "Action": "kms:Decrypt",
      "Resource": "arn:aws:kms:us-east-1:123456789012:key/your-kms-key-id"
    }
  ]
}
```

`PutParameter` is only required for `secretenv registry set`. Read-only workflows need only `GetParameter`, `GetParameters`, and `GetParameterHistory`.

## doctor Output

Healthy state:

```
aws-ssm-prod                                                    (aws-ssm)
  ✓ aws CLI v2.34.35
  ✓ authenticated  profile=prod  account=123456789012  arn=arn:aws:iam::123456789012:user/deploy  region=us-east-1
```

Not authenticated (invalid profile or credentials expired):

```
aws-ssm-prod                                                    (aws-ssm)
  ✓ aws CLI v2.34.35
  ✗ not authenticated
      → run: aws sso login --profile prod  OR  aws configure --profile prod
```

## Fragment directives

No fragment directives. Any `#...` fragment is rejected at URI parse time.

## History API support

Full support via `aws ssm get-parameter-history`. `secretenv registry history <alias>` surfaces all historical versions with timestamps, actor (AWS principal), and descriptions. Entries appear most-recent-first.

## Limitations

- **SecureString recommended:** `String` type parameters work but don't encrypt at rest. Always use `SecureString` for credentials.
- **No per-secret JSON envelope:** SSM stores the value as-is. If you need to rotate one field of a JSON object, rotate the entire parameter.
- **No automatic rotation:** SSM supports rotation policies in AWS Secrets Manager, but Parameter Store doesn't rotate automatically. If you need orchestrated rotation, use Secrets Manager or Vault.

## Examples

### Single dev instance

```toml
[backends.aws-ssm-dev]
type        = "aws-ssm"
aws_region  = "us-east-1"
aws_profile = "dev"

[registries.default]
sources = ["aws-ssm-dev:///myapp/dev/registry"]
```

```bash
# Local development — SSM parameters injected as env vars
secretenv run -- npm start
```

### Multi-account setup

```toml
[backends.aws-ssm-staging]
type        = "aws-ssm"
aws_region  = "us-east-1"
aws_profile = "staging"

[backends.aws-ssm-prod]
type        = "aws-ssm"
aws_region  = "us-east-1"
aws_profile = "prod"

[registries.staging]
sources = ["aws-ssm-staging:///myapp/staging/registry"]

[registries.prod]
sources = ["aws-ssm-prod:///myapp/prod/registry"]
```

Deploy with: `secretenv run --registry prod -- ./deploy.sh`

### As registry source

Parameter `/myapp/prod/registry` holds:

```json
{
  "stripe-key": "aws-ssm-prod:///myapp/prod/stripe_key",
  "db-url": "vault-prod:///secret/db",
  "api-token": "aws-ssm-prod:///myapp/prod/api_token"
}
```

This lets you alias secrets across backends:

```bash
secretenv run --registry aws-ssm-prod:///myapp/prod/registry -- npm start
```

## Troubleshooting

**"User is not authorized to perform: ssm:GetParameter"**
Check IAM policy covers your parameter path. `arn:aws:ssm:us-east-1:123456789012:parameter/secretenv/*` must match your actual parameter names. Run `secretenv doctor` to see which account is active.

**"ParameterNotFound"**
Verify the parameter exists in the correct region. Use `aws ssm get-parameter --name /your/param --region us-east-1` (with the right `--profile` if needed).

**"The parameter with name ... does not exist or you aren't allowed to access it"**
Same cause as above; SSM conflates "not found" and "access denied" for security. `secretenv doctor` shows the active account and region — double-check both match your parameter location.

## See Also

- [`secretenv doctor`](../../README.md#operational-health-secretenv-doctor) — health checks for all backends
- [Alias registry concepts](../reference/registry.md) — how registry sources resolve aliases
- [Fragment vocabulary](../reference/fragment-vocabulary.md) — other backends' `#version`, `#json-key` directives
- [AWS Secrets Manager](aws-secrets.md) — alternative: automatic rotation, cross-region replication
- [All backends](README.md) — pick a different backend
- [Main README](../../README.md) — overview + workflows
