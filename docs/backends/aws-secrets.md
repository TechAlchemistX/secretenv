# AWS Secrets Manager

**Type:** `aws-secrets`
**CLI required:** [`aws`](https://aws.amazon.com/cli/) (AWS CLI v2)
**URI scheme:** `<instance>://secret-name[#json-key=<field>]`
**Platform:** all (macOS, Linux, Windows)
**Tested:** `aws-cli/2.34.35` on macOS Darwin 25.4 (SecretEnv v0.13.0, 2026-05-07)

> SecretEnv injects secrets from any backend as environment variables. This page covers the `aws-secrets` backend. New here? See the [main README](../../README.md).

AWS Secrets Manager is AWS's native secrets store for cross-service replication and automatic rotation. Unlike Parameter Store (which stores values as-is), Secrets Manager offers structured secret support and fine-grained permission control. Pick Secrets Manager when you need multi-region replication, automatic rotation orchestration, or fine-grained RDS/database credential management. The `aws` CLI wraps the Secrets Manager API with full credential chain support.

## When to pick this

- **Multi-region replication:** Secrets Manager replicates across regions; Parameter Store is region-scoped
- **Automatic rotation:** Rotate database passwords and API credentials via Lambda orchestration
- **Fine-grained permissions:** IAM policy granularity per secret (not just per operation)
- **Team workflows:** Named profiles let multiple accounts/contexts live in one config

## Configuration

```toml
[backends.aws-secrets-prod]
type        = "aws-secrets"
aws_region  = "us-east-1"
aws_profile = "prod"         # optional — omit to use ambient credentials
```

### Fields

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Must be `"aws-secrets"` |
| `aws_region` | Yes | AWS region where secrets live |
| `aws_profile` | No | Named profile from `~/.aws/config`. Omit to use ambient credentials (env vars, instance metadata, SSO default) |
| `timeout_secs` | No | Per-instance fetch timeout override. Default: 30s. |

### Multiple Accounts

Create one named instance per account or environment:

```toml
[backends.aws-secrets-staging]
type        = "aws-secrets"
aws_region  = "us-east-1"
aws_profile = "staging"

[backends.aws-secrets-prod]
type        = "aws-secrets"
aws_region  = "us-east-1"
aws_profile = "prod"
```

## URI Format

```
aws-secrets-prod://myapp/prod/stripe_key
└─────────────────┘  └───────────────────┘
instance name       secret name
```

Secret names are passed verbatim to `aws secretsmanager get-secret-value --secret-id`. Both friendly names and ARNs are supported. The leading `/` is **not** part of the secret name — double-slash form `aws-secrets-prod://` omits it, while triple-slash form `aws-secrets-prod:///` strips any leading `/` from the URI path.

For secrets with JSON value (multiple key-value pairs), append the `#json-key` fragment directive:

```
aws-secrets-prod://myapp/prod/db_credentials#json-key=password
```

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
        "secretsmanager:GetSecretValue",
        "secretsmanager:PutSecretValue",
        "secretsmanager:DeleteSecret"
      ],
      "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:myapp/*"
    }
  ]
}
```

`PutSecretValue` and `DeleteSecret` are only required for `secretenv registry set` / `delete`. Read-only workflows need only `GetSecretValue`.

## doctor Output

Healthy state:

```
aws-secrets-prod                                            (aws-secrets)
  ✓ aws CLI v2.34.35
  ✓ authenticated  profile=prod  account=123456789012  arn=arn:aws:iam::123456789012:user/deploy  region=us-east-1
```

Not authenticated (invalid profile or credentials expired):

```
aws-secrets-prod                                            (aws-secrets)
  ✓ aws CLI v2.34.35
  ✗ not authenticated
      → run: aws configure --profile prod  OR  aws sso login --profile prod
```

## Fragment directives

`#json-key=<field>` extracts a single field from a JSON-shaped secret:

| Directive | Effect | Example |
|---|---|---|
| `#json-key=password` | Extract the `password` field as a string | `aws-secrets-prod://myapp/db#json-key=password` |
| (no fragment) | Return the secret value verbatim (string or whole JSON) | `aws-secrets-prod://myapp/db` |

Shorthand fragments (`#password` with no `=`) and unsupported directives (`#version=5`) are rejected at URI-parse time with a migration hint.

## History API support

Partial. `secretenv registry history <alias>` surfaces version number and creation timestamp via `aws secretsmanager list-secret-version-ids`. Actor name and change descriptions are not available via the CLI API.

## Limitations

- **Auto-create on first set:** `registry set` adds a new version to an existing secret. The secret itself must exist first (`aws secretsmanager create-secret`); this is a one-time setup per secret.
- **No nested JSON field extraction:** `#json-key` selects top-level fields only. Nested paths like `#json-key=db.password` are not supported.
- **No automatic rotation orchestration:** Secrets Manager supports rotation policies in the console; this backend rotates the version but does not invoke the rotation Lambda. Use the AWS console or CloudFormation for rotation setup.

## Examples

### Single dev instance

```toml
[backends.aws-secrets-dev]
type        = "aws-secrets"
aws_region  = "us-east-1"
aws_profile = "dev"

[registries.default]
sources = ["aws-secrets-dev://myapp/dev/registry"]
```

```bash
secretenv run -- npm start
```

### Multi-account with JSON extraction

```toml
[backends.aws-secrets-prod]
type        = "aws-secrets"
aws_region  = "us-east-1"
aws_profile = "prod"

[registries.prod]
sources = ["aws-secrets-prod://myapp/prod/registry"]
```

In the registry document, reference individual fields:

```json
{
  "db-host": "aws-secrets-prod://myapp/prod/db-creds#json-key=host",
  "db-password": "aws-secrets-prod://myapp/prod/db-creds#json-key=password"
}
```

### As registry source

Point directly at a registry-shaped secret:

```bash
secretenv run --registry aws-secrets-prod://myapp/prod/registry -- ./deploy.sh
```

## Troubleshooting

**"User is not authorized to perform: secretsmanager:GetSecretValue"**
Check IAM policy covers your secret ARN. `arn:aws:secretsmanager:us-east-1:123456789012:secret:myapp/*` must match your actual secret names. Run `secretenv doctor` to see which account is active.

**"ResourceNotFoundException"**
Verify the secret exists in the correct region. Use `aws secretsmanager describe-secret --secret-id <name> --region us-east-1` (with the right `--profile` if needed).

**"InvalidParameterException: The secret name ... is not valid"**
Secret names cannot start with `/`. Use `aws secretsmanager list-secrets --region us-east-1` to verify the correct name.

## See Also

- [`secretenv doctor`](../../README.md#operational-health-secretenv-doctor) — health checks for all backends
- [Alias registry concepts](../reference/registry.md) — how registry sources resolve aliases
- [Fragment vocabulary](../reference/fragment-vocabulary.md) — `#json-key` directive reference
- [AWS Systems Manager Parameter Store](aws-ssm.md) — alternative for simpler use cases
- [All backends](README.md) — pick a different backend
- [Main README](../../README.md) — overview + workflows
