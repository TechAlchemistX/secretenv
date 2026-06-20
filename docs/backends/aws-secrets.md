# AWS Secrets Manager

- **Type:** `aws-secrets`
- **CLI required:** [`aws`](https://aws.amazon.com/cli/)
- **CLI version:** AWS CLI v2
- **URI scheme:** `<instance>://secret-name[#json-key=<field>]`
- **Platform:** all (macOS, Linux, Windows)
- **Tested:** `aws-cli/2.34.35` on macOS Darwin 25.4 (SecretEnv v0.19.0)

> SecretEnv injects secrets as environment variables. This page covers the `aws-secrets` backend. New here? See the [overview](/).

AWS Secrets Manager is AWS's secrets store for replication and rotation. Unlike Parameter Store, it offers structured secrets and fine-grained permissions. Pick for multi-region replication, auto-rotation orchestration, or RDS/database credential management.

## When to pick this

- **Multi-region replication**, unlike Parameter Store
- **Automatic rotation**, Lambda-orchestrated rotation for passwords and API credentials
- **Fine-grained IAM**, per-secret policies, not just per-operation
- **Team workflows**, named profiles for multiple accounts

## Configuration

```toml
[backends.aws-secrets-prod]
type        = "aws-secrets"
aws_region  = "us-east-1"
aws_profile = "prod"         # optional, omit to use ambient credentials
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

Secret names passed verbatim to `aws secretsmanager get-secret-value --secret-id`. Both friendly names and ARNs supported. Leading `/` omitted automatically.

For JSON secrets, append `#json-key=<field>`:

```
aws-secrets-prod://myapp/prod/db_credentials#json-key=password
```

**Verify:** `secretenv doctor`. Green output means ready to run.

## Authentication

Delegates entirely to the `aws` CLI. All standard credential mechanisms work:

- Named profiles (via `aws_profile` field)
- Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)
- IAM instance/task roles (EC2, ECS, Lambda, AppRunner)
- AWS SSO / IAM Identity Center
- `credential_process` custom providers
- Cross-account role assumption via `role_arn` in profile

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

| Directive | Effect | Example |
|---|---|---|
| `#json-key=password` | Extract `password` field from JSON | `aws-secrets-prod://myapp/db#json-key=password` |
| (no fragment) | Return value verbatim (string or JSON) | `aws-secrets-prod://myapp/db` |

Shorthand fragments (`#password`) and invalid directives (`#version=5`) rejected at parse time with migration hint.

## History API support

Not implemented. AWS Secrets Manager exposes version IDs via `aws secretsmanager list-secret-version-ids`, but this backend does not yet use that. Check the AWS Console or call the CLI directly.

## Limitations

- **No auto-create.** Secret must exist first (`aws secretsmanager create-secret`); `registry set` adds new versions only
- **No nested JSON extraction.** `#json-key` selects top-level fields only; nested paths like `db.password` not supported
- **No rotation orchestration.** `registry set` adds versions; rotation Lambda invocation via AWS Console/CloudFormation

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

- [`secretenv doctor`](/reference/cli-reference-full#secretenv-doctor), health checks for all backends
- [Alias registry concepts](../reference/registry.md), how registry sources resolve aliases
- [Fragment vocabulary](../reference/fragment-vocabulary.md), `#json-key` directive reference
- [AWS Systems Manager Parameter Store](aws-ssm.md), alternative for simpler use cases
- [All backends](README.md), pick a different backend
- [Overview](/), overview + workflows
