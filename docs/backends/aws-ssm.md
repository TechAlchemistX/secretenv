# AWS SSM Parameter Store

**Type:** `aws-ssm`  
**CLI required:** `aws` (AWS CLI v2)  
**URI scheme:** `<instance-name>:///path/to/parameter`

---

## Configuration

```toml
[backends.aws-ssm-dev]
type        = "aws-ssm"     # required
aws_profile = "dev"         # optional — omit to use ambient credentials
aws_region  = "us-east-1"  # required
```

### Fields

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Must be `"aws-ssm"` |
| `aws_profile` | No | Named profile from `~/.aws/config`. Omit to use ambient credentials (env vars, instance metadata, SSO default) |
| `aws_region` | Yes | AWS region where parameters live |

### Multiple Accounts

Create one named instance per account:

```toml
[backends.aws-ssm-platform]
type        = "aws-ssm"
aws_profile = "platform"
aws_region  = "us-east-2"

[backends.aws-ssm-staging]
type        = "aws-ssm"
aws_profile = "staging"
aws_region  = "us-east-1"

[backends.aws-ssm-prod]
type        = "aws-ssm"
aws_profile = "prod"
aws_region  = "us-east-1"
```

---

## URI Format

```
aws-ssm-dev:///myapp/dev/stripe_key
└─────────┘   └────────────────────┘
instance name  SSM parameter path (leading slash handled automatically)
```

Parameters must exist as `SecureString` type. `String` and `StringList` types are supported but not recommended for secrets.

---

## Authentication

secretenv delegates authentication entirely to the `aws` CLI. Any credential mechanism the CLI supports works automatically:

- Named profiles (`aws_profile` field)
- Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)
- IAM instance/task roles (EC2, ECS, Lambda)
- AWS SSO / IAM Identity Center
- `credential_process` custom providers
- Cross-account role assumption via `role_arn` in profile config

---

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
        "ssm:PutParameter"
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

`PutParameter` is only required for `secretenv registry set`. Read-only workflows need only `GetParameter` and `GetParameters`.

---

## doctor Output

```
aws-ssm-dev                                                    (aws-ssm)
  ✓ aws CLI v2.15.0
  ✓ authenticated  profile=dev  account=123456789012  region=us-east-1
```

```
aws-ssm-prod                                                   (aws-ssm)
  ✓ aws CLI v2.15.0
  ✗ not authenticated
      → run: aws sso login --profile prod
```
