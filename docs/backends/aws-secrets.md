# AWS Secrets Manager

**Type:** `aws-secrets`  
**CLI required:** `aws` (AWS CLI v2)  
**URI scheme:** `<instance-name>://secret-name`

---

## Configuration

```toml
[backends.aws-secrets-prod]
type        = "aws-secrets"
aws_profile = "prod"          # optional
aws_region  = "us-east-1"    # required
```

### Fields

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Must be `"aws-secrets"` |
| `aws_profile` | No | Named profile from `~/.aws/config` |
| `aws_region` | Yes | AWS region where secrets live |

---

## URI Format

```
aws-secrets-prod://myapp/prod/stripe_key
└───────────────┘  └─────────────────────┘
instance name       secret name
```

For secrets with JSON value (multiple key-value pairs), append the JSON key:

```
aws-secrets-prod://myapp/prod/db_credentials#password
```

---

## Authentication

Identical to the `aws-ssm` backend. All AWS credential mechanisms are supported — named profiles, environment variables, IAM roles, SSO, cross-account assumption.

---

## IAM Permissions

```json
{
  "Effect": "Allow",
  "Action": [
    "secretsmanager:GetSecretValue",
    "secretsmanager:PutSecretValue"
  ],
  "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:myapp/*"
}
```
