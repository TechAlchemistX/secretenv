# AWS Secrets Manager

**Type:** `aws-secrets`  
**CLI required:** `aws` (AWS CLI v2)  
**URI scheme:** `<instance-name>://secret-name[#json-key=<field>]`

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

For secrets with JSON value (multiple key-value pairs), append the `json-key` fragment directive:

```
aws-secrets-prod://myapp/prod/db_credentials#json-key=password
```

`json-key` is the only fragment directive the aws-secrets backend recognizes. Any other directive errors with the full URI and a list of recognized directives. The legacy v0.2.0 shorthand (`#password` with no `=`) is rejected with a migration hint — see [fragment-vocabulary.md](../fragment-vocabulary.md) for the full grammar.

Supported fragment shapes:

| URI | Result |
|---|---|
| `aws-secrets-prod://myapp/db-creds` | Raw secret body (string or whole JSON blob). |
| `aws-secrets-prod://myapp/db-creds#json-key=password` | Extract the `password` field from a JSON body. |
| `aws-secrets-prod://myapp/db-creds#password` | **Rejected** — legacy shorthand; rewrite as above. |
| `aws-secrets-prod://myapp/db-creds#version=5` | **Rejected** — `version` is not an aws-secrets directive. |

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
