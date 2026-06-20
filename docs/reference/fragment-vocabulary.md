# Fragment Vocabulary

SecretEnv URIs are shaped `<instance-name>://<path>[#<fragment>]`. The optional `#<fragment>` suffix carries per-request directives (JSON field extraction, version pinning, etc.). Each backend declares which directive keys it recognizes; the URI layer enforces a single canonical grammar.

## Canonical grammar

```
fragment   := directive ("," directive)*
directive  := key "=" value
key        := [a-z][a-z0-9-]*
value      := non-empty string not containing "," or "="
```

Short examples:

```
aws-secrets-prod:///db-creds#json-key=password
gcp-prod://my-secret#version=5
azure-prod://my-secret#version=12345678-abcd-1234-ef56-9876
```

## Rules

- **Every directive is `key=value`.** No shorthand; no flags-without-values.
- **Keys are lowercase kebab-case:** letter-led, then letters/digits/hyphens only. `json-key`, `version2`, `max-age` OK; `JsonKey`, `json_key`, `1version`, `json.key` fail.
- **Values are non-empty,** must not contain `,` or `=`. Spaces, dots, hyphens, most punctuation OK.
- **Separate directives with single comma.** No whitespace around comma; no trailing/leading commas.
- **Each key appears at most once.** Duplicates are hard errors.
- **Directive semantics are backend-local.** URI layer enforces grammar; each backend decides which keys it accepts.

## Directive Registry

Lists every directive key SecretEnv backends recognize. Unrecognized directives are hard errors.

| Backend | Directive | Meaning | Since |
|---|---|---|---|
| `aws-secrets` | `json-key` | Extract a top-level JSON field from the secret body. Value is the field name. | v0.2.1 |
| `gcp` | `version` | Pin a specific GCP Secret Manager version. Positive integer or `latest`. `latest` is equivalent to no fragment. | v0.3 |
| `azure` | `version` | Pin a specific Azure Key Vault secret version. 32-character lowercase hex string (server-generated) or `latest`. | v0.3 |
| `keeper` | `field` | Select a named Keeper record field. Case-insensitive, matches custom-field label first, then typed-field label, then typed-field type name. Without this directive the `password` field is returned. Note: the `keeper` backend parses this directive directly from the raw fragment rather than through the canonical grammar parser; the directive key still follows the `key=value` shape. | v0.8 |

## Error Reporting

All fragment-grammar errors quote the full URI verbatim for log grepping:

```
fragment '#password' on URI 'aws-secrets-prod:///db-creds#password' uses legacy
plain-string shorthand; rewrite as '#<directive>=<value>' (for example,
aws-secrets requires '#json-key=password'). See docs/fragment-vocabulary.md
```

## Migration from v0.2.0

v0.2.0 shipped plain-string shorthand (`#password` = extract `password` field). Rejected in v0.2.1+:

| v0.2.0 (removed) | v0.2.1+ (canonical) |
|---|---|
| `aws-secrets-prod:///db#password` | `aws-secrets-prod:///db#json-key=password` |
| `aws-secrets-prod:///db#host` | `aws-secrets-prod:///db#json-key=host` |

If you see `ShorthandRejected` in logs, rewrite using the table above.

## Why This Shape

Earlier drafts let each backend define its own grammar. One canonical URI-layer grammar with backend-local directive registry scales better: new backends reuse well-defined keys, old backends don't drift, and tooling validates fragments early.
