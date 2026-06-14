# Fragment Vocabulary

SecretEnv URIs are shaped `<instance-name>://<path>[#<fragment>]`. The optional `#<fragment>` suffix carries per-request directives — which JSON field to extract, which version to pin, and so on. Each backend declares the directive keys it understands; the URI layer enforces a single canonical grammar everyone agrees on.

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

- **Every directive is `key=value`.** No plain-string shorthand; no flags-without-values.
- **Keys are lowercase kebab-case** — letter-led, then letters/digits/hyphens. `json-key`, `version2`, and `max-age` all parse; `JsonKey`, `json_key`, `1version`, and `json.key` do not.
- **Values are non-empty** and must not contain `,` or `=`. Spaces, dots, hyphens, and most punctuation are fine.
- **Separate multiple directives with a single comma.** No whitespace around the comma; no trailing or leading commas.
- **Each key appears at most once.** A duplicate key is a hard error (no implicit merging).
- **Directive semantics are backend-local.** The URI layer enforces the grammar; each backend decides which keys it accepts and what their values mean. A key recognized by one backend is not automatically recognized by another.

## Directive registry

The registry lists every directive key SecretEnv backends recognize today. An unrecognized directive on a backend is a hard error that lists what is recognized.

| Backend | Directive | Meaning | Since |
|---|---|---|---|
| `aws-secrets` | `json-key` | Extract a top-level JSON field from the secret body. Value is the field name. | v0.2.1 |
| `gcp` | `version` | Pin a specific GCP Secret Manager version. Positive integer or `latest`. `latest` is equivalent to no fragment. | v0.3 |
| `azure` | `version` | Pin a specific Azure Key Vault secret version. 32-character lowercase hex string (server-generated) or `latest`. | v0.3 |
| `keeper` | `field` | Select a named Keeper record field. Case-insensitive — matches custom-field label first, then typed-field label, then typed-field type name. Without this directive the `password` field is returned. Note: the `keeper` backend parses this directive directly from the raw fragment rather than through the canonical grammar parser; the directive key still follows the `key=value` shape. | v0.8 |

## Error reporting

Every fragment-grammar error quotes the full URI verbatim so you can grep your logs or config for the offender:

```
fragment '#password' on URI 'aws-secrets-prod:///db-creds#password' uses legacy
plain-string shorthand; rewrite as '#<directive>=<value>' (for example, the
aws-secrets backend now requires '#json-key=password'). See
docs/fragment-vocabulary.md
```

## Migrating from v0.2.0

v0.2.0 shipped the aws-secrets backend with a plain-string shorthand: `#password` meant "extract the `password` JSON field." That form is rejected in v0.2.1 with a migration hint pointing at the canonical replacement.

| v0.2.0 (removed) | v0.2.1+ (canonical) |
|---|---|
| `aws-secrets-prod:///db#password` | `aws-secrets-prod:///db#json-key=password` |
| `aws-secrets-prod:///db#host` | `aws-secrets-prod:///db#json-key=host` |

If you see `ShorthandRejected` in your logs, your URI uses the old form — rewrite it using the table above.

## Why this shape

Earlier internal drafts let each backend define its own fragment shape. That was cheap on day one but it forces every user, every backend contributor, and every IDE autocomplete story to re-learn the grammar per backend. A single URI-layer grammar with a backend-local directive registry scales better: new backends pick well-defined keys without re-litigating punctuation, old backends don't drift, and tooling can validate fragments before a single command reaches the wire.
