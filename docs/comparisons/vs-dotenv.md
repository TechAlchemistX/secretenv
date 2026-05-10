# SecretEnv vs `.env` files

**TL;DR.** `.env` files are the incumbent bad habit. They're the default that won't die because every framework loads them automatically. SecretEnv is the direct replacement for the workflow they enable: secrets fetched at runtime, injected into the child process, gone when it exits. Nothing on disk, nothing committed, nothing to forget.

---

## What `.env` actually does

`.env` is a convention, not a tool. Every framework parses it slightly differently. The shape is always `KEY=value` lines, loaded into the process environment at startup. The file lives in the repo root. It is supposed to be `.gitignore`'d.

In practice:
- Developers commit it accidentally (the default behaviour of many `.gitignore` files is missing `.env` entirely, or they create `.env.production` and forget the entry)
- Different developers have different values — so what works for one breaks for another
- New engineers spend their first day asking "where do I get the values for `.env`?"
- Offboarding requires every developer to confirm they don't have a `.env` with secrets that pre-dated the offboarded engineer's access
- Backend migrations require updating every repo's `.env.example` template + every developer's local `.env` + every CI's secrets store

---

## What SecretEnv replaces

| Property | `.env` | SecretEnv |
|---|---|---|
| Where the secrets live | Plaintext file on disk in the repo root | In your existing backends (AWS SSM, Vault, 1Password, etc.) |
| What's in the repo | The values themselves (when committed accidentally) OR a `.env.example` with placeholders | A `secretenv.toml` declaring alias names — never values, never paths |
| How values get to a process | Loaded by framework at startup | Fetched at runtime by SecretEnv, injected into child env, gone when child exits |
| Onboarding | "Ask in Slack where things live" | `secretenv profile install <org-name>` + clone any repo |
| Offboarding | Manual checklist per developer per backend per repo | Revoke registry-backend access — covers everything |
| Backend migration | Edit every `.env`, every `.env.example`, every CI variable | One `secretenv registry set` |
| Rotation | Edit every `.env` again | Transparent — next run picks up the new value from the backend |
| Disk persistence of secrets | Yes (always — that's the whole point of `.env`) | No (zeroed in-memory; never written) |

---

## Migration path

Going from `.env` to SecretEnv is incremental:

1. Move secret values into a backend you already have (AWS SSM, 1Password, etc.)
2. Add aliases to your registry pointing at those values
3. Replace your `.env` with a `secretenv.toml` declaring aliases for each variable
4. Add `secretenv run --` in front of your existing dev/start/test commands
5. Delete `.env`. Delete it from `.gitignore`. Move on.

Any developer who has already been bitten by a committed `.env` will not need a longer pitch than this.

---

## When `.env` is still the right answer

For a single-developer project with no production backend, `.env` is fine. If you're solo, don't have an AWS account, and the worst-case "secret" is a development-only Stripe test key — `.env` is a reasonable default until the project grows up.

The moment you have:
- A second developer
- A production environment
- A backend that already holds the secret authoritatively

`.env` is a workflow trap. Use SecretEnv (or one of the alternatives — see [the comparison overview](/comparisons/)).
