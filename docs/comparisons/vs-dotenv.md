# SecretEnv vs `.env` files

**TL;DR.** `.env` files are the incumbent bad habit. SecretEnv is the direct replacement: secrets fetched at runtime, injected into the child process, gone when it exits. Nothing on disk, nothing committed, nothing to forget.

---

## What `.env` actually does

`.env` is a convention: `KEY=value` lines in the repo root, loaded at startup. It's supposed to be `.gitignore`'d.

In practice:
- Developers commit it by accident (many `.gitignore`s are incomplete or add `.env.production` without the entry)
- Different developers have different values, breaking continuity
- Onboarding asks "where do I get `.env`?"
- Offboarding requires confirming no developer has an old `.env` with ex-member access
- Backend migrations require updating `.env.example`, every local `.env`, and every CI secret store

---

## What SecretEnv replaces

| Property | SecretEnv | `.env` |
|---|---|---|
| Where the secrets live | In your existing backends (AWS SSM, Vault, 1Password, etc.) | Plaintext file on disk in the repo root |
| What's in the repo | A `secretenv.toml` declaring alias names, never values, never paths | The values themselves (when committed accidentally) OR a `.env.example` with placeholders |
| How values get to a process | Fetched at runtime by SecretEnv, injected into child env, gone when child exits | Loaded by framework at startup |
| Onboarding | `secretenv profile install <org-name>` + clone any repo | "Ask in Slack where things live" |
| Offboarding | Revoke registry-backend access, covers everything | Manual checklist per developer per backend per repo |
| Backend migration | One `secretenv registry set` | Edit every `.env`, every `.env.example`, every CI variable |
| Rotation | Transparent; next run picks up the new value from the backend | Edit every `.env` again |
| Disk persistence of secrets | No (zeroed in-memory; never written) | Yes (always, that's the whole point of `.env`) |

---

## Migration path

1. Move secret values into a backend you already have (AWS SSM, 1Password, etc.)
2. Add aliases to your registry pointing at those values
3. Replace `.env` with a `secretenv.toml` declaring aliases
4. Prefix your dev/start/test commands with `secretenv run --`
5. Delete `.env` and its `.gitignore` entry

---

## When `.env` is still the right answer

For a solo project with no production backend and only dev-only secrets (test API keys), `.env` is fine. Once you have a second developer, a production environment, or a backend that holds secrets authoritatively, it becomes a workflow trap.
