# Distribution profiles (`secretenv profile`)

Profiles are shared, TOML-formatted config fragments hosted over HTTPS that teams can publish once and everyone installs with a single command. A profile defines `[backends.*]` and/or `[registries.*]` entries that get **merged into** the user's local `config.toml` at load time, no manual editing required.

This is the v0.4 headline feature. The canonical host is `https://secretenv.io/profiles`, and you can also install from any URL (including private mirrors or `file://` paths).

## Why profiles

Publish backend and registry config once; install everywhere with one command. No copy-paste, no doc drift:

```sh
secretenv profile install acme-defaults
secretenv doctor  # sees every team backend
```

Updates propagate with `secretenv profile update`.

## The merge model

- Profiles **fill gaps**, they don't override. Your `config.toml` always wins.
- Files in `<config_dir>/profiles/*.toml` are merged alphabetically. First definition wins.
- A profile can only add new entries, never change existing ones.

## CLI surface

```
secretenv profile install <name> [--url <url>]
secretenv profile list [--json]
secretenv profile update [<name>]
secretenv profile uninstall <name>
```

### `install`

```sh
# Fetch https://secretenv.io/profiles/acme-defaults.toml
secretenv profile install acme-defaults

# Fetch from a private mirror / staging URL / filesystem path.
secretenv profile install my-team --url https://vault.acme.corp/profiles/team.toml
secretenv profile install local-dev --url file:///tmp/draft-profile.toml
```

Validation happens before write. Malformed profiles never reach disk. A sidecar `<name>.meta.json` stores the source URL, server `ETag`, and install timestamp for conditional re-fetch on `update`.

### `list`

```sh
secretenv profile list
```

```
NAME                     INSTALLED            SOURCE
acme-defaults            2026-04-20T17:02:33Z https://secretenv.io/profiles/acme-defaults.toml
my-team                  2026-04-20T17:03:11Z https://vault.acme.corp/profiles/team.toml
```

`--json` emits a machine-readable array of `{name, path, source_url, installed_at}`.

### `update`

```sh
# Refresh one profile.
secretenv profile update acme-defaults

# Refresh all installed profiles.
secretenv profile update
```

Uses `If-None-Match: <stored-etag>` for conditional fetch. `304 Not Modified` → no change; `200 OK` → file replaced and metadata refreshed.

### `uninstall`

```sh
secretenv profile uninstall acme-defaults
```

Removes both the `.toml` and `.meta.json`. The next `secretenv doctor` (or any other subcommand) no longer sees the profile's entries.

## Overriding the base URL

Profile files are expected under `${base}/{name}.toml`. The base defaults to `https://secretenv.io/profiles` and can be overridden globally via the `SECRETENV_PROFILE_URL` env var:

```sh
export SECRETENV_PROFILE_URL=https://mirror.acme.corp/profiles
secretenv profile install team-defaults
# Fetches https://mirror.acme.corp/profiles/team-defaults.toml
```

Passing `--url <url>` bypasses the base entirely, useful for one-off installs from arbitrary URLs.

## Authoring a profile

A profile file is ordinary `config.toml` syntax, minus the `[profile]` kind of wrapper other tools use. Start with nothing more than the backend instances and registries your team needs:

```toml
# acme-defaults.toml

[backends.acme-ssm-prod]
type = "aws-ssm"
aws_region = "us-east-1"

[backends.acme-vault]
type = "vault"
vault_address = "https://vault.acme.corp"

[registries.acme]
sources = [
    "acme-ssm-prod:///teams/acme/registry",
    "acme-vault:///secret/teams/acme/registry",
]
```

After an engineer runs `secretenv profile install acme-defaults`, they can immediately do `secretenv --registry acme get any-alias`, no manual config editing.

## Storage layout

```
$XDG_CONFIG_HOME/secretenv/
├── config.toml              ← the user's own config (wins on conflicts)
└── profiles/
    ├── acme-defaults.toml
    ├── acme-defaults.meta.json
    ├── my-team.toml
    └── my-team.meta.json
```

Manual `.toml` files dropped into `profiles/` auto-merge on load and show as `(manual)` source in `profile list`. `profile update` errors on these (no sidecar URL).

## Security considerations

v0.4 delivers **unsigned profiles over HTTPS**. A compromised profile host could inject a malicious backend URI. While SecretEnv still refuses to leak secrets on argv/stdin (CV-1), attackers could trick users into **writing** secrets to a malicious target via `registry set`.

**Signed profiles (minisign / sigstore) are a v0.5+ hardening.** Until then:

- Treat `SECRETENV_PROFILE_URL` like `curl | sh`: install from trusted hosts only.
- Review contents: `curl -fsSL https://.../team.toml | less`
- For sensitive teams, host profiles behind a VPN or authenticated proxy.

## Known limitations

- **No signing yet**: planned for v0.5.
- **No profile index / search**: know the name or URL; central index planned for v0.5.
- **No version pinning**: always fetches current. Pin manually via `--url` if your host publishes versioned URLs.
