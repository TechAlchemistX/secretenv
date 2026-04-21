# Distribution profiles (`secretenv profile`)

Profiles are shared, TOML-formatted config fragments hosted over HTTPS that teams can publish once and everyone installs with a single command. A profile defines `[backends.*]` and/or `[registries.*]` entries that get **merged into** the user's local `config.toml` at load time — no manual editing required.

This is the v0.4 headline feature. The canonical host is `https://secretenv.io/profiles`, and you can also install from any URL (including private mirrors or `file://` paths).

## Why profiles

Onboarding a new engineer traditionally involves copy-pasting a chunk of `config.toml` from a wiki page or Slack thread. Profiles replace that with:

```sh
secretenv profile install acme-defaults
secretenv doctor  # now sees every team backend
```

Your org publishes `https://secretenv.io/profiles/acme-defaults.toml` (or any URL you control) once; everyone runs the same install command. Updates propagate with `secretenv profile update`.

## The merge model

- Profiles **fill gaps**, they don't override. If your `config.toml` defines `[backends.aws-prod]` and a profile also defines it, your local version wins.
- Files in `<config_dir>/profiles/*.toml` are merged in alphabetical order. First profile to define a key wins among profiles.
- Your own `config.toml` always wins over every profile.

This means a profile can never silently change your local behavior — it can only add things you haven't defined.

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

The downloaded TOML is validated as a SecretEnv config fragment before it's written — a malformed profile never reaches the filesystem. A sidecar `<name>.meta.json` captures the source URL, the server's `ETag`, and the install timestamp so `update` can do conditional re-fetch.

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

The updater sends an `If-None-Match: <stored-etag>` header; on `304 Not Modified` the local file is untouched and you see `up to date`. On `200 OK` the file is replaced and the sidecar metadata gets a fresh timestamp + ETag.

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

Passing `--url <url>` bypasses the base entirely — useful for one-off installs from arbitrary URLs.

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

After an engineer runs `secretenv profile install acme-defaults`, they can immediately do `secretenv --registry acme get any-alias` — no manual config editing.

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

You can also drop a `.toml` file into `profiles/` manually — it will be auto-merged on the next load. Such files show up in `profile list` as `(manual)` source; `profile update` errors out because there's no sidecar to tell it what URL to re-fetch.

## Security considerations

v0.4 delivers **unsigned profiles over HTTPS** — the threat model relies on TLS to guarantee integrity in transit and the canonical host's access control to prevent tampering at rest.

If the canonical profile host is compromised, an attacker could ship a profile that defines a malicious backend instance (e.g. a Vault pointing at an attacker-controlled URL). SecretEnv still refuses to leak secrets on argv/stdin (CV-1 guarantees), but the attacker could trick users into **writing** secrets to a malicious target via `registry set`.

**Signed profiles (minisign / sigstore / plain SHA256 manifests) are a v0.5+ hardening.** Until then:

- Treat `SECRETENV_PROFILE_URL` overrides like `curl | sh` — only install from hosts you trust.
- Review profile contents before installing: `curl -fsSL https://.../team.toml | less`
- For the most sensitive teams, host profiles behind a VPN or authenticated proxy.

## Known limitations

- **No signing yet** — see above. Planned for v0.5.
- **No profile index / search** — you need to know the profile name or URL. A central index (`secretenv.io/profiles/index.toml`) + `secretenv profile list --available` is a v0.4.1 / v0.5 idea.
- **No version pinning** — `profile install` always fetches the current version at that URL. If your profile host also publishes versioned URLs (e.g. `acme-defaults-v2.toml`), you can pin with `--url`.
