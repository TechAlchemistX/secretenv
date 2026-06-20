# Rolling out SecretEnv across your org

Adopting SecretEnv at scale follows a predictable sequence. Each stage is independently reversible, so you can pause or roll back at any point without stranding a team.

## The six stages

1. **Discovery.** Inventory the secret backends already in use. Pick a registry host: any backend the platform team controls and every engineer can reach (AWS SSM, Vault, 1Password, Cloudflare KV all work well).

2. **Pilot.** One team, one registry, a hand-written `config.toml`. Validate end to end with `secretenv doctor --extensive`.

3. **Author the org profile.** Publish a single `acme-defaults.toml` to an HTTPS-reachable host: a CDN, an internal artifact store, or `secretenv.io/profiles`. A profile is a TOML fragment of `[registries.*]` and `[backends.*]` blocks.

4. **Org-wide install.** Hand out the one-line installer. New joiners get the right config from minute one. Local `config.toml` always wins where keys overlap, so a profile can never silently break a developer's setup.

5. **CI integration.** Set `SECRETENV_REGISTRY` at org-level CI variable scope, and add `secretenv doctor --json` as a pre-deploy gate.

6. **Offboarding playbook.** Codify "revoke registry-backend access" in your IAM runbook. One operation; covers every repo at once.

## Profiles: how a team converges every machine

Profiles let a platform team push its intended config to every developer without ever logging into anyone's laptop. The developer pulls; there is no server-pushed update channel.

```bash
# Install (or re-install with updated metadata)
secretenv profile install acme-corp --url https://internal.acme.com/secretenv/acme-corp.toml

# Update, ETag-conditional re-fetch; reports up-to-date or refreshed
secretenv profile update

secretenv profile list
secretenv profile uninstall acme-corp
```

Profiles are **additive merges, never overrides**. Local `config.toml` always wins. Self-hosted and air-gapped orgs point at their own base with `SECRETENV_PROFILE_URL`. A hard 1 MiB size cap per profile guards against a compromised distribution.

**Rollback** is a profile re-publish followed by `secretenv profile update` across the fleet. Again, the developer pulls.

Full profile reference: [Profiles](../reference/profiles.md).

## See also

- [CI/CD integration](ci-cd.md): per-platform runner patterns
- [The three-file model](../reference/three-file-model-deep.md): why config, manifest, and registry are separate
- [`secretenv doctor`](../reference/cli-reference-full.md#secretenv-doctor): the validation gate referenced throughout
