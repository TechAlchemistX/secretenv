# Changelog

All notable changes to SecretEnv are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Dates are in `YYYY-MM-DD` (UTC).

## [Unreleased]

### v0.9.2 hygiene (merged-not-tagged 2026-04-26)

Fourth consecutive rolling-backlog cycle (v0.7.1 → v0.7.2 → v0.9.1 → **v0.9.2**) draining the v0.9.x carry-forward queue before the v0.10 OpenBao cycle opens. Merged to `main`, workspace `version` stays at `0.9.0`, no tag. v0.10 OpenBao release will fold these into its tagged CHANGELOG.

#### Added

- **`cf_kv_list_prefix` config field** (cf-kv backend) — optional key-prefix filter passed to `wrangler kv key list` as `--prefix <value>`. Enables single-namespace scalar+registry mixing via key conventions (e.g. `cf_kv_list_prefix = "registry/"` so registry-source aliases live under `registry/<alias-name>` while plain scalar secrets share the namespace at the top level). Empty string is normalized to `None` at factory time. Closes the v0.9.x carry-forward "cf-kv `--prefix` flag" item. Pre-v0.9.2 alternative — two separate namespaces — still works and remains the default posture for accounts where namespace count is not a constraint.
- **17 new factory-validation unit tests** across `secretenv-backend-1password` (+5: `op_unsafe_set` accept/reject + `timeout_secs` honor/default/reject), `secretenv-backend-cf-kv` (+4: `wrangler_bin` reject + `timeout_secs` honor/reject/zero) and prefix-related (+2 above), `secretenv-backend-vault` (+4: `vault_namespace`/`vault_bin` reject + `timeout_secs` honor/default), `secretenv-backend-aws-secrets` (+4: `aws_profile`/`aws_bin` reject + `timeout_secs` honor/default). Closes the cf-kv code-reviewer M1 carry-forward "factory-helper test parity audit" — the four backends with the thinnest factory-validation coverage now match the keeper / azure / aws-ssm pattern.

#### Audited (no findings)

- **Workspace-wide placeholder-field audit** — methodology: `grep -rn "Reserved\|reserved" crates/backends/*/src/*.rs` plus per-backend struct-field walk for any `Option<T>` config field never read after factory construction. Result: zero placeholder fields outside the `keeper_folder` already removed in v0.9.1. The two grep hits (`backend-doppler` "Fragments are reserved for v0.7+", `backend-infisical` "Fragments are reserved and currently rejected") are doc-comment phrases describing forward-compatibility posture, not dead config fields. Audit captured here so it doesn't get re-run unnecessarily next cycle.

#### Deferred / declined (carry-forward closeout notes)

- **cf-kv `bulk get`** — DEFER. Cloudflare API still in open-beta as of 2026-04-26. Trigger to revisit: GA announcement.
- **cf-kv `#metadata` fragment** — DECLINE. Speculative; zero user demand. Resurrect on demand.
- **Rust 1.87+ `env::set_var` unsafe-wrap (R-13 from v0.7.2)** — DEFER. Workspace MSRV is 1.75. Bumping to 1.87 in a hygiene patch is a user-facing breaking floor change, not hygiene. Trigger: next natural workspace MSRV bump.
- **256 KiB `spawn_blocking` measured benchmark (v0.7.2 carry-over)** — DEFER. Needs `cargo bench` / criterion infrastructure that doesn't exist in the workspace yet. Trigger: dedicated benchmark-infrastructure micro-cycle.

### v0.9.1 hygiene (merged-not-tagged 2026-04-25)

Rolling-backlog cycle following the v0.7.1 / v0.7.2 dev-work pattern: merged to `main`, workspace `version` stays at `0.9.0`, no tag. Closes 13 actionable items from the v0.9 trio audit deferred list ([reviews/2026-04-25-v0.9-cf-kv-audit](kb/wiki/reviews/2026-04-25-v0.9-cf-kv-audit.md)) plus the v0.8.x Keeper carry-forward backlog plus baseline smoke hygiene. v0.10 Bitwarden release will fold these into its tagged CHANGELOG.

#### Added

- **`keeper_list_max_records`** (Keeper backend) — opt-in cap on `list()` per-record fan-out. Default unset (no cap). Bounds heap residence and outbound rate-limit pressure on large vaults; hitting the cap emits a `tracing::warn!`. Closes Keeper trio sec-H1 follow-up.

#### Changed

- **`keeper_config_path` validated at factory time** — file existence + POSIX mode `0o077` mask. Permissive modes (group/other-readable) now bail with a `chmod 600` hint instead of silently loading a Keeper device token from a shared file. Closes Keeper trio sec-H2.
- **cf-kv `WranglerWhoami::parse` refactored to `find_map`** — clearer style, same behavior. Closes cf-kv rust-L1.
- **cf-kv `resolve_target` allocation-free** — `split_once('/')` chain replaces the previous `Vec<&str>` collect. Closes cf-kv rust-L5.
- **cf-kv smoke namespace IDs centralized** to `scripts/smoke-test/lib/cfkv-namespace.env` — single source of truth (was 3-place duplication). Closes cf-kv code-reviewer L2.
- **cf-kv docs expanded** with Troubleshooting, `set()` opt-in posture comparison table vs other backends, and multi-namespace worked example. Closes cf-kv code-reviewer L1.
- **Backend-spec template Phase 1 checklist** explicit "new crate → `deny.toml` per-crate AGPL exception" + `cargo deny check licenses` preflight gate. Captures the v0.8 Keeper lesson so future cycles don't hit the CI-only failure.

#### Removed

- **`keeper_folder` config field** — declared since v0.8 but never wired up (documented as "reserved for future short-form URI scoping. Currently accepted but unused"). API-surface debt removed; if folder scoping ships in a future release it will be re-introduced under a deliberate spec.

#### Fixed

- **Section 17 (v0.4 history) — `seed_runtime_from_fixtures` git-init validity gate.** The previous `[ ! -d .git ]` check skipped re-init when `.git/` existed but was broken (e.g., empty from a prior failed run). Replaced with `git rev-parse --git-dir` validity probe that wipes and reinits broken state. Recovers the 8 baseline failures (assertions 185-192) that were stuck in this state. Pre-existing baseline drift surfaced by v0.9 pre-tag full-matrix smoke.
- **Section 25k cf-kv post-delete read assertion** — switched pattern from lowercase `'not found'` to literal `'404'` to match wrangler 4.85.0's actual `404: Not Found` (capital N) error string. Same evidence; immune to case-shifts.

#### Smoke Section 25 additions (v0.9.1 hygiene)

- **343a — registry-namespace must NOT contain scalar fixtures** (sec-L1). Negative assertion locks the two-namespace discipline so a future regression mixing scalar + URI keys in the registry namespace fails loudly.
- **352–354 — wrangler-delete-actually-deletes canary** (sec-M2). Provisions a probe key, deletes via wrangler in the same non-TTY mode the cf-kv backend uses, asserts (a) post-delete read returns `404`, (b) `wrangler kv key list` no longer shows the probe. Locks the wrangler contract our backend depends on; if wrangler ever regresses to default-no on its interactive confirmation prompt, this canary catches it.

#### Smoke matrix delta

- v0.9.0 pre-tag: 408/419 PASS (11 baseline failures: 8 history + 3 Infisical).
- v0.9.1 post-fix: **420/423 PASS** (3 remaining = Infisical session expired locally; environmental, not code). +12 net recovered + 4 new assertions.

## [0.9.0] - 2026-04-25

**Headline:** fourth release of the single-backend-per-release cycle; fourth [[project_cycle_execution_model|solo-fresh-session]] release. One new backend — **Cloudflare Workers KV** (`cf-kv` via `wrangler` CLI 4.x) — brings the total to **12**. First backend whose Phase 0 CLI-shape probe materially flipped the spec: the v0.7-era spec recommended a curl-against-REST design citing 2-3 s wrangler startup, but live measurement at wrangler 4.85.0 showed 0.28 s startup (Bun runtime), so the entire curl branch was retired and the backend ships wrangler-wrapped. v0.8.0 → v0.9.0: workspace unit tests **676 → 705** (+29 from the new cf-kv crate); live smoke matrix **395 → 419** (+24 for Section 25's 13 cf-kv assertions plus a few extras). Pre-tag full-matrix smoke passed all 13 cf-kv assertions on the second run after fixing a registry-source design issue (single namespace can't mix scalar secrets with URI-valued aliases — the resolver bails on the first non-URI value; switched to a two-namespace pattern, mirroring how Doppler/Infisical use separate paths). Closing three-agent trio audit (security + code + rust) landed 8 BLOCKING/HIGH/MEDIUM findings inline before tag. The remaining 11 baseline-smoke failures (8 in v0.4 history + 3 in v0.7 Infisical) are environmental drift unrelated to v0.9 — to be addressed in a follow-up hygiene cycle.

### Added

- **Cloudflare Workers KV backend** (`cf-kv`) wrapping the official `wrangler` CLI 4.x. Supports OAuth (`wrangler login`) and `CLOUDFLARE_API_TOKEN` env-var auth transparently. Two-segment URI shape `cf-kv-<instance>:///<namespace-id>/<key>`, with optional single-segment form `cf-kv-<instance>:///<key>` enabled by `cf_kv_default_namespace_id` config. `set()` writes through a mode-0600 tempfile + `--path` flag (no `_unsafe_set` opt-in needed — strictly safer than argv; matches Infisical's `--file` discipline). `list()` is Pattern A bulk-mode with sequential per-key fan-out for value hydration; `history()` is unsupported (KV has no per-key versioning — overwrites simply replace). Brings the total backend count to **12**. Spec at [docs/backends/cf-kv.md](docs/backends/cf-kv.md).
- **Smoke Section 25** (assertions 330-352, 13 total) covering cf-kv as both a secrets backend (doctor / get / run-injection / history-unsupported / fragment-reject) AND a registry source (registry list / registry get / cross-backend resolve / end-to-end run via cf-kv-backed registry → local-main file content). Two-namespace pattern (`secretenv-smoke-v09` for secrets + `secretenv-smoke-v09-registry` for URI-valued aliases) is documented in `provision.sh` since cf-kv namespaces are flat (no folders to scope mixed key types).

### Fixed

- **Tightened `cf-kv` "key not found" detector** from a loose `"10009"` substring match to word-boundary forms (`error 10009` / `code 10009` / `code: 10009`) — prevents false-positives on stderr containing the digit run inside request IDs or timestamps. Surfaced by Phase 6 trio audit.
- **Made `set()` tempfile flush fatal** (`with_context` instead of `.ok()`) — silently dropping a flush error could leave wrangler reading a truncated value with no surface to caller. Surfaced by Phase 6 trio audit.
- **Added `NotFound` mapping to the `whoami` arm of `check()`** — the `tokio::join!` fires both probes simultaneously; the previous code only mapped `NotFound` on the version arm. Defense-in-depth for OS-shape variation. Surfaced by Phase 6 trio audit.

## [0.8.0] - 2026-04-24

## [0.8.0] - 2026-04-24

**Headline:** third release of the single-backend-per-release cycle; third [[project_cycle_execution_model|solo-fresh-session]] release. One new backend — **Keeper** (Keeper Security vault via Keeper Commander v17+) — brings the total to 11. First backend to require a **prerequisite setup step** (persistent-login device-token registration); the install UX has an extra paragraph in docs as a result. v0.7.1 → v0.8.0: workspace unit tests **645 → 676** (+31 from the new Keeper crate); live smoke matrix **383 → 395** (+12 for Section 24). Pre-tag full-matrix smoke passed 395/395 across all 11 backends on first clean run; closing three-agent trio audit (security + code + rust) landed 9 BLOCKING/HIGH/MEDIUM findings inline before tag, including a post-audit whoami text-parse fix surfaced during pre-tag smoke (CLI v17 `keeper whoami` has no `--format=json` flag — a spec/impl drift caught at the final integration gate). Note: v0.7.1 + v0.7.2 shipped as merged-not-tagged hygiene cycles; workspace version stayed at 0.7.1 until this tag bumps directly to 0.8.0.

### Added

- **Keeper backend** (`keeper`) — 11th backend. Wraps the `keeper` CLI (Keeper Commander v17+, installed via `pip install keepercommander`) to read, write (opt-in), delete, and list secrets in a user's Keeper vault. Unlike every other SecretEnv backend, **Keeper requires persistent-login setup as a prerequisite** — one-shot CLI invocations prompt for the master password unless a device token has been persisted via `keeper shell` → `this-device register` → `this-device persistent-login on`. The backend enforces `--batch-mode` on every invocation to prevent interactive prompts from hanging; a non-authenticated instance surfaces cleanly through `doctor` with a setup hint rather than blocking. URI shape: `keeper-<instance>:///<record-uid-or-title>` — a single path segment the CLI resolves to either a 22-char base64url UID or a record title. Optional `#field=<name>` fragment selects a typed or custom field (default: password). Config fields: `keeper_config_path` (custom `~/.keeper/config.json` path for multi-account setups), `keeper_unsafe_set` (default `false`; opt-in gate for argv-based `set()` — the Keeper CLI has no stdin form for field values, matching 1Password's `op_unsafe_set` precedent; emits `tracing::warn!` per unsafe invocation), `timeout_secs`, `keeper_bin` (test hook). `list()` uses the Pattern A bulk model (each vault record = one alias, password field = target URI) mirroring Doppler + Infisical; per-record failures during the hydration fan-out emit `tracing::warn!` with instance + title + reason rather than silent-continue (divergence from the silent pattern was flagged + fixed inline during trio audit). `history()` is unsupported — CLI `history` is interactive-shell command history, NOT per-record version history; bails with Vault-UI pointer. Full reference at [`docs/backends/keeper.md`](docs/backends/keeper.md).
- **Smoke harness Section 24** — 12 live-backend assertions for the new Keeper backend. Provisions `SMOKE_TEST_VALUE` (scalar `kp_vault_88888`) and `SMOKE_REGISTRY_ALIAS` (URI-valued) records in the user's root folder; exercises `doctor` / `get` (round-trip via both title and registry alias) / `run` (end-to-end env injection) / `history` (unsupported bail) / unknown-fragment-reject end-to-end. Tears down both records after. Tagged `cloud=yes`; skipped when the `keeper` CLI is missing OR persistent login isn't set up.

### Fixed (v0.7.1 + v0.7.2 hygiene work, merged as dev work 2026-04-23/24)

The v0.7.1 (#67) and v0.7.2 (#68) cycles closed 25 DEFER items from the v0.6 Doppler and v0.7 Infisical closing audits as *merged-but-unreleased* work on `main`. Shipping now under the v0.8.0 tag so downstream users benefit. Full detail in [v0.7.1 CHANGELOG](#071---2026-04-23) and the build log.

Key items:
- Infisical `set()` value-aware stderr scrub; fd-based chmod; non-UTF-8 `$TMPDIR` explicit bail.
- Doppler `ResolvedTarget` struct (replaces positional tuple); tightened `not found` heuristic so auth errors no longer mask as missing-secret; `tracing::debug!` on set/delete happy paths.
- Both Doppler + Infisical `list()` JSON parse hops to `spawn_blocking` ≥256 KiB (threshold PROVISIONAL pending 10K-secret benchmark).
- Infisical env-inherit test deterministic via mutex-serialized `EnvVarGuard`.
- Live smoke coverage: Doppler + Infisical finally exercised as registry sources (sections 22g, 23g) — closed the long-deferred TODO from v0.6.
- Documentation polish: Infisical self-hosted domain trust, Doppler IAM/RBAC + chmod advisory, `docs/security.md#self-hosted-domains` cross-linked from Infisical + Vault.

### Changed

- **Workspace version 0.7.1 → 0.8.0.** v0.7.1 + v0.7.2 held Cargo.toml at 0.7.1 while merging hygiene work as dev-only (no tag, no crates.io publish). This v0.8.0 tag bumps directly to 0.8.0, skipping a 0.7.2 tag. Users pulling from crates.io see v0.7.0 → v0.8.0 linearly; the intermediate hygiene fixes are bundled into v0.8.0.
- **Backend count 10 → 11.** README badge + supported-backends table reflect the Keeper addition.

### Deferred to v0.8.x+

- **Keeper `keeper_config_path` world-readable stat-check** at factory time (trio security H2). Feature-add, not tag-blocker.
- **Keeper Pattern A `registry set` extension.** Would let `registry set`/`unset` target Keeper (as well as Doppler + Infisical). Feature, not hygiene; target v0.9+.
- **`keeper_folder` short-form URI scoping.** Field declared + accepted; implementation deferred.
- **Rust 1.87+ `env::set_var` unsafe-wrap** (v0.7.2 carry-over R-13) — triggers when workspace rust-version floor moves.
- **256 KiB `spawn_blocking` threshold benchmark** (v0.7.2 carry-over) — distinct activity, not hygiene-shaped.

## [0.7.1] - 2026-04-23

**Headline:** dedicated DEFER-closeout hygiene patch between v0.7.0 and v0.8, keeping the next backend cycle cleanly thematic. Twenty items from the v0.6 (Doppler) and v0.7 (Infisical) closing audits closed in a single patch PR: three security-hardening items on Infisical's `set()` temp-file path, six consistency items unifying Doppler and Infisical error shapes and symmetry patterns, three testing-quality items (deterministic env-isolation, list()-parse spawn_blocking on multi-MB payloads, symmetric drift-catch naming), and eight documentation polish items spanning the self-hosted-domain trust boundary, IAM/RBAC walkthroughs, and smoke-harness fixture comments. No user-facing behavior changes beyond tightened error messages. v0.7.0 → v0.7.1: workspace unit tests **637 → 642** (+5); live smoke matrix unchanged at **373 assertions** (hygiene doesn't add assertions; pre-tag smoke re-runs the v0.7.0 baseline). Closing audit by the `code-reviewer` agent landed 2 HIGH fixes (ENV_LOCK invariant documentation + spawn_blocking threshold provisional flag) inline before tag; 0 BLOCKING findings.

### Changed

- **Doppler `resolve_target` returns a struct** (`ResolvedTarget { project, config, secret }`), replacing the positional `(&str, &str, &str)` tuple. Mirrors the Infisical backend's shape so the two SaaS-bulk-model backends read the same way across four call sites (`get` / `set` / `delete` / `list`).
- **Doppler `not found` heuristic tightened.** Now requires the CLI's canonical `"Could not find requested secret"` prefix rather than the looser `"not found"` substring. Before: a stderr line like `Doppler Error: Unauthorized: token not found` (auth-error phrasing) false-positived into the friendly "secret not found" arm and hid the real failure. After: only the canonical missing-secret phrasing routes to the friendly arm; auth errors surface verbatim via `operation_failure_message`. Regression tests on both `get()` and `delete()` lock the distinction.
- **Doppler segment-count error surfaces parsed segments.** A URI like `doppler-prod:///acme/prd` (two segments) now errors with `got 2 segment(s): [acme, prd]` instead of just `got 2 segment(s)`.
- **Doppler `set()` and `delete()` emit `tracing::debug!` on happy paths.** Matches the Keychain backend's audit-symmetry precedent. No values logged — only instance, op, project, config, secret name.
- **Infisical `resolve_target` lifetimes split.** Previously `<'a>(&'a self, uri: &'a BackendUri)` over-constrained `self` and `uri` to the same lifetime. Now `<'s, 'u>(&'s self, uri: &'u BackendUri) -> Result<ResolvedTarget<'u>> where 's: 'u` — callers with `self` outliving the URI (the common case) get precise borrow-checker reasoning without an artificial lifetime tie.
- **Both backends' `list()` JSON parse uses `tokio::task::spawn_blocking` above 256 KiB.** Below the threshold, the zero-overhead inline path runs (thread-pool dispatch > parse cost for a typical small registry). Above it, the parse runs on a blocking worker thread so a multi-MB payload stops stalling the tokio executor. Threshold is provisional — a measured benchmark is deferred to v0.7.2+.
- **Infisical drift-catch test renamed.** `delete_without_type_shared_flag_would_fail_strict_mock` → `delete_requires_type_shared_flag` for symmetry with the existing set() canary. Dual-purpose doc comment added to `set_value_never_appears_on_argv` flagging its paired `--type shared` drift-catch role.

### Fixed

- **Infisical `set()` stderr scrubs the secret value** before folding stderr into the error chain. A CLI parse-error that echoes the `--file` contents back can surface `NAME=VALUE` in stderr; the new `set_failure_message` helper replaces the value string with `<REDACTED>` when present (≥4 chars to avoid collision-prone short values), preserving non-value diagnostic information for debugging. Dedicated unit tests cover both the scrub path and the passthrough case.
- **Infisical env-inherit test deterministic.** `check_not_authenticated_when_probe_fails_and_no_token` previously carried a runtime skip if the parent process had `$INFISICAL_TOKEN` set. Now wrapped in an RAII `EnvVarGuard` (mutex-serialized against `ENV_LOCK`) that unsets for the test duration and restores on drop. Test runs and asserts deterministically regardless of parent-process state.

### Security

- **Infisical `set()` uses fd-based `chmod` instead of path-based.** Replaces `std::fs::set_permissions(tempfile.path(), perm)` with `tempfile.as_file().set_permissions(perm)` — closes the narrow TOCTOU window between `NamedTempFile::new()` and the redundant 0600 re-assertion. (The `NamedTempFile` crate already creates with `O_CREAT|O_EXCL` + mode 0600 on Unix; the explicit re-chmod is belt-and-braces.)
- **Infisical `set()` explicit bail on non-UTF-8 `$TMPDIR` paths.** Replaces `to_string_lossy().into_owned()` with `to_str().ok_or_else(...)?` — a non-UTF-8 temp path now surfaces a clear error instead of passing a U+FFFD-substituted garbled string to `infisical secrets set --file` (which would fail with an opaque "file not found").

### Docs

- **Infisical self-hosted domain-trust section expanded.** New subsection under [Minting a service token](docs/backends/infisical.md) with pin-the-cert callout, verify-the-domain checklist, `openssl s_client` inspection snippet, and the "malicious domain receives every token" threat statement. Cross-linked to new `docs/security.md#self-hosted-domains`.
- **Infisical `NamedTempFile` panic-safety wording.** `set()` discipline section now spells out that `Drop` runs during unwind so panics / cancellations / runtime drops cannot orphan a secret-bearing file under `$TMPDIR`.
- **Doppler IAM/RBAC expansion** under [Service-token scope mismatch](docs/backends/doppler.md): service-token scope-mismatch vs. auth-error distinction (ties back to the tightened `not found` heuristic above), service accounts and project-level access grants, multi-workplace setup pattern.
- **Doppler `doppler_token` file-permissions advisory.** Explicit `chmod 600 config.toml` guidance matching the 1Password backend's precedent, with a pointer to also `700`-scope the parent directory.
- **Smoke harness Infisical blocks flagged "fixtures only, never use for a real secret"** on both `provision.sh` and `teardown.sh`. The provisioner uses the CLI's positional argv form (value on argv) because the value is a known-fixed fixture string and this is a fixture hook, not the code path end-users invoke.
- **`docs/security.md` new Self-hosted Domains section** cross-linked from both Infisical (`infisical_domain`) and Vault (`vault_address`). Covers the five-point discipline: verify the domain, pin HTTPS, confirm the cert chain, don't inherit a domain from an untrusted registry, rotate tokens after suspected exposure.

### Deferred to v0.7.2+

- **10K-secret `list()` benchmark** for the 256 KiB `spawn_blocking` threshold. Constant is explicitly marked `PROVISIONAL` in-source; benchmark to be captured under the smoke-harness report that exercises `list()` against a large real registry.
- **Pattern A registry `set` extension** (would let `registry set`/`unset` target Doppler + Infisical). This is a feature, not hygiene. Logged in the v0.8+ roadmap row.
- **Already-correct-code-just-needs-a-comment** items from the v0.7 audit (redundant chmod rationale, `sync_all` doc, env-var check scope comment) — drive-by cleanups for any future PR touching those lines.

## [0.7.0] - 2026-04-22

**Headline:** third release of the single-backend-per-release cycle; second [[project_cycle_execution_model|solo-fresh-session]] release. One new backend — **Infisical** (SaaS + self-hostable) — brings the total to 10. Spec at [[backends/infisical]] shipped with three inline post-implementation corrections (no `secrets versions` subcommand at CLI v0.43.77; `--plain` deprecated on list (use `--output json`); `delete --type` defaults to `personal` and must be passed `--type shared` explicitly). v0.6.0 → v0.7.0: workspace unit tests **604 → 637** (+33); live smoke matrix **362 → 377** (+15). Pre-tag full-matrix smoke passed 377/377 across all 10 backends; closing reviewer-trio audit (security + code + rust) landed 3 BLOCKING fixes (serde `rename_all`, `list()` iterator readability, `with_context` quality) inline before tag; one post-audit `list()` semantic fix landed during pre-tag smoke (corrected to return `(name, value-as-URI)` pairs matching the Doppler-style bulk model). DEFER items consolidated into [[build-plan-v0.7.1]] for the next hygiene cycle.

### Added

- **Infisical backend** (`infisical`) — 10th backend. Wraps the `infisical` CLI (v0.43+) to read, write, delete, and list secrets in Infisical projects + environments + folders. Works against both the hosted SaaS at `app.infisical.com` and self-hosted Infisical instances — one config field (`infisical_domain`) flips between them. URI shape: full form `infisical-<instance>:///<project-id>/<env>/<secret>` or short form `infisical-<instance>:///<secret>` when `infisical_project_id` + `infisical_environment` defaults are set in `[backends.<instance>]`. Nested folders fold into middle segments (`<project-id>/<env>/<folder1>/<folder2>/<secret>` → path = `/folder1/folder2`). Config fields (all optional): `infisical_project_id`, `infisical_environment` (both-or-neither), `infisical_secret_path` (default `/`), `infisical_token` (per-instance override for `$INFISICAL_TOKEN`), `infisical_domain` (self-hosted instance URL), `timeout_secs`, `infisical_bin` (test hook). Tokens travel via the `INFISICAL_TOKEN` subprocess env var — **never** via the `--token` argv flag (canary test `token_travels_via_env_not_argv` locks this); self-hosted domain travels via `INFISICAL_API_URL` env, never `--domain` on argv (symmetric discipline, `domain_travels_via_env_not_argv` canary). `set()` writes `NAME=VALUE` to a mode-0600 `NamedTempFile` under `$TMPDIR` and spawns `infisical secrets set --file <tempfile> --type shared` — the CLI has no stdin form, and using argv-positional form would expose values via `ps`; canary test `set_value_never_appears_on_argv` asserts values never reach argv. **`--type shared` is mandatory on set AND delete** — the CLI default is `personal` (user-override scope), which would silently target the wrong secret on shared project secrets; drift-catch test locks the invariant. `list()` uses `--output json` (the forward-compatible form; `--plain` is deprecated at v0.43.77) and follows the **Doppler-style bulk model** — each Infisical secret in the scoped env+path becomes one alias, the secret's value serves as the alias's target URI. `history()` is unsupported in v0.7 — the `infisical` CLI (v0.43.77) exposes no `secrets versions` subcommand; history exists in the Infisical Dashboard and REST API only. Full reference at [`docs/backends/infisical.md`](docs/backends/infisical.md).
- **Smoke harness Section 23** — live-backend assertions for the new Infisical backend. Provisions `SMOKE_TEST_VALUE=sk_test_infisical_55555` in the user's `secretenv-validation` project at `dev@/`; exercises `doctor` / `get` (full-form and short-form) / `run` / fragment-reject / `history` (unsupported bail) end-to-end. Tears down the seeded secret after. Tagged `cloud=yes`; skipped when the `infisical` CLI is missing or not authenticated. Project ID is overridable via `$SECRETENV_INFISICAL_PROJECT_ID`. Live matrix grows 362 → 373 (+11). Live-smoke of `backend.set()` is deliberately omitted — `registry set` only supports Pattern B backends (single-doc registries: local / 1password / aws-ssm / vault / aws-secrets / gcp / azure); Infisical follows the Pattern A Doppler-style bulk model, and unit-test canaries (argv + `--type shared` drift-catch) cover `set()` discipline. Extending `registry set` to Pattern A backends is deferred to v0.8+.

## [0.6.0] - 2026-04-22

**Headline:** second release of the single-backend-per-release cycle. One new backend (Doppler, 9th total), first **solo-fresh-session** cycle per the post-v0.5 execution model — orchestrator-solo through Phase 6, paused for sister-pane authentication at Phase 7, then tagged. Spec at [[backends/doppler]] shipped two post-implementation corrections (no `doppler secrets versions` subcommand in CLI v3.76.0; `DOPPLER_` prefix is not hard-reserved by Doppler). 9 backends supported: local, aws-ssm, aws-secrets, 1password, vault, gcp, azure, keychain, **doppler**. v0.5.0 → v0.6.0: unit tests **575 → 604** (+29); live smoke matrix **347 → 362** (+15). Pre-tag full-matrix smoke passed 362/362 across all 9 backends; closing reviewer-trio audit (security + code + rust) landed one BLOCKING fix (short-form URI + fragment-reject live assertions) plus three minor cleanups inline before tag; DEFER items captured in [[reviews/2026-04-22-v0.6-doppler-audit]].

### Added

- **Doppler backend** (`doppler`) — 9th backend. Wraps the `doppler` CLI (v3+) to read, write, delete, and list secrets in Doppler projects + configs. URI shape: full form `doppler-<instance>:///<project>/<config>/<secret>` or short form `doppler-<instance>:///<secret>` when `doppler_project` + `doppler_config` defaults are set in `[backends.<instance>]`. Config fields (all optional): `doppler_project`, `doppler_config` (both-or-neither), `doppler_token` (per-instance override for `$DOPPLER_TOKEN`), `timeout_secs`, `doppler_bin` (test hook). Tokens travel via the `DOPPLER_TOKEN` subprocess env var — **never** via the `--token` argv flag (canary test `token_travels_via_env_not_argv` locks this). `set` pipes values through child stdin with `--no-interactive` (CV-1 discipline, locked by stdin-fragment canary). `list()` uses the entire Doppler config as the alias map (each Doppler secret = one alias), with a **`DOPPLER_*`-prefix filter** that excludes the synthetic `DOPPLER_PROJECT` / `DOPPLER_CONFIG` / `DOPPLER_ENVIRONMENT` entries Doppler auto-injects into every `secrets download`. `history()` is unsupported in v0.6 — the `doppler` CLI (v3.76.0) exposes no `secrets versions` subcommand; history exists in the Doppler Dashboard and REST API only. A future CLI release adding `secrets versions` can flip this to a native implementation in a patch. Full reference at [`docs/backends/doppler.md`](docs/backends/doppler.md).
- **Smoke harness Section 22** — 15 live-backend assertions for the new Doppler backend. Provisions a `secretenv-validation` Doppler project + `dev` config with a `SMOKE_TEST_VALUE` fixture; exercises `doctor` / `get` (full-form and short-form) / `run` / fragment-reject / `history` (unsupported bail) end-to-end; tears down the test secret after. Tagged `cloud=yes`; skipped when the `doppler` CLI is missing or not authenticated. The synthetic-`DOPPLER_*`-key filter is locked by unit tests (`list_returns_filtered_map` + `list_filters_every_doppler_prefixed_key`) rather than in the live matrix, since `registry list --registry <doppler-URI>` requires every entry's value to parse as a URI — and the live fixture's scalar `SMOKE_TEST_VALUE` exercises the `get` round-trip instead. Live matrix grows 347 → 362 (+15).

### Fixed

- **Provision harness — Azure soft-delete recoverable state handling.** The v0.5 provision flow failed on a fresh run whenever `az keyvault secret delete` from a prior teardown had soft-deleted (rather than purged) the two `secretenv-validation-*` fixtures. The resulting `409 Conflict — ObjectIsDeletedButRecoverable` aborted the Azure block and cascaded into missing-secret failures in the v0.3 Azure smoke sections. Added `az_ensure_available()` helper in `scripts/smoke-test/provision.sh` that pre-checks `show-deleted` state per fixture, calls `az keyvault secret recover` + `sleep 8` propagation wait when soft-deleted, then proceeds to `set`. Makes provision fully idempotent across teardown/provision cycles.

## [0.5.0] - 2026-04-22

**Headline:** first release of the "single backend per release" cycle — one new backend (macOS Keychain), the canonical `examples/` directory at repo root, and the five blocking fixes from the parallel three-agent closing audit. Rung-1 release of the [parallel-backend-workflow](kb/wiki/parallel-backend-workflow.md) — last "orchestrator writes the code" cycle before external agent sessions take over in v0.6. 8 backends supported: local, aws-ssm, aws-secrets, 1password, vault, gcp, azure, **keychain**. v0.4.0 → v0.5.0: unit tests **536 → 575** (+39); live smoke matrix **336 → 347** (+11). Pre-tag full-matrix smoke passed 347/347 against all 8 backends; closing reviewer-trio audit (security + code + rust) landed 5 BLOCKING fixes before tag; DEFER items captured below.

### Added

- **macOS Keychain backend** (`keychain`) — 8th backend. Wraps the system `security` CLI to read, write, and delete `generic-password` or `internet-password` items in any addressable keychain (the user's login keychain by default, or a custom keychain via `keychain_path`). URI shape: `keychain-<instance>:///<service>/<account>`. Config fields: `keychain_path` (optional; default = login keychain), `kind` (optional; `"generic-password"` default or `"internet-password"`), `timeout_secs` (optional). Platform-gated: the factory bails on non-macOS at config-load time with a clear "macOS-only" error; the crate itself compiles everywhere so the workspace tests cleanly on Linux/Windows CI. Every `security` invocation uses `stdin: Stdio::null()` to prevent password-prompt hangs on locked keychains. `set` passes the secret value through child argv; on macOS's same-UID process model this exposure is same-UID-only and we accept it (no opt-in gate, unlike 1Password's `op_unsafe_set` on Linux), with a `tracing::warn!` on every `set` for audit. **`list()` is intentionally unsupported** — `security` has no safe list-by-prefix operation; host your alias registry on a different backend type (local, aws-ssm, aws-secrets, 1password, vault, gcp, or azure). `history()` and extensive-check are likewise unsupported (Keychain has no native version-history API). Full reference at [`docs/backends/keychain.md`](docs/backends/keychain.md).
- **`examples/` directory at repo root** — canonical configuration patterns. Seven subdirectories: `single-backend-local/`, `single-backend-aws-ssm/`, `single-backend-keychain/`, `cascade-local-then-vault/`, `multi-cloud-aws-and-1password/`, `ci-github-actions/`, `secretenv-toml-canonical/`. Each has `config.toml` + `secretenv.toml` + a README explaining the *why* of the pattern. Top-level [`examples/README.md`](examples/README.md) flags the "NOT Cargo examples" caveat so `cargo build --examples` is expected to no-op.
- **Smoke harness Section 21** — live-backend integration coverage for the new keychain backend. Provisions a self-contained test keychain at `$RUNTIME_DIR/test.keychain-db`, exercises `doctor` / `get` / `run` / `list` / `history` end-to-end, and tears down after. Tagged `cloud=yes` so `--local-only` (Ubuntu CI) skips it; macOS full-matrix runs include it. Live matrix grows 336 → 347 (+11).

### Tests

- Workspace unit tests **536 → 575** (+39): all in the new `secretenv-backend-keychain` crate. Covers URI parsing (including `%2F` slash-escape); factory validation (kind enum, timeout_secs, `keychain_path` flag-injection rejection, cross-platform cfg-gated tests); get/set/delete strict-mock argv coverage; list / check_extensive / history backend-specific unsupported-error messages; check() paths (Ok, Locked/NotAuthenticated, CliMissing, missing keychain file → Error, wrong stdout shape → Error); and drift-catch regression locks for every argv invariant (missing `-U` upsert, `-k`-vs-positional on get/delete/check).
- Live smoke matrix **336 → 347** (+11): Section 21 Keychain.

### Internal — closing audit (2026-04-22)

Three-agent audit (`security-engineer` + `code-reviewer` + `rust-engineer`) ran in parallel against the merged v0.5 backend + smoke + docs. Five BLOCKING findings landed in an audit-polish PR; all DEFER items captured in `kb/wiki/build-log.md`:

- `keychain_path` values starting with `-` rejected at factory time (would be parsed as a flag by `security` once appended to argv).
- `check()` distinguishes `"No such keychain"` (missing file → `Error`, no fix available) from "locked keychain" (`NotAuthenticated`, `security unlock-keychain` hint).
- `check()` validates that `show-keychain-info` output contains a `Keychain` sentinel (in stdout or stderr — the real binary writes to stderr) before returning `Ok`, guarding against a shadowing PATH binary.
- Three drift-catch tests added — declaring `-k <path>` argv on get / delete / check and asserting no-match, locking the trailing-positional convention against future reintroduction.
- `history()` overridden to call `reject_any_fragment("keychain")` before bailing, so a `#version=2`-carrying URI surfaces the unsupported-directive mistake rather than silently dropping the fragment.

## [0.4.0] - 2026-04-22

**Headline:** team ergonomics + distribution profile system + tooling hygiene. Functionality-only release — **no new backends** (still 7 live: local, aws-ssm, aws-secrets, 1password, vault, gcp, azure). Aggregate of v0.4 phases 1-7: `doctor --fix/--extensive` + `registry history/invite` (operator surfaces), distribution profile system served from `https://secretenv.io/profiles/` (the headline feature), per-instance `timeout_secs` + 1Password `set` safe-by-default, smoke-harness promoted into the repo with selective-run flags, GitHub Actions Node 24 readiness, `deny.toml` AGPL tightening, and per-file SPDX headers. v0.3.0 → v0.4.0 unit tests grew **442 → 536**; live smoke matrix grew **250 → 336** assertions. Closing reviewer-trio audit (security + code + rust) ran 2026-04-21; 6 blocking findings closed.

### Added

- **`secretenv profile install|list|update|uninstall`** — distribution profile system. A "profile" is a TOML document (`[backends.*]` + `[registries.*]` fragments only) fetched over HTTPS and auto-merged into the active `config.toml` at load time. Profiles fill gaps, never override: the user's own `config.toml` always wins where both define the same key; among profiles, alphabetical filename order decides conflicts. Profiles land in `<config_dir>/profiles/<name>.toml` with a sidecar `<name>.meta.json` (source URL + `ETag` + install timestamp) that `profile update` uses for conditional `If-None-Match` re-fetch. Default base URL is `https://secretenv.io/profiles`; overridable globally via `SECRETENV_PROFILE_URL` or per-invocation via `--url <url>` (supports `file://` for offline / local-staging flows). Fetching uses `curl` (subprocess) — no new HTTP client dependency, consistent with every other backend's CLI-spawn pattern. Fetched bodies are validated as `Config` fragments before being written to disk, so a malformed profile never lands. Profile names go through a strict ASCII allowlist (`[A-Za-z0-9][A-Za-z0-9_-]*`) with 64-char cap and Windows reserved-name check; `curl --max-filesize 1MiB` + `--proto =https,file` cap response size and pin scheme. `profile list --json` emits a machine-readable array; `profile update` (no name) updates every installed profile with a per-row report. Full walkthrough at [`docs/profiles.md`](docs/profiles.md).
- **`Config::load` + `Config::load_from` auto-merge profiles** from the `profiles/` directory next to the active config. Behavior for callers with no profiles installed is unchanged. New public helpers `secretenv_core::default_config_path_xdg()` and `secretenv_core::profiles_dir_for(config_path)`. The merge path enforces a 1 MiB per-file size cap so a compromised local `profiles/` dir can't OOM the load.
- **`secretenv registry history <alias>`** — show version history for the secret an alias resolves to. Output is most-recent-first across all backends. New `Backend::history()` trait method returns `Vec<HistoryEntry>` (`version`, `timestamp`, `actor`, `description`); default impl reports the operation as unsupported. Native implementations:
  - `local`: shells out to `git log --follow --pretty=format:%h%x09%aI%x09%an <%ae>%x09%s -- <path>`. Surfaces "not under a git repo" / "untracked" errors verbatim from git.
  - `aws-ssm`: calls `aws ssm get-parameter-history --with-decryption --name <param> --output json` and reverses AWS's oldest-first ordering. The `Value` payload is deliberately NOT captured by the deserializer (`ParameterHistoryRecord` lacks a `value` field) so secret values can never leak into history rendering.
  - `vault`: calls `vault kv metadata get -format=json <path>` (KV v2 only — KV v1's "Metadata not supported" error is surfaced verbatim). Versions sorted numerically descending. Soft-deleted versions surface as `[soft-deleted]`; destroyed versions as `[destroyed]`.
  - `aws-secrets`, `1password`, `gcp`, `azure` report "history unsupported" via the trait default; native overrides deferred (each has a quirk).
- **`HistoryEntry`** struct exported from `secretenv_core` for backend authors and tooling outside the workspace. Fields are string-typed so backend-specific identifiers (git SHAs, AWS integer versions, Vault decimal-string versions, RFC-3339 vs raw native timestamps) all fit without forcing CLI parse.
- **`secretenv registry invite [--registry <name>] [--invitee <id>] [--json]`** — copy-pasteable onboarding payload for sharing a registry with a new collaborator. Three sections: the `config.toml` snippet the new user adds (mirrors every non-`type` field from the inviter's `[backends.<instance>]` block, sorted, with strict-mock test-only fields filtered); the per-backend IAM/RBAC grant command the inviter runs (`aws iam attach-user-policy ...`, `op vault user grant ...`, `vault policy write ...`, `gcloud secrets add-iam-policy-binding ...`, `az role assignment create ...`, etc.); and two universal verify steps the invitee runs (`secretenv doctor`, `secretenv registry list`). Local backend renders filesystem/git access guidance with no CLI grant. Unknown backend types render a generic "no canonical template" pointer.
- **`secretenv doctor --fix`** — when any backend reports `NotAuthenticated`, `--fix` shells out to the canonical remediation CLI for that backend type (`aws sso login`, `op signin`, `gcloud auth login`, `az login`, `vault login`) and inherits stdio so the user can complete the interactive flow. Re-runs `check()` once afterward and renders the post-remediation report. Audit trail (which command, exit success, any spawn-error) recorded as a `Remediation actions` section in human output and a `fix_actions` array in `--json` output. Local backend + unrecognized types are skipped without panicking.
- **`secretenv doctor --extensive`** — Level 3 depth probe. For each `Ok` backend, doctor reads every `[registries.*]` source whose scheme matches and runs `Backend::check_extensive(uri)`. Result (alias count or read-failure error) renders as an indented `depth probe` block under the backend's tree node and serializes into a `backends[*].depth` array. Source URIs are deduped across registries. Surfaces permission scope (`12 aliases readable` vs `read failed: permission denied`) so operators can verify IAM/RBAC scope without leaving doctor.
- **`--fix` and `--extensive` compose** — `secretenv doctor --fix --extensive` first remediates any auth gaps and then probes depth against the post-remediation backend set in a single invocation.
- **`DoctorOpts` struct** — flags pass to `run_doctor` via a struct rather than positional booleans so future knobs (e.g. `--quiet`, `--strict`) can be added without churning internal call sites. Implements `Default` so `setup`'s embedded post-write doctor run keeps the existing behavior unchanged.
- **Per-instance `timeout_secs` config override** (`[backends.<name>]`) — applies to every fetch-class operation (`get`, `set`, `delete`, `list`, `history`) on that backend instance. Optional integer, must be positive seconds; default stays at `DEFAULT_GET_TIMEOUT` (30 s). The `check` (doctor) timeout deliberately does NOT consult this — `DEFAULT_CHECK_TIMEOUT` (10 s) keeps doctor parallelism predictable across instances. New `Backend::timeout()` trait method (default returns `DEFAULT_GET_TIMEOUT`); call sites in `runner::fetch_one` and `resolver::fetch_layer` wrap their backend-op futures with `with_timeout(backend.timeout(), ...)`. All 7 backends read the field at factory time. New `optional_duration_secs` and `optional_bool` helpers exported from `secretenv_core::factory_helpers` for plugin authors.
- **`scripts/smoke-test/`** — promoted live-backend integration smoke into the repo (was `/tmp/secretenv-test/` since v0.2.0). Three scripts (`provision.sh`, `run-tests.sh`, `teardown.sh`) plus `lib/common.sh` (shared bootstrap, env-driven cloud IDs, fixture seeding), `fixtures/` (templated config + local secrets), and `README.md`. `run-tests.sh` gains three filter flags: `--sections N,M,P-Q` (range syntax supported), `--local-only` (subset that needs no cloud CLI — sections 1, 12, 18 — runs in <30s without auth), `--list-sections` (inventory). Selective gating via a `SECTION_ACTIVE` short-circuit on `run_test`/`assert_contains`/`record`. Full matrix remains the maintainer-run pre-tag gate.
- **`smoke-local` CI gate** in `.github/workflows/ci.yml` — runs `bash scripts/smoke-test/run-tests.sh --local-only` on every push and PR. ~30s, no cloud auth needed. Catches CLI / completions / registry-invite / config-knobs regressions cheaply.
- **SPDX + copyright headers** on every `crates/**/*.rs` (29 files): `// Copyright (C) 2026 Mandeep Patel` + `// SPDX-License-Identifier: AGPL-3.0-only` at the top of each file. SBOM-tooling clarity + per-file provenance for fork / vendored-subtree consumers.

### Changed

- **1Password `set` is now safe-by-default.** Previously the `set` path silently passed the secret value through `op item edit`'s `field=value` argv tokens (CV-1: visible via `/proc/<pid>/cmdline` on multi-user Linux hosts) — a known limitation deferred from v0.2.4 because the `op` CLI still has no portable stdin-fed value form across the 1.x and 2.x generations. v0.4 closes the TODO by flipping the safe default: `set` now refuses with a clear error explaining the exposure, instructing the operator to either edit the field manually or opt in by adding `op_unsafe_set = true` to `[backends.<name>]`. The opt-in retains the previous argv-based behavior (with the existing tracing warning). **This is a behavior change for anyone who was running `secretenv registry set` against 1Password backends**; the new error surfaces immediately on upgrade and the remediation is one config line. Documented as a pre-launch breaking change.
- **Canonical project domain renamed `secretenv.dev` → `secretenv.io`.** All `install.sh`, README, CHANGELOG, SECURITY, docs, and Cargo metadata updated. The shell-level `install.sh --profile <name>` flag is **removed** — it wrote fetched TOML directly into `config.toml` with zero validation, a regression vs the threat model documented in `docs/profiles.md`. Use the in-binary `secretenv profile install <name>` subcommand instead, which parses + validates as `Config` before writing. The shell flag now errors with a pointer to the new path.
- **`UpdateOutcome` and `UpdateReport` marked `#[non_exhaustive]`** to keep v0.5+ variant/field additions (signature verification, retry metadata) non-breaking.
- **`profile install` / `update` / `uninstall` status messages** flipped from `println!` → `eprintln!`. Stdout reserved for data-shaped output; symmetric with `registry set/unset`.
- **`deny.toml` AGPL allowance tightened.** Removed `AGPL-3.0-only` from the global `licenses.allow` list; first-party crates admitted via per-crate `[[licenses.exceptions]]`. A future transitive AGPL dep now surfaces as a `cargo deny check` failure → forced explicit review.
- **Profiles posture (v0.4):** unsigned + HTTPS only. Signing (minisign / sigstore / SHA256 manifests) + central index file are deliberate v0.5+ work — threat model + mitigations in [`docs/profiles.md`](docs/profiles.md) §"Security considerations".

### Tests

- Workspace unit tests **442 → 536** (+94): doctor (+11 for `--fix`/`--extensive`), registry history (+10 across core trait + 3 backend overrides), registry invite (+16 in new `crates/secretenv-cli/src/invite.rs`), profile (+19 across name-validation, body-validation, install/list/update/uninstall, ETag parser, RFC 3339 formatter), config merge (+5 for profile gap-fill, user-wins, alphabetical order, malformed-profile error, missing-dir noop), CLI integration (+6 for profile + doctor + registry-invite help-locks).
- Live smoke matrix **250 → 336** (+86): registry history (24), registry invite (35), doctor `--fix` + `--extensive` (15), `timeout_secs` + `op_unsafe_set` (12).

### Internal

- Workspace version `0.3.0` → `0.4.0`.
- GitHub Actions bumped for Node 24 readiness: `actions/checkout` v4 → v6, `actions/upload-artifact` v4 → v7, `actions/download-artifact` v4 → v8, `softprops/action-gh-release` v2 → v3.
- Phase 6 decision: `secretenv-testing` stays `publish = false` (zero external consumers; reversible any time via single-line Cargo.toml flip + `cargo publish`). The strict-mock harness is still consumed internally as a path-dependency.
- Closing reviewer-trio audit (security-engineer + code-reviewer + rust-engineer in parallel) on 2026-04-21 surfaced 6 blocking findings; all closed before tag. Non-blocking items captured in `kb/wiki/build-log.md`.

## [0.3.0] - 2026-04-19

**Headline:** two new cloud backends (GCP Secret Manager + Azure Key Vault), the canonical `#key=value` fragment grammar locked in (v0.2.1 work), strict-mode mock test harness retrofitted across every backend (v0.2.2 → v0.2.7 + Phase 0), shared factory helpers, parallel `check()` probes via `tokio::join!`, and a **relicensing from MIT → AGPL-3.0-only + Contributor License Agreement**. The entire v0.2.1 → v0.2.7 internal-dev arc ships as one cohesive `v0.3.0` release (the last public version was v0.2.0 on 2026-04-18; v0.2.x patches were dev-merged without separate publishes per the aggregate-release posture locked during the cycle). 7 backends live: local, aws-ssm, aws-secrets, 1password, vault, **gcp**, **azure**.

### Fixed

- **Azure vault URL regex accepted 1-char names but rejected 2-char names.** The original pattern `^https://[a-zA-Z0-9]([a-zA-Z0-9-]{1,22}[a-zA-Z0-9])?\.vault\...` made the middle+last group optional, allowing a 1-char vault name while disallowing 2-char. Azure's own rule is 3-24. Flipped to `^https://[a-zA-Z0-9][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]\.vault\...` (required middle+last, min 3 chars, max 24). Three new factory tests lock the boundary: `factory_rejects_one_char_vault_name`, `factory_rejects_two_char_vault_name`, `factory_accepts_three_char_vault_name`. Caught by the v0.3 closing code-review audit.

### Added (closing-audit fixes, same unreleased window)

- **`Response::with_stdin_fragment(impl Into<String>)`** chainable method on `secretenv-testing::Response`. Appends to `stdin_must_contain`, allowing fluent composition: `Response::success("ok\n").with_stdin_fragment("secret")`. The existing `success_with_stdin(stdout, Vec<String>)` constructor remains for back-compat.
- **`check_extensive_counts_registry_entries`** unit test added to both `secretenv-backend-gcp` and `secretenv-backend-azure`. Locks the trait-default `Ok(self.list(test_uri).await?.len())` behavior for both v0.3 backends.
- **`set_drift_catch_rejects_data_flag_on_argv`** unit test added to `secretenv-backend-gcp`. Positive CV-1 lock mirroring azure's `--value`-leak + `--encoding-utf-8` locks — declares the buggy argv form (`--data=<secret>`) so a regression emitting the secret on argv instead of via `--data-file=/dev/stdin` fails.
- **Fragment-error messages now link to `docs/fragment-vocabulary.md`** in both gcp and azure's `resolve_version` (matches the aws-secrets shorthand error). Tests extended with `msg.contains("fragment-vocabulary")` assertions.

### Changed (v0.3 closing audit polish)

- **`BackendUri::fragment_directives` return type: `HashMap<String, String>` → `IndexMap<String, String>`.** Insertion order now deterministic = URI-written order, removes the need for `sort_unstable` in backend error-message construction. Backend code calls `.shift_remove("<key>")` instead of `.remove(...)` per `IndexMap`'s deprecation guidance. Pre-launch breaking change per the [[feedback_prelaunch_breaking_changes]] policy. Touched: `secretenv-core/src/uri.rs`, `secretenv-backend-{aws-secrets,gcp,azure}/src/lib.rs`.
- **`strict::Rule` refactor:** `Rule` in `secretenv-testing::strict` used to flatten every `Response` field (`argv, stdin_must_contain, env_must_contain, env_must_not_contain, stdout, stderr, exit_code`). Now `Rule { argv, response: Response }` — thin `(argv, response)` pair. `StrictMock::on` copies one struct move instead of seven field moves. Internal refactor; `Rule` is private so no API break.
- **Drift-catch assertion bodies tightened** from `msg.contains("strict-mock-no-match") || msg.contains("azure")` (always-true tautology — every azure error begins with `azure backend '…'`) to `msg.contains("strict-mock-no-match")` only. The `.unwrap_err()` at the outer layer remains the load-bearing lock; the content check now specifically confirms mock-level divergence rather than any azure-named error. Applied to gcp + azure drift-catch tests. Caught by the v0.3 closing security review.

### Changed

- **LICENSE: MIT → AGPL-3.0-only** (pre-launch breaking change per the policy documented in the memory system). MIT was the license of v0.1 and v0.2.0 — the latter is the only version currently published to crates.io / Homebrew / GitHub Releases. v0.3.0 and all subsequent releases ship under GNU Affero General Public License v3.0 (AGPL-3.0-only). The published MIT releases (v0.1.x, v0.2.0) remain available under their original terms; AGPLv3 applies going forward. Rationale: v0.3.0 finalizes the big-3-cloud-providers story (AWS, GCP, Azure) and the install base at the time of this change is effectively zero. AGPLv3 closes the SaaS-wrapping loophole (§13 requires source availability to network users of modified versions) while preserving user freedom for direct installs.
- **Workspace `Cargo.toml` `license`** field flipped `"MIT"` → `"AGPL-3.0-only"`. Every crate that inherits via `license.workspace = true` picks this up automatically; no per-crate change needed.
- **README** badge + License section updated to reflect AGPLv3 + the MIT-era disclosure.

### Added

- **Contributor License Agreement (CLA).** New [`CLA.md`](CLA.md) (license grant — NOT copyright assignment), [`AUTHORS.md`](AUTHORS.md) (signed-contributor ledger), and expanded [`CONTRIBUTING.md`](CONTRIBUTING.md) §License-and-CLA. The CLA lets the project relicense contributions (e.g., offer commercial licenses alongside AGPL) while contributors retain ownership of their own work. Signing is via `git commit --signoff` on every commit plus adding your name to `AUTHORS.md` on first contribution. "No CLA = no merge" is enforced at review.

### Added

- **`secretenv-backend-azure` (new crate):** second v0.3 backend — Azure Key Vault via the `az` CLI. URI shape `azure-<instance>:///<secret-name>[#version=<32-char-hex>]`. Canonical `#version=<id>` directive accepts a 32-character lowercase-hex Azure version ID OR the literal `latest`; `latest` (and the absent-fragment default) normalizes to omitting the `--version` flag entirely. Required config: `azure_vault_url` — fully-qualified HTTPS URL, regex-validated at factory time across all four sovereign-cloud domains (`.vault.azure.net`, `.vault.azure.cn`, `.vault.usgovcloudapi.net`, `.vault.microsoftazure.de`) with explicit rejection of path traversal (anchored trailing `/?$`) and hyphen-edge vault names. Optional: `azure_tenant`, `azure_subscription` (each passed as `--tenant` / `--subscription` when set), `az_bin` (test hook). `set` pipes secret values via `--file /dev/stdin --encoding utf-8` — the `--encoding utf-8` flag is load-bearing: the default `base64` would corrupt stored text secrets. Fragment on `set` URI explicitly rejected before any network call. `check()` runs Level 1 (`az --version` — multi-line output, regex-extracted) + Level 2 (`az account show`) concurrently via `tokio::join!`. Identity format: `user=<name> tenant=<id> subscription=<name> vault=<short-name>`. Soft-delete semantics documented — `delete` soft-deletes (Azure default); operators wanting full purge must run `az keyvault secret purge` manually. Cert-bound secrets (`kid != null` in response) surface a distinct error. Strict-mode mocks from day one — 36 tests across factory URL regex (5 tests incl. sovereign-cloud accepts + hyphen-edge + path-traversal rejects), `check` probe pair (4), `get` (10 incl. cert-bound + `#version=latest` flag-omission), `set` (3), `delete` (2), `list` (2), tenant/subscription argv variants (3), drift-catch locks (4: missing `--vault-name`, CV-1 stdin, `--value`-leak lock, missing-`--encoding-utf-8` lock).
- **`secretenv setup` gains `--azure-vault-url` + `--azure-tenant` + `--azure-subscription` flags** for azure-scheme registry URIs. Scheme router accepts `azure` + `azure-*` suffix forms; registry serializer adds `azure` to the JSON arm.

- **`secretenv-backend-gcp` (new crate):** first v0.3 backend — Google Cloud Secret Manager via the `gcloud` CLI. URI shape `gcp-<instance>:///<secret-name>[#version=<n>]`. Canonical `#version=<n>` directive supports positive integers + `latest` (latest = flag omitted; `gcloud` resolves to newest enabled version). Required config: `gcp_project`. Optional: `gcp_impersonate_service_account` (plausibility-validated as an SA email at factory time), `gcloud_bin` (test hook). `set` pipes the secret value through child stdin via `--data-file=/dev/stdin` (CV-1 discipline); fragment on `set` URI explicitly rejected before any network call. `check()` runs Level 1 (`gcloud --version`) + Level 2 (`gcloud auth print-access-token`) + identity enrichment (`gcloud config get-value account`) concurrently via `tokio::join!`. The OAuth2 bearer token returned by `print-access-token` is read only for exit status — `output.stdout` is dropped immediately and never interpolated into logs, errors, or identity strings. A dedicated canary test (`check_level2_auth_ok_never_logs_token_body`) locks this defense-in-depth contract with a sentinel token substring. Strict-mode mocks from day one — 32 tests across factory validation, the `check` probe triad, `get` + `set` + `delete` + `list`, fragment grammar rejection (shorthand, unsupported directive, invalid version value, invalid secret name), impersonation argv shape, and two drift-catch locks (missing `--project`, CV-1 stdin discipline). Secret-name charset `[a-zA-Z0-9_-]{1,255}` validated locally BEFORE any `gcloud` call.
- **`secretenv setup` gains `--gcp-project` + `--gcp-impersonate-service-account` flags** for gcp-scheme registry URIs. Scheme router accepts `gcp` + `gcp-*` suffix forms; registry serializer emits gcp registries as JSON (same wire shape as aws-ssm / vault / aws-secrets).

## [0.3.0-alpha.0]

**Headline:** v0.3 Phase 0 groundwork. Workspace version bumped to `0.3.0-alpha.0` — the aggregate release window is now open. This patch is pure internal refactoring — zero behavior change. GCP + Azure backend implementation follows in subsequent patches.

Aggregate release posture (locked 2026-04-19): the entire v0.2.1 → v0.2.7 + v0.3 backend series will ship as ONE cohesive `v0.3.0` release on crates.io, Homebrew, and GH Releases.

### Changed

- **`Backend::check_extensive`:** now has a default implementation on the trait itself (`Ok(self.list(test_uri).await?.len())`). The five backends' duplicated verbatim impls removed. A backend with a faster "count without materializing" CLI path may still override. Rust-engineer review flagged this as a 5× duplication.
- **`secretenv-core::factory_helpers`:** new public module exposing `required_string(config, field, backend_type, instance_name)` and `optional_string(config, field, backend_type, instance_name)`. The `backend_type` label is the new argument (vs. v0.2's hard-coded-per-backend strings); error shape is unchanged. aws-ssm, vault, aws-secrets factory blocks now call the shared helpers. v0.3 gcp + azure will use the same entry points, avoiding two more copies. 6 new unit tests in the helper module.
- **`Backend::check` for aws-ssm, aws-secrets, vault, 1password:** Level 1 (`<cli> --version`) and Level 2 (auth probe) now run concurrently via `tokio::join!`. The two probes are independent; serializing them doubled `secretenv doctor` latency per backend. For a config with 5 backends (current) that's ~5× the latency saving vs. v0.2; for v0.3 with 7 backends (adding gcp + azure) it becomes ~7×. No behavior change — error handling and short-circuiting semantics preserved.

### Internal

- Workspace version 0.2.7 → 0.3.0-alpha.0.
- Workspace test count 359 → 365 (+6 new factory_helpers unit tests).
- CHANGELOG entries undated — per the dev-only posture, no tag pushed yet. Date fills in at `v0.3.0` tag.

## [0.2.7]

**Headline:** security hardening follow-up to the v0.2.x retrofit series — three reviewer agents (code / security / rust) audited the full v0.2.x scope; this patch lands the defense-in-depth fixes surfaced by the security review. No user-facing behavior change for valid URIs.

### Security

- **`secretenv-testing::StrictMock`:** env-var keys passed to `Response::with_env_var` / `with_env_absent` are now validated at call time against `^[A-Za-z_][A-Za-z0-9_]*$`. A malformed key (e.g. `"KEY}; rm -rf /; :{"`) panics immediately rather than injecting arbitrary shell into the generated mock script. Closes a test-author-side defense-in-depth gap flagged by the security review.
- **`secretenv-testing::StrictMock`:** stdin-fragment mismatch diagnostic now emits only a REDACTED fingerprint of the missing fragment (`<len>-byte:<first-4-chars>…` for long values, `<len>-byte:<redacted>` for short). Previously, CV-1 stdin-discipline tests used canary secret values as the `stdin_must_contain` fragment; a regression that routed the secret to argv would have echoed the full secret to stderr and into CI logs. Now only the fingerprint appears.
- **`secretenv-testing::strict::escape_for_double_quoted`:** now panics on embedded `\n` / `\r` instead of silently swapping them for space. Caller contract was already "no newlines"; enforcement was lax. Fail-fast catches bugs where a diagnostic string was assumed safe but wasn't.
- **`secretenv-core::uri`:** new `BackendUri::reject_any_fragment(backend_label)` method + `FragmentError::UnsupportedForBackend` variant. Called from the top of `get` / `set` / `delete` / `list` in **aws-ssm**, **vault**, and **1password** — backends which do not accept fragment directives. Previously, a URI like `vault-prod:///secret/x#json-key=password` was silently accepted and the fragment dropped; now surfaces a clear "this backend accepts no fragment directives" error. Applied transitively to `list` paths that delegate to `get` (aws-ssm, 1password).
- **`secretenv-backend-1password::get`:** added a `debug_assert!` post-condition on `parse_path` output (no `/` in any of `(vault, item, field)`) to guard against future parse_path regressions that could leak the path structure into the `op://<v>/<i>/<f>` argv token.
- **Integration smoke harness:** the shared `secretenv-validation/api-key` fixture restore is now wired via `trap restore_fixture_on_exit EXIT` at the top of `/tmp/secretenv-test/scripts/run-tests.sh`. A mid-run failure, SIGINT, or interpreter error cannot leave the fixture polluted — the NEXT run's tests 30 / 39 will see the canonical `sk_test_secrets_22222` value regardless of how the prior run terminated. The v0.2.6 test 118 ("fixture restored") is retained for observability parity but is now a consequence of the trap handler, not the primary mechanism.

### Internal

- 6 new unit tests in `secretenv-testing::strict::tests` covering the above: `stdin_fragment_redaction_fingerprint_hides_value_never_leaks_full`, four panic-tests for env-var key validation, `escape_for_double_quoted_panics_on_newline`. The existing `stdin_check_rejects_when_fragment_missing` test updated to assert the redacted-fingerprint contract AND that the full secret does NOT appear in stderr.
- Workspace test count **353 → 359**.

### Origin

Findings surfaced by three parallel reviewer agents (code-reviewer, security-engineer, rust-engineer) auditing the full v0.2.x scope (fragment grammar, StrictMock harness, 5 backends, v0.2.6 fragment-before-network fix). The reviewers' v0.3-spec findings (GCP `print-access-token --project` flag, Azure argv size miscounts, Azure vault-URL regex path traversal) are applied to `kb/wiki/backends/{gcp,azure}.md` alongside this patch. The `AwsCli` / `tokio::join!` / `Response`-`Rule` unification / `IndexMap` refactors flagged by the rust-engineer land as v0.3 Phase 0.

## [0.2.6]

**Headline:** internal test-infrastructure release — aws-secrets backend's mock-CLI tests migrated to `StrictMock`, closing out the v0.2.x strict-mode retrofit series. **The first prod-code bug surfaced by the strict retrofit lands alongside the migration**: `AwsSecretsBackend::get()` was calling `aws secretsmanager get-secret-value` BEFORE validating the fragment directive, meaning a URI like `aws-secrets-prod:///myapp/cfg#password` (legacy shorthand, rejected since v0.2.1) would make a wasted AWS API call before surfacing the local grammar error. The v0.2 permissive-mock tests silently masked the extra call. Fixed: fragment validation now happens up-front, no AWS call occurs for invalid-grammar URIs.

### Fixed

- **`secretenv-backend-aws-secrets`:** `get()` now validates the fragment directive (`#json-key=<field>`, shorthand rejection, unsupported-directive rejection) BEFORE invoking `aws secretsmanager get-secret-value`. Pre-fix, an invalid fragment (`#password`, `#version=5`, or `#json-key=X,version=5`) caused a round-trip to AWS — wasting an IAM permission check, API latency, and potentially leaking an access pattern — before surfacing the local error. Caught by v0.2.6 strict-mode mocks with empty-rule installations (`StrictMock::new("aws").install(...)`) that reject any AWS call with exit 97; the v0.2 permissive-mock form returned success on the call, silently masking the extra round-trip. No end-user-visible behavior change for valid URIs.

### Changed

- **Internal:** all 25 mock-using tests in `secretenv-backend-aws-secrets` converted from the v0.2 raw `install_mock_aws(body)` API to declarative `StrictMock::new("aws").on(argv, Response).install(...)`. Every `secretsmanager get-secret-value`, `secretsmanager put-secret-value`, `secretsmanager delete-secret`, `sts get-caller-identity`, and `aws --version` argv is now asserted exactly. PR #33 BUG-2 (leading-slash on `--secret-id`) is **implicitly locked** across every migrated test — the declared argv carries the POST-STRIP secret ID; any regression would fail with a `strict-mock-no-match` diagnostic.
- **Internal:** argv-builder helpers `get_argv(secret_id)` / `put_argv(secret_id)` / `delete_argv(secret_id)` + `STS_ARGV_NO_PROFILE` const keep test bodies concise and make "what argv changed?" diffs narrow when a real shape change ships.
- **Internal:** `set_passes_secret_value_via_stdin_not_argv` rewritten using `Response::success_with_stdin` — CV-1 discipline is now a typed harness assertion rather than a log-file grep (parallel to aws-ssm v0.2.3 + vault v0.2.5).
- **Internal:** two new drift-catch regression-lock tests:
  - `get_drift_catch_rejects_leading_slash_on_secret_id` — POSITIVE BUG-2 lock: declares argv with the pre-fix slash-prefixed form; post-fix code diverges, strict harness emits exit 97 surfaced to the caller.
  - `set_drift_catch_rejects_secret_leaking_to_argv` — CV-1 parallel.
- **Internal:** three `command_always_passes_region` / `command_omits_profile` / `command_includes_profile` v0.2 log-file argv-shape tests collapsed: `--region us-east-1` is now implicitly asserted in every migrated test through the `get_argv` / `put_argv` / `delete_argv` helpers; profile-absent and profile-present cases retained as dedicated tests.
- **Internal:** v0.2.1 shorthand-reject and unsupported-directive-reject tests (`get_rejects_legacy_shorthand_fragment_with_migration_hint`, `get_rejects_unsupported_directive_with_enumerated_list`) now use empty-rule mocks — any AWS call exits 97 — making "this error originates in the fragment parser before any AWS call" a typed assertion. Both test bodies include an explicit `!msg.contains("strict-mock-no-match")` check to verify the error comes from the backend's grammar code, not the harness.

## [0.2.5]

**Headline:** internal test-infrastructure release — vault backend's mock-CLI tests migrated to `StrictMock`, and PR #33 BUG-1 (the flag-order fix: address/namespace routed via `VAULT_ADDR` / `VAULT_NAMESPACE` env vars rather than argv flags) is now a typed regression lock on every vault argv. No user-facing CLI changes; no prod bugs surfaced.

### Changed

- **Internal:** all 17 mock-using tests in `secretenv-backend-vault` converted from the v0.2 raw `install_mock` API to declarative `StrictMock::new("vault")...install()`. Every `vault kv get`, `vault kv put`, `vault kv delete`, `vault token lookup`, and `vault --version` argv is now asserted exactly. The PR #33 BUG-1 regression lock (no `-address` / `-namespace` argv flags) is implicit in the strict argv match — any regression that reintroduces those flags would fail with a `strict-mock-no-match` diagnostic.
- **Internal:** the two env-log side-channel tests (`command_omits_namespace_env_when_not_configured`, `command_includes_namespace_env_when_configured`) rewritten as declarative `with_env_var` / `with_env_absent` assertions — shorter, tighter, and checkable uniformly with argv at every invocation (not just this one test).
- **Internal:** `set_passes_secret_value_via_stdin_not_argv` rewritten using `Response::success_with_stdin` — CV-1 discipline is now a typed harness assertion rather than a log-file grep (same pattern aws-ssm adopted in v0.2.3).
- **Internal:** two new drift-catch regression-lock tests (`set_drift_catch_rejects_secret_leaking_to_argv` for CV-1, `get_drift_catch_env_check_rejects_wrong_vault_addr` for env-pathway) that prove the strict harness surfaces env drift loudly when it occurs.

### Added

- **`secretenv-testing`:** `Response::with_env_var(key, value)` and `Response::with_env_absent(key)` chainable methods for declaring per-rule env-var contracts. The generated POSIX shell uses `${KEY+set}` parameter expansion rather than `grep` so values with spaces, quotes, or regex metacharacters round-trip safely. Additive; `#[non_exhaustive]` policy honored. 6 new unit tests in `secretenv-testing::strict::tests` cover match / mismatch / key-absent / absence-violated / absence-satisfied / special-char-value.

### Fixed

- **None.** The retrofit surfaced no prod bugs in the vault backend — the PR #33 fix is correct and now has typed regression locks preventing its accidental reversal.

## [0.2.4]

**Headline:** internal test-infrastructure release — 1password backend's mock-CLI tests migrated to `StrictMock`. No user-facing CLI changes; no prod bugs surfaced.

### Changed

- **Internal:** all 13 mock-using tests in `secretenv-backend-1password` converted from the v0.2 raw `install_mock_op(body)` API to declarative `StrictMock::new("op").on(argv, Response).install(...)`. Every `op read`, `op item edit`, `op --version`, and `op whoami --format=json` argv is now asserted exactly (including the `--account <X>` tail when `op_account` is configured); a regression that drops `--account`, reorders `--vault`, or changes the `F=value` assignment shape will fail at test time rather than silently passing.
- **Internal:** `delete_runs_edit_with_empty_value` simplified — the args-log side-channel that verified the empty `F=` assignment is now obsolete because the declared argv token `F=` IS the assertion under strict match.
- **Internal:** two new drift-catch regression-lock tests (`get_drift_catch_rejects_missing_account_flag`, `set_drift_catch_rejects_missing_vault_flag`) that prove the strict harness surfaces drift loudly when it occurs.
- **Internal (one exception):** `get_non_utf8_response_errors_with_context` stays on the v0.2 raw `install_mock` harness because its assertion relies on a non-UTF-8 response, which the strict harness's `Response.stdout: String` cannot express. Documented inline; same carve-out as aws-ssm in v0.2.3.

### Fixed

- **None.** The retrofit surfaced no prod bugs in the 1password backend. Version-gating for the `set` stdin path (tracked in the backend's CV-1 comment) remains a v0.3 follow-up — not yet implemented, so no strict-mode coverage added for it.

## [0.2.3]

**Headline:** internal test-infrastructure release — aws-ssm backend's mock-CLI tests migrated to `StrictMock`. No user-facing CLI changes; no prod bugs surfaced.

### Changed

- **Internal:** all 14 mock-using tests in `secretenv-backend-aws-ssm` converted from the v0.2 raw `install_mock_aws(body)` API to declarative `StrictMock::new("aws").on(argv, Response).install(...)`. Every flag, positional, and value in every `aws` argv is now asserted exactly; a future refactor that drops `--with-decryption`, reorders `--region`/`--profile`, or reintroduces the CV-1 argv-leak regression will fail at test time rather than silently passing.
- **Internal:** `set_passes_secret_value_via_stdin_not_argv` rewritten using `Response::success_with_stdin`. CV-1 discipline is now a typed harness assertion rather than a log-file grep.
- **Internal:** two new drift-catch regression-lock tests (`get_drift_catch_rejects_missing_with_decryption_flag`, `set_drift_catch_rejects_secret_leaking_to_argv`) that prove the strict harness surfaces drift loudly when it occurs.
- **Internal (one exception):** `get_non_utf8_response_errors_with_context` stays on the v0.2 raw `install_mock` harness because its assertion relies on a non-UTF-8 response, which the strict harness's `Response.stdout: String` cannot express. Documented inline.

### Added

- **`secretenv-testing`:** `Response::with_stderr(stderr)` chainable method for expressing "response emits on stderr, not stdout." Additive; `#[non_exhaustive]` policy honored.

## [0.2.2]

**Headline:** internal test-infrastructure release — strict-mode mock harness for backend crates. No user-facing CLI changes.

### Added

- **`secretenv-testing::StrictMock`** — declarative mock-CLI builder.
  `StrictMock::new(bin).on(argv, Response).install(dir)` generates a
  POSIX shell script that matches the full joined argv against a rule
  list and exits 97 on no-match with a diagnostic naming the observed
  argv and every declared shape. Closes the gap that let the v0.2.0
  vault flag-order bug and aws-secrets leading-slash bug ship through
  `cargo test --workspace` green. `Response::success`,
  `Response::failure`, and `Response::success_with_stdin` (for testing
  the CV-1 stdin-delivery discipline) cover the response shapes
  backend tests need. Types are `#[non_exhaustive]` so future
  matchers (`PositionalThenFlags`, `Regex`, env-var assertions) can
  land additively as concrete backend retrofits need them.
- `crates/secretenv-cli/tests/e2e.rs` — two end-to-end scenarios
  proving `StrictMock` works in anger through the full secretenv call
  chain: one happy-path exercising exact argv match, one drift-catch
  asserting exit 97 surfaces a clear diagnostic naming the missing
  flag. These will serve as the reference pattern for the per-backend
  retrofits in v0.2.3 → v0.2.6.
- `secretenv-backend-local` crate-level doc note explaining why the
  v0.2.2 strict-mode retrofit covers it by documentation only — the
  backend does not shell out, so there is no argv surface to validate.

### Changed

- **Internal only:** strict-mode harness test infrastructure. No CLI
  behavior, URI grammar, or backend semantics changed. Users upgrading
  will see no difference.

## [0.2.1]

**Headline:** canonical `#key=value` fragment grammar. One deliberate pre-launch breaking change that locks the URI vocabulary before public eyes see the v0.2.0 shorthand form.

### Changed — BREAKING (pre-launch correction window)

- **Fragment grammar canonicalized.** URI fragments now must match
  `#key=value[,key=value]*` under a single grammar enforced by
  `BackendUri::fragment_directives()` in `secretenv-core`. Each backend
  declares the directive keys it recognizes; unknown keys error with
  the full URI and a list of recognized directives. See
  [`docs/fragment-vocabulary.md`](docs/fragment-vocabulary.md) for the
  grammar and the per-backend directive registry.
- **aws-secrets**: `#<field>` shorthand (v0.2.0) → `#json-key=<field>`
  canonical (v0.2.1). The shorthand is rejected at URI-parse time with
  a `ShorthandRejected` error that names the canonical replacement
  literally (e.g. `aws-secrets:///db#password` fails with a hint
  suggesting `aws-secrets:///db#json-key=password`). The backend
  recognizes only `json-key`; any other directive — alone or alongside
  `json-key` — surfaces as a single error listing every offender.

  This is the only deliberate breaking change permitted inside a 0.2.x
  patch. It was taken before public launch while the install base was
  zero (v0.2.0 tag was ~1 day old; Show HN not yet posted). Post-launch,
  0.x.y patches remain non-breaking per standard semver.

### Added

- `BackendUri::fragment_directives()` — typed accessor that parses
  the fragment body into a directive map per the canonical grammar.
  `FragmentError` (re-exported from `secretenv_core`) reports
  `ShorthandRejected`, `Malformed`, and `DuplicateKey` with enough
  context for a caller to produce a helpful user-facing message.
- Canonical grammar doc at `docs/fragment-vocabulary.md` (user-facing)
  and `kb/wiki/fragment-vocabulary.md` (project wiki). Both include
  the directive registry and the migration table for v0.2.0 shorthand
  URIs.

### Migration

| v0.2.0 (removed) | v0.2.1+ (canonical) |
|---|---|
| `aws-secrets-prod:///db-creds#password` | `aws-secrets-prod:///db-creds#json-key=password` |
| `aws-secrets-prod:///db-creds#host` | `aws-secrets-prod:///db-creds#json-key=host` |

If an error message in your logs mentions "legacy plain-string shorthand", rewrite the cited URI per the table above. No config or registry changes needed beyond the URI bodies.

## [0.2.0] - 2026-04-18

**Headline:** 2 new backends (Vault, AWS Secrets Manager), cascading registries, parallel secret fetch, shell completions, enriched `resolve` report, per-cascade-source doctor, shared `secretenv-testing` crate, and a 7-item security preflight. 13 PRs (#22–#34) from scaffolding to tag.

### Added

- **Shell completions.** New `secretenv completions <bash|zsh|fish>`
  subcommand emits a completion script generated from clap's command
  tree. Writes to `--output <path>` (chmod 0o644) or stdout. When
  stdout is a TTY, a shell-specific install hint is printed to
  stderr; when redirected (the usual `... > _secretenv` pipeline)
  stderr stays silent. PowerShell/Elvish deliberately omitted from
  v0.2 — no reason to carry the surface preemptively.
- **AWS Secrets Manager backend** (`type = "aws-secrets"`). Wraps the
  same `aws` CLI as `aws-ssm` — auth story is identical (every
  profile / SSO / IAM-role flow works unchanged). URI shape:
  `aws-secrets-<instance>:///<secret-id>[#<json-key>]`. First consumer
  of the `BackendUri.fragment` field added in Phase 0.5 RE-2:
  `#<json-key>` extracts a top-level field from a JSON-valued secret,
  coercing scalars (string/number/boolean/null) to strings and
  erroring on nested objects/arrays with the available field names
  listed so operators can correct the URI. `set` pipes through child
  stdin via `--secret-string file:///dev/stdin` (CV-1 discipline);
  `delete` is unconditionally `--force-delete-without-recovery` to
  keep semantics symmetric with aws-ssm/vault. Update-only — creating
  new secrets requires `aws secretsmanager create-secret` (deferred
  to v0.3 alongside `SecretBinary` + nested-field extraction). 26
  mock-CLI tests cover every row of the spec's harness table.
- `secretenv setup` routes `aws-secrets(-*)` schemes to the new
  backend type; `--region` + `--profile` flags apply to both AWS
  backends identically.
- **HashiCorp Vault backend** (`type = "vault"`). Wraps the `vault` CLI
  — every auth flow the CLI supports (`VAULT_TOKEN`, `AppRole`, OIDC,
  Kubernetes, AWS IAM) works transparently with no secretenv auth
  surface. URI shape: `vault-<instance>://<mount>/<path>`. Uses the
  unified `vault kv` CLI so KV v1 and KV v2 mounts work identically
  (the CLI handles `data/` segment injection for v2 internally). `get`
  uses `-field=value` for trim-one-newline single-value semantics;
  `set` pipes the secret through child stdin via `value=-` (CV-1
  discipline — the secret never appears on argv). Level 2 doctor
  check uses `vault token lookup` (vs `vault status` which succeeds
  with no token). Supports Vault Enterprise namespaces via optional
  `vault_namespace` config field — the `-namespace` flag is omitted
  when unset because open-source Vault rejects it. 25 mock-CLI tests
  cover every row of the spec's harness table.
- `secretenv setup` gains `--vault-address` and `--vault-namespace`
  flags. Scheme prefixes `vault` and `vault-*` map to the vault
  backend type.
- **Session-scoped registry cache.** New `secretenv_core::RegistryCache`
  memoizes `backend.list(source)` results by source URI for the life of
  a process. `resolve_registry` takes `&mut RegistryCache` and only
  issues a backend call on cache miss; subsequent references to the
  same source return a zero-I/O `Arc<CascadeLayer>`. Within a single
  `resolve_registry` call, the cache is warmed concurrently via
  `futures::future::join_all` so Phase 1's cascade parallelism is
  preserved. The cache holds alias-to-URI pointers only — secret
  values are never cached.
- **Registry cascades.** `[registries.<name>]` now accepts multiple
  `sources = [...]` entries. Lookup is first-match-wins from `sources[0]`
  downward; `sources[0]` remains the single write target for
  `registry set/unset`. All sources are fetched concurrently via
  `futures::future::join_all`; any source failure fails the whole
  resolve (silent fall-through would hide environment problems).
- `secretenv_core::CascadeLayer` public type exposing per-source
  `{source, map}` for future doctor/verbose reporting.
- `AliasMap::get` now returns `(target_uri, source_uri)` so callers can
  tell which cascade layer an alias was resolved from.
- `AliasMap::primary_source`, `layers`, `sources` accessors.
- `BackendUri.fragment: Option<String>` — parses the `#<fragment>` suffix
  of `scheme://path#fragment` URIs. Not yet consumed by any backend; v0.2
  Phase 6 (aws-secrets) will use it for `#json-key` extraction (RE-2).
- `secretenv_core::with_timeout` helper and `DEFAULT_GET_TIMEOUT` (30s) /
  `DEFAULT_CHECK_TIMEOUT` (10s) constants. Backend ops now have deadlines;
  `doctor` and `run` cannot hang indefinitely on a wedged CLI (CV-5).
- `BackendConfig.raw_fields` now preserves typed TOML values
  (`HashMap<String, toml::Value>` instead of `HashMap<String, String>`).
  Factories can read `as_str`, `as_integer`, `as_bool`, `as_array` — v0.2+
  backends get typed config fields without a later ABI break (RE-1).

### Changed

- **`secretenv doctor`** gains a `Registries` section that reports
  per-source reachability for every cascade source in `config.toml`.
  Each source line shows ✓/✗ + the source URI + a one-word suffix
  (`reachable` / `backend not authenticated` / `backend CLI 'x' missing`
  / `backend error`); non-OK sources render an indented `→ <hint>`
  with the actionable remediation. A single backend-instance status
  feeds every source that uses it (no duplicate `check()` calls).
  `--json` gains a top-level `registries: [{name, sources: [{uri,
  status, hint}]}]` key. `skip_serializing_if = "Vec::is_empty"`
  means consumers of the v0.1 doctor JSON shape see no new key when
  no registries are configured — backward-compatible.
- **`doctor` exit code still driven by backend-level summary only.**
  A backend failure already propagates to every source that uses it,
  so doubling the signal at the source level would double-count.
  Registry section is informational.
- **`secretenv resolve <alias>`** now emits a tabular metadata report
  instead of printing only the resolved URI. Rows: `alias`, `env var`
  (reverse-lookup from the manifest, `(none)` if unused),
  `resolved` (target backend URI), `source` (cascade layer URI + the
  layer index), and `backend` (one-line Level 2 status of the target
  backend instance — doubles as a lightweight pre-flight check). New
  `--json` flag emits the same data as structured JSON for editor /
  IDE consumers. Manifest loading is best-effort: a missing
  `secretenv.toml` no longer blocks resolve, it just sets `env_var`
  to `(none)`. Backend check failure does not fail resolve — the
  mapping is still printed so operators can debug auth separately.
- **`resolve_registry` signature.** Added a `cache: &mut RegistryCache`
  parameter. Callers must now construct a `RegistryCache::new()`
  (typically per command) and pass it through. Breaking change for
  anyone consuming `secretenv-core` as a library.
- **`AliasMap` internals.** Layers are now held as
  `Vec<Arc<CascadeLayer>>` instead of `Vec<CascadeLayer>`.
  `AliasMap::layers()` returns `&[Arc<CascadeLayer>]`. Enables
  shared-layer semantics between the cache and returned maps with
  zero deep clones.
- **Backend crate directories** renamed to match their published
  crate names: `crates/backends/backend-local` →
  `crates/backends/secretenv-backend-local` (and same for
  `aws-ssm`, `1password`). The v0.1 crates.io-prep rename deliberately
  left the directories unchanged; aligning them removes the
  path-vs-package-name inconsistency that was tripping readers. The
  CLI directory (`crates/secretenv-cli/`) stays as-is — it publishes
  as plain `secretenv` so `cargo install secretenv` lines up with the
  binary name.
- **Parallel secret fetch.** `runner::build_env` dispatches every
  alias-backed secret concurrently via `futures::future::join_all`
  instead of awaiting them one at a time. `Default`-sourced entries
  stay inline (zero I/O). Declaration order in the emitted env map is
  preserved regardless of backend completion order.
- **Multi-error aggregation.** When more than one alias fetch fails,
  the returned error now lists every failure in one message
  (`<N> secrets failed to resolve:` followed by one line per alias
  with env-var, URI, and upstream cause). Single-failure error shape
  is unchanged so operators with one broken alias see the same
  message as before (RE-7).
- `ResolvedSource::Uri` is now a struct variant `{ target, source }`
  instead of `Uri(BackendUri)`. The added `source` field carries the
  cascade layer URI the alias resolved from, for future `--verbose`
  and `doctor --extensive` surfacing.
- `registry set`/`unset` writes use `BTreeMap<String, String>` internally
  so alias output is alphabetically sorted and deterministic across
  runs — no more spurious diffs on every write (CV-4).
- `BackendFactory::create` signature: `config: &HashMap<String, toml::Value>`
  (was `config: HashMap<String, String>` by value). Borrowed config removes
  a per-load clone and matches core's borrowed-config convention (RE-5).
- `Manifest::find_upward` stops at project-root sentinels (`.git`, `.hg`,
  `.svn`, `.secretenv-root`). A hostile `secretenv.toml` dropped upstream
  of the user's project can no longer hijack alias resolution (CV-6).
  Falls back to v0.1 behavior when no sentinel exists anywhere.
- `--verbose` stderr output omits full URI paths — only env-var + backend
  instance name. Registry topology no longer leaks into CI build logs on
  `--verbose` runs (CV-7). Full URIs remain available under `--dry-run`.

### Fixed

- **AWS SSM `set`** pipes secret values via child-process stdin using
  `--value file:///dev/stdin`. The secret never appears on argv, closing
  the `/proc/<pid>/cmdline` local-user exposure window (CV-1 — critical).
- **1Password `set`** documents its remaining argv exposure with an
  inline comment + stderr warning on every call. Full stdin fix pending
  a v0.3 follow-up with `op` CLI version gating (CV-1 — partial).
- `BackendUri::parse` rejects invalid scheme characters (anything outside
  `[a-zA-Z0-9][a-zA-Z0-9_-]*`), NUL bytes in path/fragment, and ASCII
  control characters except tab. Warns on Unicode bidi-override codepoints
  without rejecting them (CV-3).
- `SECRETENV_REGISTRY` and `SECRETENV_CONFIG` scrubbed from the child
  process environment before `exec()`/`spawn`. CLI-layer config provenance
  no longer leaks to the child (SEC-1).

### Security

- Phase 0.5 security preflight complete. See
  `kb/wiki/reviews/pre-v0.2-review.md` for the three-reviewer audit that
  identified the above items, and `kb/wiki/build-plan-v0.2.md §Phase 0.5`
  for the subtask breakdown. Remaining audit items are addressed in the
  Phase 1+ feature work.

### Internal

- **Extracted `secretenv-testing` crate** (unpublished). The `install_mock`
  shell-script writer with its Linux ETXTBSY probe loop previously lived
  in three separate locations (`backend-aws-ssm/src/lib.rs`,
  `backend-1password/src/lib.rs`, `secretenv-cli/tests/e2e.rs`). All
  three now call into the shared crate. Public surface is
  `install_mock(dir, bin_name, body) -> PathBuf` plus thin
  `install_mock_aws` / `install_mock_op` wrappers. `publish = false`
  for v0.2 — revisit once Phase 5 (Vault) + Phase 6 (AWS Secrets
  Manager) have proven the API shape.
- v0.2 development baseline: branch `feat/v0.2-prep` opened, workspace bumped
  to 0.2.0, roadmap updated to reflect the Vault + AWS Secrets Manager
  dual-backend release.
- `tokio` promoted from dev-dep to runtime dep on `secretenv-core` (needed
  for `tokio::time::timeout` in the timeout wrapper). Workspace tokio
  features gain `"time"`.
- `tracing` added as a direct runtime dep on `secretenv-core` (bidi-override
  warning) and `secretenv-backend-1password` (argv-exposure warning).
- `toml` added as a direct runtime dep on `secretenv-backend-aws-ssm` (now
  references `toml::Value` in the factory signature).

## [0.1.1] - 2026-04-17

First public release of SecretEnv.

### Added

- Core CLI surface: `run`, `registry list/get/set/unset`, `setup`, `doctor`,
  `get`.
- Three backends: `local` (TOML file), `aws-ssm` (AWS Systems Manager
  Parameter Store via `aws` CLI), `1password` (1Password via `op` CLI).
- `secretenv.toml` manifest format with alias (`from = "secretenv://..."`)
  and default (`default = "..."`) secret declarations.
- `~/.config/secretenv/config.toml` machine-level configuration with
  `[registries.<name>] sources = [...]` and `[backends.<name>]` blocks.
- `secretenv://<alias>` URI scheme for aliases resolved against the
  registry; direct-scheme URIs (e.g. `aws-ssm-prod:///path`) for concrete
  backend references inside registry documents.
- `BackendRegistry` + `Backend` + `BackendFactory` plugin system; all
  backends compiled into a single binary (no compile-time feature flags).
- Level 1 (CLI present) + Level 2 (authenticated) doctor checks, with
  `--json` output for CI integration.
- `secretenv setup <registry-uri>` bootstrap with `--force`, `--skip-doctor`,
  and backend-specific flags (`--region`, `--profile`, `--account`).
- `install.sh` POSIX installer with `--profile <name>` distribution-profile
  support (downloads config from `https://secretenv.io/profiles/<name>.toml`
  by default; override via `SECRETENV_PROFILE_URL`).
- Homebrew tap at `TechAlchemistX/homebrew-secretenv`.
- Release workflow builds and publishes for `x86_64-unknown-linux-gnu`,
  `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`.

### Security

- Workspace-wide `unsafe_code = "forbid"`.
- Clippy `unwrap_used` / `expect_used` set to warn; CI denies warnings.
- Secret values wrapped in `zeroize::Zeroizing<String>` in the runner;
  `exec()` replaces the parent process, zeroing automatically on drop.
- No shell interpolation — every backend uses
  `tokio::process::Command::args([...])` with separate argv strings.
- `cargo deny check` + `cargo audit` gate every PR.
- Errors include alias + URI + instance name + trimmed backend stderr,
  never the secret value.

[Unreleased]: https://github.com/TechAlchemistX/secretenv/compare/v0.2.3...HEAD
[0.2.3]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.2.3
[0.2.2]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.2.2
[0.2.1]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.2.1
[0.2.0]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.2.0
[0.1.1]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.1.1
