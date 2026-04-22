# SecretEnv smoke-test harness

Live-backend integration smoke for `secretenv`. Provisions cloud-side fixtures
across all 7 supported backends, runs a 336-assertion validation matrix
against a release binary, then tears down what it created.

This is the gate run before every tagged release.

## What's here

```
scripts/smoke-test/
├── README.md            ← you are here
├── lib/
│   └── common.sh        ← shared env + path helpers (sourced by all scripts)
├── fixtures/
│   ├── local-secrets/   ← scalar secret values (non-real, safe to commit)
│   ├── local-registry/  ← alias→URI map; templated with @@RUNTIME_DIR@@
│   ├── config/          ← config.toml template; @@GCP_PROJECT@@/@@AZURE_VAULT@@
│   └── project-repo/    ← per-project secretenv.toml manifest
├── provision.sh         ← seed cloud fixtures + render local fixtures
├── run-tests.sh         ← the 336-assertion runner (selective via flags)
└── teardown.sh          ← remove cloud fixtures
```

## Prerequisites

You need authenticated CLIs for every backend the matrix touches:

| Backend         | CLI       | Notes                                                    |
|-----------------|-----------|----------------------------------------------------------|
| AWS SSM         | `aws`     | Region defaults to `us-east-1`                           |
| AWS Secrets Mgr | `aws`     | Same credentials as SSM                                  |
| 1Password       | `op`      | `op signin` — vault `Private` must exist                 |
| Vault           | `vault`   | Dev-mode server: `vault server -dev` (KV v2 mounted at `secret/`) |
| GCP Secret Mgr  | `gcloud`  | `gcloud auth application-default login`                  |
| Azure Key Vault | `az`      | `az login` + Key Vault Secrets Officer role on the vault |

Plus a Rust toolchain to build the release binary.

## Required env vars

```sh
export SECRETENV_TEST_GCP_PROJECT=your-gcp-project-id
export SECRETENV_TEST_AZURE_VAULT=your-azure-key-vault-name
```

Optional overrides:

```sh
export SECRETENV_TEST_AWS_REGION=us-east-1          # default
export SECRETENV_SMOKE_RUNTIME=/tmp/secretenv-test  # default
export SECRETENV_BIN=/path/to/secretenv             # default: <repo>/target/release/secretenv
```

## Quick start

```sh
# 1. build the release binary
cargo build --release

# 2. seed cloud + local fixtures (idempotent — safe to re-run)
./scripts/smoke-test/provision.sh

# 3. run the full matrix (~5 minutes wall-clock)
./scripts/smoke-test/run-tests.sh

# 4. tear down cloud fixtures when done
./scripts/smoke-test/teardown.sh
```

## Selective runs

The full matrix takes ~5 minutes and hits every cloud. For dev iteration you
usually want a subset.

```sh
# offline-only sections (no cloud CLIs required at all)
./scripts/smoke-test/run-tests.sh --local-only

# specific section numbers (supports comma-separated lists and ranges)
./scripts/smoke-test/run-tests.sh --sections 1,2,17-20

# what sections exist?
./scripts/smoke-test/run-tests.sh --list-sections
```

`--local-only` skips every section that needs a cloud CLI authenticated. Ideal
for: a contributor onboarding loop, a CI pre-check on every PR, or testing CLI
ergonomics changes that don't touch backend code.

`--sections N,M-P` runs the listed sections only — useful when iterating on a
specific surface (e.g. `--sections 17` while debugging registry history).

The full matrix remains the default and is the **only** mode that gates a
release tag.

## Section inventory

| #  | Cloud? | Coverage                                                  |
|----|--------|-----------------------------------------------------------|
| 1  | no     | Basic CLI surface (`--version`, `--help`)                 |
| 2  | yes    | `doctor` Level 1 + Level 2 across every backend           |
| 3  | yes    | `registry list` against every registry source             |
| 4  | yes    | `registry get` single-alias lookups                       |
| 5  | yes    | `resolve` metadata path                                   |
| 6  | yes    | `get` live fetch from every backend                       |
| 7  | yes    | `run` end-to-end exec with injected env                   |
| 8  | yes    | Cascade / multi-source registry                           |
| 9  | yes    | `--verbose` path-sanitization                             |
| 10 | yes    | Error paths (bogus registry, missing alias, bad URI)      |
| 11 | yes    | `registry set` / `unset` write path                       |
| 12 | no     | Shell completions                                         |
| 13 | yes    | v0.2.1 canonical fragment grammar                         |
| 14 | yes    | v0.2.6 cross-backend matrix                               |
| 15 | yes    | v0.3 Phase 1 — GCP Secret Manager                         |
| 16 | yes    | v0.3 Phase 2 — Azure Key Vault                            |
| 17 | yes    | v0.4 Phase 2a — `registry history`                        |
| 18 | no     | v0.4 Phase 2b — `registry invite` (offline)               |
| 19 | yes    | v0.4 Phase 1 — `doctor --fix` + `--extensive`             |
| 20 | no     | v0.4 Phase 3 — `timeout_secs` + `op_unsafe_set`           |

Run `./run-tests.sh --list-sections` for the live inventory.

## Output

Every test writes its own log under `$SECRETENV_SMOKE_RUNTIME/runs/`. The
summary appears at `runs/90-summary.log` and ends with `TESTS_DONE`.

The runner exits non-zero if any test failed.

## Troubleshooting

- **"secretenv binary not found"** — run `cargo build --release` from the repo
  root, or set `SECRETENV_BIN` to an explicit path.
- **"SECRETENV_TEST_GCP_PROJECT is not set"** — export the cloud env vars (see
  above). `--local-only` skips this requirement entirely.
- **AWS Secrets Manager `InvalidRequestException` on first run** — the fixture
  may be stuck in soft-deleted state from a previous run. Wait the recovery
  window or use `aws secretsmanager restore-secret` then re-run `provision.sh`.
- **1Password `op` session expired mid-run** — re-auth (`eval $(op signin)`)
  and re-run; `provision.sh` is idempotent.
