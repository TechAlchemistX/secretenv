// SPDX-License-Identifier: AGPL-3.0-only
//
// EXPECTED TO FAIL to compile.
// `secretenv_core::build_env` is cfg-gated behind `not(feature =
// "mcp-safe")` per Phase 7 security audit findings B1 + H4 — the
// `build_env`/`EnvEntry::value` pair bypassed `Secret::expose_secret`
// gating in v0.14 pre-fix. mcp-safe consumers must reach build_env
// (if they need it at all) via `secretenv_core::runner::build_env`,
// where it is still public but only buildable inside the crate
// graph.

fn main() {
    let _ = secretenv_core::build_env;
}
