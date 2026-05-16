// SPDX-License-Identifier: AGPL-3.0-only
//
// EXPECTED TO FAIL to compile.
// `EnvEntry::value` is cfg-gated behind `not(feature = "mcp-safe")`
// per Phase 7 security audit B1: the accessor was a public exfil
// path for resolved secret values that bypassed `Secret::expose_secret`.
// Reach via the runner module path if absolutely needed (still gated
// at the source-level cfg).

use secretenv_core::runner::EnvEntry;

fn leak(e: &EnvEntry) -> &str {
    e.value()
}

fn main() {
    let _ = leak;
}
