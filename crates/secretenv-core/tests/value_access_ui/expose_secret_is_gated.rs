// SPDX-License-Identifier: AGPL-3.0-only
//
// EXPECTED TO FAIL to compile.
// `Secret::expose_secret` is cfg-gated behind `not(feature = "mcp-safe")`
// and must not exist on the public API surface when the feature is on.

use secretenv_core::Secret;

fn main() {
    let s = Secret::new(String::from("oops"));
    let _leak: &str = s.expose_secret();
}
