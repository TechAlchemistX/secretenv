// SPDX-License-Identifier: AGPL-3.0-only
//
// EXPECTED TO FAIL to compile.
// The crate-root `pub use Backend` is cfg-gated behind
// `not(feature = "mcp-safe")`; mcp-safe consumers must reach
// `secretenv_core::backend::Backend` via the module path.

fn main() {
    fn _wants_backend<T: secretenv_core::Backend>() {}
}
