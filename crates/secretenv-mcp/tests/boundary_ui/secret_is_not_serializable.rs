// SPDX-License-Identifier: AGPL-3.0-only
//
// EXPECTED TO FAIL to compile.
//
// SEC-INV-02 structural guarantee: a `secretenv_core::Secret<T>` must
// not implement `serde::Serialize`. Every tool response struct in
// `secretenv-mcp` is serialized via `rmcp::handler::server::wrapper::Json`
// which requires `Serialize` — so if a response struct ever embedded
// (or transitively reached) a `Secret`, the closure would also
// require `Secret: Serialize`. This fixture proves that bound is
// unsatisfiable today; the day someone adds `#[derive(Serialize)]`
// to `Secret`, this test starts compiling and the trybuild runner
// in `tests/secret_not_serializable.rs` fails loudly.

use secretenv_core::Secret;

fn requires_serialize<T: serde::Serialize>(_: T) {}

fn main() {
    let s: Secret<String> = Secret::new(String::from("never reached"));
    requires_serialize(s);
}
