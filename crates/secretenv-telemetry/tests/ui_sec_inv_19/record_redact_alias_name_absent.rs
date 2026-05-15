// SPDX-License-Identifier: AGPL-3.0-only
//
// EXPECTED TO FAIL to compile.
//
// `SecretEnvSpan::record_redact_alias_name` was deliberately removed
// in v0.14 Phase 9 (Sec-B2) per SEC-INV-19. Adding it back to the
// public API surface is a security regression and must surface as a
// compile error here.

use secretenv_telemetry::SecretEnvSpan;

fn main() {
    let (mut span, _guard) = SecretEnvSpan::start("redact.match");
    span.record_redact_alias_name("stripe-key");
}
