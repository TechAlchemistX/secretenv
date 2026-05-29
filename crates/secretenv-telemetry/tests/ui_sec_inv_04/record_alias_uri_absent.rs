// SPDX-License-Identifier: AGPL-3.0-only
//
// EXPECTED TO FAIL to compile.
//
// `secretenv.alias.uri` and every `uri.*` variant are DENY for OTel
// emission per `docs/reference/opentelemetry.md` §2.2 — they reveal
// backend topology. The `SecretEnvSpan` typed builder must NEVER
// expose a setter for them. This compile-fail fixture asserts the
// canonical four absent setter names; trybuild rejects compilation.

use secretenv_telemetry::SecretEnvSpan;

fn main() {
    let (mut span, _guard) = SecretEnvSpan::start("resolve.alias");
    span.record_alias_uri("aws-ssm:///payments/stripe");
    span.record_alias_uri_raw("aws-ssm:///payments/stripe");
    span.record_alias_uri_path("/payments/stripe");
    span.record_alias_uri_scheme("aws-ssm");
}
