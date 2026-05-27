// SPDX-License-Identifier: AGPL-3.0-only
//
// EXPECTED TO FAIL to compile.
//
// SEC-INV-04: the `SecretEnvSpan` typed builder must never expose a
// generic `set_attribute(&str, &str)` (or `set_attribute(&str, impl
// Into<Value>)`) escape hatch. Every attribute must go through a
// typed `record_*` method, so adding a new attribute is a code-review
// event by construction. This fixture asserts the absence of any
// such generic setter.

use secretenv_telemetry::SecretEnvSpan;

fn main() {
    let (mut span, _guard) = SecretEnvSpan::start("resolve.alias");
    // Three plausible escape-hatch shapes. None must exist.
    span.set_attribute("any.key", "any.value");
    span.set_attribute_str("any.key", "any.value");
    span.add_attribute("any.key", 42);
}
