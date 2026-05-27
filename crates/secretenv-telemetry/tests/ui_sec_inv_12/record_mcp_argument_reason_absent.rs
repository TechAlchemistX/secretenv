// SPDX-License-Identifier: AGPL-3.0-only
//
// EXPECTED TO FAIL to compile.
//
// `secretenv.mcp.argument_reason`, `secretenv.mcp.resolved_value`,
// and `secretenv.mcp.tool.output_raw` are DENY per
// `docs/reference/opentelemetry.md` §2.8:
//
// - `argument_reason` is a prompt-injection vehicle (operator-typed
//   free text from the MCP elicitation prompt); it lives in the
//   append-only audit log only, never on OTel attributes
//   (SEC-INV-12).
// - `resolved_value` and `tool.output_raw` are secret values.
//
// The `SecretEnvSpan` typed builder must never expose a setter for
// any of them. This compile-fail fixture asserts all three; trybuild
// rejects compilation if any contributor reintroduces them.

use secretenv_telemetry::SecretEnvSpan;

fn main() {
    let (mut span, _guard) = SecretEnvSpan::start("mcp.tool.set_alias");
    span.record_mcp_argument_reason("operator rationale string");
    span.record_mcp_resolved_value("sk_live_abc123...");
    span.record_mcp_tool_output_raw("{\"value\":\"sk_live_abc123\"}");
}
