// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Declarative ALLOW/DENY classification of SecretEnv span
//! attributes, mirroring the v0.14+ synthesis §6 attribute matrix.
//!
//! The matrix is enforced **structurally** by [`crate::SecretEnvSpan`]
//! — there is no `set_attribute(&str, &str)` escape hatch in the
//! public API, so any DENY attribute is unreachable from a call
//! site by construction.
//!
//! [`RedactionPolicy`] exists as a *reference table* that v0.17's
//! attribute-emitter consults for sanity checks at exporter
//! startup; it also lets operators audit the matrix in code without
//! cross-referencing the synthesis doc.

/// Classification of a SecretEnv span attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeClassification {
    /// Attribute may be emitted.
    Allow,
    /// Attribute must NEVER be emitted.
    Deny,
    /// Attribute is allowed only under an explicit per-run opt-in
    /// flag (e.g. `--otel-include-error-detail` for
    /// `secretenv.backend.error.message`).
    DenyByDefault,
}

/// The canonical v0.14+ §6 ALLOW/DENY matrix as code.
///
/// Read-only at runtime; constructed via [`RedactionPolicy::default`].
/// v0.17's exporter validates every attribute name it serializes
/// against this table at startup; an unrecognized attribute is a
/// programming error (the typed builder should have prevented it).
#[derive(Debug, Clone, Copy)]
pub struct RedactionPolicy {
    entries: &'static [(&'static str, AttributeClassification)],
}

impl RedactionPolicy {
    /// The canonical policy. Matches the v0.14+ synthesis §6
    /// attribute matrix. Order is not significant.
    #[must_use]
    pub const fn canonical() -> Self {
        Self { entries: CANONICAL }
    }

    /// Look up an attribute name's classification, or `None` if it
    /// isn't in the matrix at all. `None` from a runtime emission
    /// path is a bug — every call site goes through the typed
    /// builder which only knows about ALLOW names.
    #[must_use]
    pub fn classify(&self, name: &str) -> Option<AttributeClassification> {
        self.entries.iter().find(|(k, _)| *k == name).map(|(_, c)| *c)
    }

    /// Iterate every (name, classification) pair. Useful for
    /// `cargo doc` rendering and for v0.17's exporter startup
    /// audit.
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, AttributeClassification)> + '_ {
        self.entries.iter().copied()
    }
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self::canonical()
    }
}

/// The matrix, transcribed from v0.14+ synthesis §6. New attribute
/// additions update **both** this table AND a method on
/// [`crate::SecretEnvSpan`]. Reviewers verify the two stay in sync.
const CANONICAL: &[(&str, AttributeClassification)] = &[
    // --- run-level ---
    ("secretenv.version", AttributeClassification::Allow),
    ("secretenv.run_id", AttributeClassification::Allow),
    ("secretenv.command", AttributeClassification::Allow),
    ("secretenv.exit_code", AttributeClassification::Allow),
    ("secretenv.duration_ms", AttributeClassification::Allow),
    // --- alias-level ---
    ("secretenv.alias.name", AttributeClassification::Allow),
    ("secretenv.alias.env_var", AttributeClassification::Allow),
    ("secretenv.alias.count", AttributeClassification::Allow),
    ("secretenv.alias.cascade_layer_index", AttributeClassification::Allow),
    ("secretenv.alias.outcome", AttributeClassification::Allow),
    // v0.17 Phase 9c — Sec F-3 residue. Spec §2.1 ALLOW (bool flag for
    // manifest-default vs registry-resolved aliases).
    ("secretenv.alias.is_default", AttributeClassification::Allow),
    ("secretenv.alias.uri", AttributeClassification::Deny),
    ("secretenv.alias.uri.raw", AttributeClassification::Deny),
    ("secretenv.alias.uri.path", AttributeClassification::Deny),
    // v0.17 Phase 9c — Sec F-3 residue. DENY per synthesis §9
    // specialist-disagreement resolution (security §5.2 wins over
    // otel §4; scheme + path together = topology fingerprint, and
    // `backend.instance_name` already covers the operational need).
    ("secretenv.alias.uri_scheme", AttributeClassification::Deny),
    // --- value (always DENY) ---
    ("secretenv.value", AttributeClassification::Deny),
    ("secretenv.value.length", AttributeClassification::Deny),
    ("secretenv.value.hash", AttributeClassification::Deny),
    // --- backend ---
    ("secretenv.backend.type", AttributeClassification::Allow),
    ("secretenv.backend.instance_name", AttributeClassification::Allow),
    ("secretenv.backend.address", AttributeClassification::Deny),
    ("secretenv.backend.account_id", AttributeClassification::Deny),
    // v0.17 Phase 9b — Sec F-3. Spec §2.3 lists DENY (Vault Enterprise
    // namespace + similar topology hints). No setter shipped; locked in
    // the matrix so a future ALLOW addition is caught.
    ("secretenv.backend.namespace", AttributeClassification::Deny),
    ("secretenv.backend.region", AttributeClassification::Allow),
    // Phase 9b — Sec F-3. Spec §2.3 ALLOW. Operator-stated label.
    ("secretenv.backend.profile_name", AttributeClassification::Allow),
    ("secretenv.backend.cli.version", AttributeClassification::Allow),
    ("secretenv.backend.cli.name", AttributeClassification::Allow),
    ("secretenv.backend.cli.identity", AttributeClassification::Deny),
    ("secretenv.backend.auth_method", AttributeClassification::Allow),
    // v0.17 Phase 9c — Sec F-3 residue. Spec §2.3 ALLOW (closed-enum
    // probe-level + probe-outcome attrs from the v0.16 doctor levels).
    ("secretenv.backend.probe.level", AttributeClassification::Allow),
    ("secretenv.backend.probe.outcome", AttributeClassification::Allow),
    // --- error ---
    // v0.17 Phase 7b — renamed from `secretenv.error.kind` to match
    // doc §2.3. No callers existed at the time of rename, so this is
    // a pure key-string change inside `SecretEnvSpan::record_error_kind`.
    ("secretenv.backend.error.kind", AttributeClassification::Allow),
    // v0.17 Phase 9c — names aligned to spec §2.3 (Phase 7b renamed
    // `error.kind` → `backend.error.kind` but missed these two siblings).
    ("secretenv.backend.error.message", AttributeClassification::DenyByDefault),
    ("secretenv.backend.error.cli_stderr", AttributeClassification::Deny),
    // --- process ---
    ("secretenv.process.argv", AttributeClassification::Deny),
    ("secretenv.process.command_name", AttributeClassification::Allow),
    ("secretenv.process.env_var_count", AttributeClassification::Allow),
    // --- run (v0.17 Phase 8b) ---
    // Top-level `secretenv.run` span attrs wired through new
    // `SecretEnvSpan::record_run_*` setters. ALLOW per
    // `docs/reference/opentelemetry.md` §2.5.
    ("secretenv.run.dry_run", AttributeClassification::Allow),
    ("secretenv.run.verbose", AttributeClassification::Allow),
    ("secretenv.run.command_name", AttributeClassification::Allow),
    ("secretenv.run.command_argv", AttributeClassification::Deny),
    ("secretenv.run.env_var_count", AttributeClassification::Allow),
    ("secretenv.run.env_var_value", AttributeClassification::Deny),
    ("secretenv.run.outcome", AttributeClassification::Allow),
    ("secretenv.run.failed_alias_count", AttributeClassification::Allow),
    // --- resolution + backend fetch (v0.17 Phase 8b) ---
    ("secretenv.resolution.outcome", AttributeClassification::Allow),
    ("secretenv.resolution.cache_hit", AttributeClassification::Allow),
    ("secretenv.resolution.attempt", AttributeClassification::Allow),
    ("secretenv.resolution.latency_ms", AttributeClassification::Allow),
    ("secretenv.backend.fetch.outcome", AttributeClassification::Allow),
    ("secretenv.backend.fetch.timeout_ms", AttributeClassification::Allow),
    ("secretenv.backend.fetch.attempt", AttributeClassification::Allow),
    ("secretenv.backend.fetch.duration_ms", AttributeClassification::Allow),
    // Registry identifier — operator-stated; ALLOW.
    ("secretenv.registry.name", AttributeClassification::Allow),
    // v0.17 Phase 9b — Sec F-3. Spec §2.4 entries the canonical
    // matrix was missing. `selection` is the closed-enum tag for
    // named-vs-direct-uri (NOT the URI itself). Source URI is DENY
    // for the same topology reason as alias.uri.
    ("secretenv.registry.selection", AttributeClassification::Allow),
    ("secretenv.registry.source_count", AttributeClassification::Allow),
    ("secretenv.registry.source_index", AttributeClassification::Allow),
    ("secretenv.registry.source_uri", AttributeClassification::Deny),
    // Phase 9b — Sec F-3. Spec §2.4 manifest entries. `path` is
    // relative-only by contract (absolute path = host filesystem leak,
    // see F-1 fix for the parallel command_name basename guard).
    ("secretenv.manifest.path", AttributeClassification::Allow),
    ("secretenv.manifest.alias_count", AttributeClassification::Allow),
    ("secretenv.manifest.default_count", AttributeClassification::Allow),
    // v0.18 Phase 4 — Arch-M6 subset. `manifest.outcome` is the
    // closed-enum result of `Manifest::load_from` (ok / not_found /
    // parse_error / validation_error).
    ("secretenv.manifest.outcome", AttributeClassification::Allow),
    // Phase 9b — Sec F-3. Spec §2.9 doctor aggregates.
    ("secretenv.doctor.check_level", AttributeClassification::Allow),
    ("secretenv.doctor.backend_count", AttributeClassification::Allow),
    ("secretenv.doctor.failure_count", AttributeClassification::Allow),
    // Phase 9b — Sec F-3. Spec §2.9 gen.password. Length + charset name
    // are ALLOW (operational); value + entropy_bits are DENY (the
    // entropy_bits is a partial length oracle).
    ("secretenv.gen.password.length", AttributeClassification::Allow),
    ("secretenv.gen.password.charset_name", AttributeClassification::Allow),
    ("secretenv.gen.password.value", AttributeClassification::Deny),
    ("secretenv.gen.password.entropy_bits", AttributeClassification::Deny),
    // --- redact ---
    ("secretenv.redact.match_count", AttributeClassification::Allow),
    ("secretenv.redact.byte_count", AttributeClassification::Allow),
    // SEC-INV-19 (v0.14 Phase 9 Sec-B2): alias name remains in the
    // operator-local terminal substitution token only. The OTel
    // emission must NOT carry it — alias names are sensitive enough
    // to belong off shared trace surfaces (the security council's
    // position overrode otel/concept-C's ALLOW vote per the
    // invariant ledger §9).
    ("secretenv.redact.alias_name", AttributeClassification::Deny),
    ("secretenv.redact.mode", AttributeClassification::Allow),
    ("secretenv.redact.stream", AttributeClassification::Allow),
    ("secretenv.redact.source", AttributeClassification::Allow),
    // v0.17 Phase 9c — Sec F-3 residue. Spec §2.6 ALLOW entries
    // (line + token + context attrs on redact event spans) +
    // DENY guard on matched_value (alongside the existing alias_name
    // DENY above; both are alias-or-value-shaped surfaces).
    ("secretenv.redact.line_number", AttributeClassification::Allow),
    ("secretenv.redact.replacement_token", AttributeClassification::Allow),
    ("secretenv.redact.match_context", AttributeClassification::Allow),
    ("secretenv.redact.matched_value", AttributeClassification::Deny),
    // --- migrate (v0.15) ---
    ("secretenv.migrate.phase", AttributeClassification::Allow),
    ("secretenv.migrate.outcome", AttributeClassification::Allow),
    // Backend TYPE only (e.g. `aws-ssm`, `vault`); INSTANCE name stays
    // DENY because instance names can carry environment hints
    // (`prod`, `staging`) that fingerprint operator infra topology.
    ("secretenv.migrate.source_backend_type", AttributeClassification::Allow),
    ("secretenv.migrate.dest_backend_type", AttributeClassification::Allow),
    ("secretenv.migrate.source_backend_instance", AttributeClassification::Deny),
    ("secretenv.migrate.dest_backend_instance", AttributeClassification::Deny),
    // Full URIs always DENY — they include backend path which leaks
    // operator-internal naming (e.g. `/prod/stripe-key`).
    ("secretenv.migrate.source_uri", AttributeClassification::Deny),
    ("secretenv.migrate.dest_uri", AttributeClassification::Deny),
    // The flag value (whether `--delete-source` was specified), NOT
    // the deletion outcome (which surfaces via migrate.outcome).
    ("secretenv.migrate.delete_source", AttributeClassification::Allow),
    ("secretenv.migrate.transaction_id", AttributeClassification::Allow),
    // v0.18 M-9. Forward-compat slot for the dual-control collapse
    // detection. Emitted as `false` in v0.18 (no backend currently
    // exposes an atomic cas_set surface); future collapse paths
    // flip the bit at the parent migrate span.
    ("secretenv.migrate.collapsed", AttributeClassification::Allow),
    // v0.17 Phase 9c — Sec F-3 residue. Spec §2.7 ALLOW (closed enum,
    // same shape as `migrate.phase`; identifies which phase failed
    // when migrate.outcome=partial-failure).
    ("secretenv.migrate.partial_failure_stage", AttributeClassification::Allow),
    // The migrated value itself NEVER appears on any attribute name —
    // these explicit DENY rows exist to fail-closed if a future call
    // site invents the name. `secretenv.value` above also catches
    // generic value-named leaks.
    ("secretenv.migrate.value", AttributeClassification::Deny),
    // Migrate spans use the generic `secretenv.alias.name` attribute
    // (a `record_alias_name` call on `SecretEnvSpan`), not a
    // migrate-scoped variant. The migrate-prefixed name stays DENY as
    // a fail-closed guard: if a future contributor invents it
    // thinking it's needed, this row + the SEC-INV-04 typed-builder
    // discipline reject the emission. (Doc §2.7 lists
    // `secretenv.migrate.alias_name` as ALLOW; that row of the
    // matrix is reserved-but-not-shipped in v0.17 — the active
    // setter is `record_alias_name`.)
    ("secretenv.migrate.alias_name", AttributeClassification::Deny),
    // --- mcp (v0.16+) ---
    //
    // Doc §2.8 ALLOW entries — captured here so the canonical table
    // is a complete enumeration of every MCP attribute the schema
    // names, even when the matching `SecretEnvSpan` setter has not
    // yet been added (the typed builder is the gatekeeper, the
    // policy table is the audit-facing manifest).
    ("secretenv.mcp.tool_name", AttributeClassification::Allow),
    ("secretenv.mcp.client_name", AttributeClassification::Allow),
    ("secretenv.mcp.client_version", AttributeClassification::Allow),
    ("secretenv.mcp.transport", AttributeClassification::Allow),
    ("secretenv.mcp.session_id", AttributeClassification::Allow),
    ("secretenv.mcp.outcome", AttributeClassification::Allow),
    ("secretenv.mcp.mutation_confirmed", AttributeClassification::Allow),
    ("secretenv.mcp.argument_alias_name", AttributeClassification::Allow),
    // Doc §2.8 DENY entries. `argument_uri` reveals backend topology;
    // `argument_reason` is the operator-typed elicitation rationale
    // (prompt-injection vehicle, audit-log only per SEC-INV-12);
    // `resolved_value` and `tool.output_raw` are secret values.
    ("secretenv.mcp.argument_uri", AttributeClassification::Deny),
    ("secretenv.mcp.argument_reason", AttributeClassification::Deny),
    ("secretenv.mcp.resolved_value", AttributeClassification::Deny),
    ("secretenv.mcp.tool.output_raw", AttributeClassification::Deny),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_classifies_every_documented_name() {
        let p = RedactionPolicy::canonical();
        assert_eq!(p.classify("secretenv.run_id"), Some(AttributeClassification::Allow));
        assert_eq!(p.classify("secretenv.value"), Some(AttributeClassification::Deny));
        assert_eq!(
            p.classify("secretenv.backend.error.message"),
            Some(AttributeClassification::DenyByDefault),
        );
        assert_eq!(p.classify("does.not.exist"), None);
    }

    #[test]
    fn no_value_attribute_is_allow() {
        // Structural sanity: every entry containing the substring
        // "value" must be DENY. A drift would mean the matrix has
        // grown a new value-leaking attribute that didn't get
        // properly classified.
        for (name, c) in RedactionPolicy::canonical().iter() {
            if name.contains("value") || name.contains("argv") || name.contains("uri") {
                assert!(
                    matches!(c, AttributeClassification::Deny),
                    "attribute '{name}' looks value-shaped but is not DENY",
                );
            }
        }
    }
}
