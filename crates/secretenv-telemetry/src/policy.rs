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
    /// `secretenv.error.message`).
    DenyByDefault,
}

/// The canonical v0.14+ §6 ALLOW/DENY matrix as code.
///
/// Read-only at runtime; constructed via [`RedactionPolicy::default`].
/// v0.17's exporter validates every attribute name it serializes
/// against this table at startup; an unrecognized attribute is a
/// programming error (the typed builder should have prevented it).
#[derive(Debug, Clone)]
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
    ("secretenv.alias.uri", AttributeClassification::Deny),
    ("secretenv.alias.uri.raw", AttributeClassification::Deny),
    ("secretenv.alias.uri.path", AttributeClassification::Deny),
    // --- value (always DENY) ---
    ("secretenv.value", AttributeClassification::Deny),
    ("secretenv.value.length", AttributeClassification::Deny),
    ("secretenv.value.hash", AttributeClassification::Deny),
    // --- backend ---
    ("secretenv.backend.type", AttributeClassification::Allow),
    ("secretenv.backend.instance_name", AttributeClassification::Allow),
    ("secretenv.backend.address", AttributeClassification::Deny),
    ("secretenv.backend.account_id", AttributeClassification::Deny),
    ("secretenv.backend.region", AttributeClassification::Allow),
    ("secretenv.backend.cli.version", AttributeClassification::Allow),
    ("secretenv.backend.cli.name", AttributeClassification::Allow),
    ("secretenv.backend.cli.identity", AttributeClassification::Deny),
    ("secretenv.backend.auth_method", AttributeClassification::Allow),
    // --- error ---
    ("secretenv.error.kind", AttributeClassification::Allow),
    ("secretenv.error.message", AttributeClassification::DenyByDefault),
    ("secretenv.error.cli_stderr", AttributeClassification::Deny),
    // --- process ---
    ("secretenv.process.argv", AttributeClassification::Deny),
    ("secretenv.process.command_name", AttributeClassification::Allow),
    ("secretenv.process.env_var_count", AttributeClassification::Allow),
    // --- redact ---
    ("secretenv.redact.match_count", AttributeClassification::Allow),
    ("secretenv.redact.byte_count", AttributeClassification::Allow),
    ("secretenv.redact.alias_name", AttributeClassification::Allow),
    ("secretenv.redact.stream", AttributeClassification::Allow),
    ("secretenv.redact.source", AttributeClassification::Allow),
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
            p.classify("secretenv.error.message"),
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
