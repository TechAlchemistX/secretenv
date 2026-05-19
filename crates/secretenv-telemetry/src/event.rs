// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured event emitted by the redact module on each match
//! (mode A) or post-hoc scrub completion (mode B).
//!
//! **Critical invariant:** [`RedactionEvent`] NEVER carries the
//! matched value, its length, or its position. Only the count, the
//! byte count, the stream identity, and the source mode. v0.14's
//! `secretenv-telemetry` documents this constraint; v0.17's
//! `tracing-opentelemetry` exporter consumes events through the
//! [`crate::RedactionSink`] trait.

/// Which child-process stream a redaction match originated from
/// (mode A) or which file class produced the post-hoc scrub
/// (mode B).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RedactionStream {
    /// Child process `stdout`.
    Stdout,
    /// Child process `stderr`.
    Stderr,
    /// Post-hoc file scrub (mode B); the stream is whatever the
    /// caller redirected redact's output to.
    File,
}

impl RedactionStream {
    /// Stable kebab-case attribute value.
    #[must_use]
    pub const fn as_attribute_value(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
            Self::File => "file",
        }
    }
}

/// Which redact mode raised the event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RedactionSource {
    /// Mode A — runtime child-process stdout/stderr filter.
    ModeA,
    /// Mode B — `secretenv redact <path>` post-hoc scrub.
    ModeB,
}

impl RedactionSource {
    /// Stable kebab-case attribute value.
    #[must_use]
    pub const fn as_attribute_value(self) -> &'static str {
        match self {
            Self::ModeA => "mode-a",
            Self::ModeB => "mode-b",
        }
    }
}

/// A single redaction event.
///
/// In mode A, one event fires per match (Hook 1 in
/// [[v0.14-plus/specialist-otel]] §9). In mode B, one event fires
/// per file at completion (Hook 2/3) plus aggregate counts.
///
/// **DENY:** the matched bytes themselves; the position offset; the
/// alias-to-byte mapping; the host file path beyond what is already
/// in the calling span's command attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionEvent {
    /// How many distinct match occurrences this event represents.
    /// Per-match events use `count = 1`; aggregate events sum.
    pub count: u64,
    /// Total bytes replaced across this event's matches. ALLOW per
    /// synthesis §6 (`secretenv.redact.byte_count`).
    pub byte_count: u64,
    /// Which stream produced the match.
    pub stream: RedactionStream,
    /// Which redact mode raised the event.
    pub source: RedactionSource,
    /// Alias name whose value was matched.
    ///
    /// **DENY for OTel attribute emission** per SEC-INV-19 (v0.14
    /// Phase 9 Sec-B2). This field exists so the redact engine can
    /// render the operator-local terminal substitution token
    /// (`[redacted:<alias>]`); it must NOT cross into a
    /// `secretenv.redact.alias_name` OTel attribute. v0.17's OTel
    /// sink consumes the count/byte_count/stream/source fields only;
    /// any future sink that needs the alias does so for terminal
    /// rendering only.
    ///
    /// `None` when an aggregate event covers multiple aliases.
    pub alias_name: Option<String>,
}

impl RedactionEvent {
    /// Per-match constructor. `count = 1`, alias known.
    #[must_use]
    pub const fn per_match(
        byte_count: u64,
        stream: RedactionStream,
        source: RedactionSource,
        alias_name: String,
    ) -> Self {
        Self { count: 1, byte_count, stream, source, alias_name: Some(alias_name) }
    }

    /// Mode B post-hoc aggregate constructor. Multi-alias.
    #[must_use]
    pub const fn aggregate_mode_b(count: u64, byte_count: u64) -> Self {
        Self {
            count,
            byte_count,
            stream: RedactionStream::File,
            source: RedactionSource::ModeB,
            alias_name: None,
        }
    }

    /// Projection of this event safe to emit on a non-operator-terminal
    /// destination — i.e. anywhere `alias_name` could land outside the
    /// operator's terminal (OTel span attributes, structured log
    /// pipelines, shared trace surfaces, etc.).
    ///
    /// **v0.14.x DiD chip L4.** Strips [`Self::alias_name`] (DENY per
    /// SEC-INV-19) by setting it to `None`. The remaining fields
    /// (`count`, `byte_count`, `stream`, `source`) are ALLOW per the
    /// v0.14+ §6 attribute matrix.
    ///
    /// `RedactionSink` impls that emit to non-terminal destinations
    /// **MUST** use this projection. Terminal-rendering sinks that
    /// produce the `[redacted:<alias>]` substitution token render
    /// `alias_name` directly from the original event and may skip
    /// this projection; their output never reaches the OTel adapter.
    #[must_use]
    pub const fn for_otel(&self) -> Self {
        Self {
            count: self.count,
            byte_count: self.byte_count,
            stream: self.stream,
            source: self.source,
            alias_name: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn for_otel_strips_alias_name() {
        let evt = RedactionEvent::per_match(
            14,
            RedactionStream::Stdout,
            RedactionSource::ModeA,
            "stripe-key".to_owned(),
        );
        assert_eq!(evt.alias_name.as_deref(), Some("stripe-key"));

        let projected = evt.for_otel();
        assert_eq!(projected.alias_name, None, "for_otel() must drop alias_name");
        assert_eq!(projected.count, evt.count);
        assert_eq!(projected.byte_count, evt.byte_count);
        assert_eq!(projected.stream, evt.stream);
        assert_eq!(projected.source, evt.source);
    }

    #[test]
    fn for_otel_is_idempotent_when_alias_already_none() {
        let evt = RedactionEvent::aggregate_mode_b(3, 42);
        assert_eq!(evt.alias_name, None);
        let projected = evt.for_otel();
        assert_eq!(projected, evt);
    }
}
