// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! [`RedactionSink`] — the trait the redact module emits
//! [`RedactionEvent`](crate::RedactionEvent)s through.
//!
//! v0.14 ships [`NoopRedactionSink`] only. v0.17's OTel impl
//! consumes the same trait without restructuring redact call
//! sites.

use crate::RedactionEvent;

/// Consumer for [`RedactionEvent`]s.
///
/// Implementations must be `Send + Sync` so the redact module's
/// concurrent emission path (Aho-Corasick scanner across pipe-based
/// child stdout/stderr) can share a single sink across threads
/// without extra wrapping.
pub trait RedactionSink: Send + Sync {
    /// Receive an event. Implementations should be allocation-light
    /// — the redact hot path fires this once per match.
    fn record(&self, event: &RedactionEvent);
}

/// No-op sink. The default at v0.14; replaced by an OTel-backed
/// impl in v0.17 via runtime configuration.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopRedactionSink;

impl RedactionSink for NoopRedactionSink {
    fn record(&self, _event: &RedactionEvent) {
        // Intentionally empty. v0.17 wires an OTel-backed impl.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RedactionSource, RedactionStream};

    #[test]
    fn noop_sink_accepts_events_without_panic() {
        let sink = NoopRedactionSink;
        let evt = RedactionEvent::per_match(
            12,
            RedactionStream::Stdout,
            RedactionSource::ModeA,
            "stripe-key".to_owned(),
        );
        sink.record(&evt);
    }
}
