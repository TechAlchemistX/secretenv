// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Streaming scrubber for redact mode A (runtime stdout/stderr
//! filter). Maintains a tail-window of size `max(pattern_len)-1`
//! across chunk boundaries so a pattern split across chunks still
//! matches.
//!
//! # Buffering invariant
//!
//! On every call to [`StreamingScrubber::push`]:
//!
//! 1. The new chunk is appended to the carry-over tail from the
//!    previous chunk.
//! 2. Aho-Corasick runs over the combined buffer.
//! 3. Pre-match + substitution bytes are written to the output, up
//!    to a point that leaves at least `max_pattern_len - 1` bytes
//!    in the tail. Those bytes might be the prefix of a match that
//!    completes in the next chunk.
//! 4. The remaining tail (`max_pattern_len - 1` bytes) is retained
//!    for the next [`push`] call.
//!
//! [`StreamingScrubber::flush`] drains the tail at end-of-stream.
//!
//! # Tail-window cap
//!
//! Patterns larger than [`MODE_A_TAIL_WINDOW`](super::MODE_A_TAIL_WINDOW)
//! make the carry-over window pathological. [`StreamingScrubber::new`]
//! refuses at construction time with a clear error.

use std::io::Write;

use anyhow::{anyhow, Context, Result};

use super::{ScrubReport, Scrubber, SubstitutionToken, TaintedSet, MODE_A_TAIL_WINDOW};

/// Streaming scrubber. Build once with [`StreamingScrubber::new`],
/// call [`push`] for each chunk read from the child's stdout/stderr,
/// finally [`flush`] to drain the tail.
pub struct StreamingScrubber {
    scrubber: Scrubber,
    /// Carry-over tail from the previous chunk. Length is bounded
    /// by `max_pattern_len - 1`.
    carry: Vec<u8>,
    /// Maximum pattern length. Cached at construction.
    max_pattern_len: usize,
}

impl std::fmt::Debug for StreamingScrubber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `Scrubber`'s internals carry an `AhoCorasick` automaton
        // (no useful Debug); we summarize the streaming state and
        // mark the formatter non-exhaustive.
        f.debug_struct("StreamingScrubber")
            .field("carry_len", &self.carry.len())
            .field("max_pattern_len", &self.max_pattern_len)
            .finish_non_exhaustive()
    }
}

impl StreamingScrubber {
    /// Construct a streaming scrubber. Returns `Ok(None)` when the
    /// set is empty (caller can skip redaction entirely). Returns
    /// `Err` when any pattern is larger than [`MODE_A_TAIL_WINDOW`].
    ///
    /// # Errors
    /// Returns an error when the underlying [`Scrubber`] cannot be
    /// built, or when any pattern is larger than the tail-window cap.
    pub fn new(set: &TaintedSet, token: SubstitutionToken) -> Result<Option<Self>> {
        let max_pattern_len = set.iter().map(|v| v.bytes.len()).max().unwrap_or(0);
        if max_pattern_len > MODE_A_TAIL_WINDOW {
            return Err(anyhow!(
                "redact mode A: a tainted value exceeds the {MODE_A_TAIL_WINDOW}-byte \
                 tail-window cap; refusing to start runtime redaction (would otherwise \
                 miss matches split across chunk boundaries)",
            ));
        }
        let Some(scrubber) = Scrubber::new(set, token)? else {
            return Ok(None);
        };
        Ok(Some(Self { scrubber, carry: Vec::with_capacity(max_pattern_len), max_pattern_len }))
    }

    /// Append `chunk` to the buffer, scan, and emit pre-match +
    /// substitution bytes to `out`. Returns the partial scrub
    /// report covering this chunk's matches.
    ///
    /// # Errors
    /// Returns an error on any write to `out`.
    pub fn push<W: Write>(&mut self, chunk: &[u8], out: &mut W) -> Result<ScrubReport> {
        self.carry.extend_from_slice(chunk);

        // We retain `max_pattern_len - 1` bytes at the end for the
        // next push call so a pattern straddling the boundary still
        // matches. Anything before that point is safe to scan and
        // emit.
        let retain = self.max_pattern_len.saturating_sub(1);
        let scannable_len = self.carry.len().saturating_sub(retain);
        if scannable_len == 0 {
            return Ok(ScrubReport::zero());
        }

        // Scan over `&self.carry[..scannable_len + retain]` so a
        // match starting in the scannable region can still complete
        // anywhere in the carry; only emit replacements whose match
        // starts before `scannable_len`.
        let mut emitted_up_to: usize = 0;
        let mut report = ScrubReport::zero();
        let combined = &self.carry[..];
        for mat in self.scrubber.ac().find_iter(combined) {
            if mat.start() >= scannable_len {
                // Match starts in the retention window — defer to
                // the next push so we never partially-render across
                // a boundary.
                break;
            }
            if mat.start() > emitted_up_to {
                out.write_all(&combined[emitted_up_to..mat.start()])
                    .context("redact stream: writing pre-match bytes")?;
            }
            let pat_id = mat.pattern().as_usize();
            let alias = self.scrubber.alias_for(pat_id);
            let token_bytes = self.scrubber.token().render(alias);
            out.write_all(&token_bytes).context("redact stream: writing substitution")?;
            emitted_up_to = mat.end();
            report.match_count += 1;
            report.byte_count += self.scrubber.pattern_len(pat_id) as u64;
        }

        // Emit pre-tail bytes (any unmatched bytes preceding the
        // retention window).
        if emitted_up_to < scannable_len {
            out.write_all(&combined[emitted_up_to..scannable_len])
                .context("redact stream: writing pre-tail bytes")?;
            emitted_up_to = scannable_len;
        }

        // Compact the carry: drop the bytes we've emitted, retain
        // the tail.
        self.carry.drain(..emitted_up_to);
        Ok(report)
    }

    /// Drain the carry-over tail at end-of-stream. Any remaining
    /// matches fire here; otherwise the residue is emitted verbatim.
    ///
    /// # Errors
    /// Returns an error on any write to `out`.
    pub fn flush<W: Write>(&mut self, out: &mut W) -> Result<ScrubReport> {
        if self.carry.is_empty() {
            return Ok(ScrubReport::zero());
        }
        let rep = self.scrubber.scrub_bytes(&self.carry, out)?;
        self.carry.clear();
        Ok(rep)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::redact::TaintedValue;

    fn set_of(values: &[(&str, &str)]) -> TaintedSet {
        let mut set = TaintedSet::new();
        for (alias, val) in values {
            set.insert(TaintedValue::from_alias(*alias, *val));
        }
        set
    }

    #[test]
    fn streaming_matches_within_single_chunk() {
        let set = set_of(&[("api", "sk_live_abc123")]);
        let mut ss = StreamingScrubber::new(&set, SubstitutionToken::AliasAware).unwrap().unwrap();
        let mut out = Vec::new();
        let _ = ss.push(b"prefix sk_live_abc123 suffix\n", &mut out).unwrap();
        let _ = ss.flush(&mut out).unwrap();
        assert_eq!(out, b"prefix [redacted:api] suffix\n");
    }

    #[test]
    fn streaming_matches_across_chunk_boundary() {
        let set = set_of(&[("k", "sk_live_abc123")]);
        let mut ss = StreamingScrubber::new(&set, SubstitutionToken::AliasAware).unwrap().unwrap();
        let mut out = Vec::new();
        // Split the match in half: first chunk ends with "sk_live_"
        // (which is shorter than the tail window so will be carried).
        let _ = ss.push(b"start sk_live_", &mut out).unwrap();
        let _ = ss.push(b"abc123 end", &mut out).unwrap();
        let _ = ss.flush(&mut out).unwrap();
        assert_eq!(out, b"start [redacted:k] end");
    }

    #[test]
    fn streaming_flush_emits_unmatched_tail() {
        let set = set_of(&[("k", "sk_live_abc123")]);
        let mut ss = StreamingScrubber::new(&set, SubstitutionToken::AliasAware).unwrap().unwrap();
        let mut out = Vec::new();
        let _ = ss.push(b"hello", &mut out).unwrap();
        let _ = ss.flush(&mut out).unwrap();
        assert_eq!(out, b"hello");
    }

    #[test]
    fn streaming_refuses_oversize_pattern() {
        let mut set = TaintedSet::new();
        let big_value = "x".repeat(MODE_A_TAIL_WINDOW + 1);
        set.insert(TaintedValue::from_alias("big", big_value));
        let err = StreamingScrubber::new(&set, SubstitutionToken::AliasAware).unwrap_err();
        assert!(format!("{err:#}").contains("tail-window cap"));
    }

    /// v0.14.x code-hygiene: boundary at `pattern_len == MODE_A_TAIL_WINDOW`
    /// is the LARGEST accepted pattern. Previously only the strictly-greater
    /// rejection case was tested; this case exercised the `>` (not `>=`)
    /// in the bounds check at stream.rs:71.
    #[test]
    fn streaming_accepts_pattern_at_exact_tail_window() {
        let mut set = TaintedSet::new();
        let exact_value = "x".repeat(MODE_A_TAIL_WINDOW);
        set.insert(TaintedValue::from_alias("exact", exact_value));
        let res = StreamingScrubber::new(&set, SubstitutionToken::AliasAware);
        assert!(res.is_ok(), "MODE_A_TAIL_WINDOW-sized pattern must be accepted");
        assert!(res.unwrap().is_some(), "non-empty set must yield Some(StreamingScrubber)");
    }

    #[test]
    fn streaming_aggregates_match_count_across_chunks() {
        let set = set_of(&[("k", "sk_live_abc123")]);
        let mut ss = StreamingScrubber::new(&set, SubstitutionToken::AliasAware).unwrap().unwrap();
        let mut out = Vec::new();
        let mut total = ScrubReport::zero();
        total = total + ss.push(b"a sk_live_abc123 b ", &mut out).unwrap();
        total = total + ss.push(b"c sk_live_abc123 d", &mut out).unwrap();
        total = total + ss.flush(&mut out).unwrap();
        assert_eq!(total.match_count, 2);
    }
}
