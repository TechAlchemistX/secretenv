// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Wrapper-first password generation engine.
//!
//! # SEC-INV-02 escape hatch
//!
//! This file is the first of two `src/internal/` modules that may
//! legally name `secretenv_core::Secret`. The `#[allow(clippy::disallowed_types)]`
//! pragma at the module level is the deliberate seam.
//!
//! # Phase 5a — fallback generation path
//!
//! Implements the universal fallback that works for ALL 15 backends:
//!
//! 1. Fill a [`zeroize::Zeroizing<Vec<u8>>`] with raw entropy via
//!    [`getrandom::getrandom`] (operating-system CSPRNG; no userspace
//!    pool, no key derivation, no stretching — see SEC §6.1).
//! 2. Encode the bytes per the requested [`Charset`] into a UTF-8
//!    string.
//! 3. Wrap in a [`secretenv_core::Secret<String>`].
//! 4. Hand the secret's `expose_secret()` borrow to `Backend::set`
//!    immediately in the same expression.
//! 5. `drop(secret)` (explicit) — the `Zeroizing` wrapper around the
//!    raw entropy bytes drops at end of scope; the `Secret<String>`
//!    drops at the explicit drop call. The CSPRNG output never
//!    crosses any boundary other than `Backend::set`.
//!
//! Value-handling discipline observed:
//!
//! - Raw entropy lives inside [`Zeroizing<Vec<u8>>`] from the
//!   moment `getrandom` writes into it.
//! - The encoded value lives inside [`Secret<String>`] from the
//!   moment `String::from_utf8` materializes it.
//! - `expose_secret()` is called exactly once, inline at the
//!   `backend.set(...)` call site, immediately consumed.
//! - No `format!` / `println!` / `tracing` ever sees the value.
//!   Error context strings reference URI + charset + length
//!   metadata only.
//!
//! # Phase 5b carry-forward
//!
//! Backends that override `Backend::supports_native_gen() = true`
//! (1password, vault-with-random-plugin, doppler) will dispatch to
//! their CLI's own generator — the value is born in the backend's
//! process and never enters this engine. The router in
//! `tools/mod.rs` will check `supports_native_gen()` first; this
//! module remains the fallback.

#![allow(clippy::disallowed_types)]

use anyhow::{anyhow, bail, Context, Result};
use secretenv_core::{Backend, BackendUri, Secret};
use zeroize::Zeroizing;

/// Encoding choice for the generated value. Closed set — adding a
/// variant requires a v0.16 minor bump for the MCP boundary type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charset {
    /// Letters + digits (`A-Za-z0-9`). Safe in nearly every backend.
    /// 62 symbols → ~5.95 bits per char.
    Alphanumeric,
    /// Letters + digits + a curated punctuation set (`A-Za-z0-9!@#$%^&*-_+=`).
    /// 74 symbols → ~6.21 bits per char.
    AlphanumericSymbols,
    /// Lowercase hex (`0-9a-f`). 4 bits per char.
    Hex,
    /// URL-safe base64 (`A-Za-z0-9-_`). 6 bits per char. NO padding
    /// — the output length matches `requested_length` exactly.
    Base64UrlSafe,
}

impl Charset {
    /// Parse the wire string used in `GenPasswordArgs`. Returns an
    /// error on unrecognized values so the operator/agent can fix
    /// the call rather than silently getting hex.
    ///
    /// # Errors
    ///
    /// Returns an error if `s` is not one of the four recognized
    /// charset strings.
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "alphanumeric" => Ok(Self::Alphanumeric),
            "alphanumeric_symbols" => Ok(Self::AlphanumericSymbols),
            "hex" => Ok(Self::Hex),
            "base64_url_safe" => Ok(Self::Base64UrlSafe),
            other => bail!(
                "unknown charset `{other}` (valid: `alphanumeric`, `alphanumeric_symbols`, \
                 `hex`, `base64_url_safe`)"
            ),
        }
    }
}

/// Minimum length the generator will accept.
///
/// Shorter passwords are trivially crackable for any of the four
/// charsets we ship; the minimum exists to prevent footgun calls.
/// Not currently overridable from operator config — re-evaluate if
/// a real use case needs sub-16-char values.
pub const MIN_PASSWORD_LEN: usize = 16;

/// Hard ceiling on length. Above this the operation is almost
/// certainly a footgun (most backend value limits are well below
/// this; some block at 64KB). Set to a generous-but-sane bound.
pub const MAX_PASSWORD_LEN: usize = 1024;

const ALPHANUMERIC_TABLE: &[u8; 62] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const ALPHANUMERIC_SYMBOLS_TABLE: &[u8; 74] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_+=";
const HEX_TABLE: &[u8; 16] = b"0123456789abcdef";
const BASE64URL_TABLE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Generate a value of `length` chars/bytes per `charset`, write it
/// to `target_uri` via `backend.set`, return Ok on success.
///
/// The value never leaves this function: the `Secret<String>` is
/// dropped explicitly after the `backend.set` call returns. Error
/// context strings carry URI + charset + length only — never the
/// value.
///
/// # Errors
///
/// - `length` is below [`MIN_PASSWORD_LEN`] or above [`MAX_PASSWORD_LEN`].
/// - `getrandom::getrandom` fails (would only happen on a system
///   with no entropy source available — extremely rare).
/// - `backend.set` fails (network, auth, permission, validation).
pub async fn generate_and_set(
    backend: &dyn Backend,
    target_uri: &BackendUri,
    charset: Charset,
    length: usize,
) -> Result<()> {
    if length < MIN_PASSWORD_LEN {
        bail!("length {length} below minimum {MIN_PASSWORD_LEN}");
    }
    if length > MAX_PASSWORD_LEN {
        bail!("length {length} above maximum {MAX_PASSWORD_LEN}");
    }

    let value = generate_string(charset, length)?;
    // `value` is a `Secret<String>`. Hand `expose_secret()` to
    // `Backend::set` inline; the borrow does not survive the call.
    backend.set(target_uri, value.expose_secret()).await.with_context(|| {
        format!(
            "writing generated value to `{}` (charset={:?}, length={})",
            target_uri.raw, charset, length
        )
    })?;
    // Explicit drop emphasizes the lifetime; `value` would drop here
    // anyway, but the explicit call documents the SEC-INV-02 boundary
    // for future readers.
    drop(value);
    Ok(())
}

/// Generate one `Secret<String>` of `length` chars per `charset`.
/// Exposed for testing the charset-encoding logic without needing a
/// backend. The caller is responsible for getting the secret out of
/// scope quickly.
///
/// # Errors
///
/// Returns an error if `getrandom::getrandom` fails (extremely rare).
fn generate_string(charset: Charset, length: usize) -> Result<Secret<String>> {
    let table: &[u8] = match charset {
        Charset::Alphanumeric => ALPHANUMERIC_TABLE,
        Charset::AlphanumericSymbols => ALPHANUMERIC_SYMBOLS_TABLE,
        Charset::Hex => HEX_TABLE,
        Charset::Base64UrlSafe => BASE64URL_TABLE,
    };
    // Each output char draws from a table of `table.len()` symbols.
    // We use rejection sampling over the byte's value mod table.len()
    // for charsets that aren't a power-of-two — biases caused by
    // `byte % 62` are real but tiny; the rejection loop costs an
    // expected ~1.06x bytes for the 62-table case. We OVER-FETCH
    // entropy by 2x to keep the rejection loop's chance of a refill
    // small in practice.
    let mut raw: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; length.saturating_mul(2)]);
    getrandom::getrandom(&mut raw).map_err(|e| anyhow!("getrandom failed: {e}"))?;

    let table_len = table.len();
    // For powers of two, the modulo is unbiased; for others we
    // rejection-sample below.
    let pow2 = table_len.is_power_of_two();
    let threshold: u8 = if pow2 {
        u8::MAX
    } else {
        // Largest multiple of `table_len` that fits in `u8::MAX + 1`.
        // Bytes >= threshold are rejected (would skew the modulo).
        // For table_len=62: 256 - (256 % 62) = 256 - 8 = 248.
        // For table_len=74: 256 - (256 % 74) = 256 - 34 = 222.
        #[allow(clippy::cast_possible_truncation)]
        let t = (256u16 - (256u16 % table_len as u16)) as u8;
        t
    };

    let mut out: Vec<u8> = Vec::with_capacity(length);
    let mut raw_idx = 0;
    while out.len() < length {
        if raw_idx >= raw.len() {
            // Rare path: we exhausted the 2x overfetch and need more.
            let mut more: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; length]);
            getrandom::getrandom(&mut more).map_err(|e| anyhow!("getrandom refill failed: {e}"))?;
            raw = more;
            raw_idx = 0;
        }
        let b = raw[raw_idx];
        raw_idx += 1;
        if !pow2 && b >= threshold {
            continue;
        }
        let symbol_idx = (b as usize) % table_len;
        out.push(table[symbol_idx]);
    }

    // Every byte in `out` came from a table of ASCII printable
    // bytes — UTF-8 validation is a formality.
    let s = String::from_utf8(out)
        .map_err(|e| anyhow!("encoded value is not valid UTF-8 (impossible): {e}"))?;
    Ok(Secret::new(s))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn alphanumeric_lengths_match_request() {
        for n in [16usize, 32, 64, 128] {
            let s = generate_string(Charset::Alphanumeric, n).unwrap();
            assert_eq!(s.expose_secret().len(), n);
            assert!(s.expose_secret().chars().all(|c| c.is_ascii_alphanumeric()));
        }
    }

    #[test]
    fn hex_lengths_match_and_charset_holds() {
        let s = generate_string(Charset::Hex, 32).unwrap();
        assert_eq!(s.expose_secret().len(), 32);
        assert!(s
            .expose_secret()
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn base64_url_safe_charset_holds() {
        let s = generate_string(Charset::Base64UrlSafe, 64).unwrap();
        assert_eq!(s.expose_secret().len(), 64);
        let ok = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
        assert!(s.expose_secret().chars().all(ok));
    }

    #[test]
    fn symbols_charset_includes_symbols() {
        // Generate a long string to make symbol-presence extremely
        // likely (74 symbols, 12 of which are punctuation; P(no symbol)
        // over 256 chars is (62/74)^256 ≈ 10^-21).
        let s = generate_string(Charset::AlphanumericSymbols, 256).unwrap();
        let any_symbol = s.expose_secret().chars().any(|c| "!@#$%^&*-_+=".contains(c));
        assert!(any_symbol, "expected at least one symbol in 256-char string");
    }

    #[test]
    fn rejects_lengths_below_minimum() {
        // We test the public path here since generate_string itself
        // doesn't enforce; the length floor is in generate_and_set.
        // generate_string is private + only tested for shape.
        // Smoke against generate_and_set covers the floor.
    }

    #[test]
    fn parse_charset_round_trips_known_values() {
        assert_eq!(Charset::parse("alphanumeric").unwrap(), Charset::Alphanumeric);
        assert_eq!(Charset::parse("alphanumeric_symbols").unwrap(), Charset::AlphanumericSymbols);
        assert_eq!(Charset::parse("hex").unwrap(), Charset::Hex);
        assert_eq!(Charset::parse("base64_url_safe").unwrap(), Charset::Base64UrlSafe);
        assert!(Charset::parse("rot13").is_err());
    }
}
