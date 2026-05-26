// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Mutation policy enforcement.
//!
//! Every mutation tool handler (Phases 4c–6) calls
//! [`enforce_mutation_policy`] at entry. The function returns
//! `Ok(OperatorDecision)` describing how the call was approved (or
//! `Err` if the policy refused / no surface was available). The
//! returned decision is what the handler writes to the audit log via
//! [`crate::audit_log::MutationLog::append`] — the policy module owns
//! the decision; the audit-log module owns the persistence.
//!
//! The TTY confirmation prompt opens `/dev/tty` for both read and
//! write. This bypasses the agent's stdio + the IDE's "approve all
//! this session" gate — the operator gets a real prompt at their
//! terminal regardless of how the MCP server was launched.

use std::io::{BufRead, BufReader, IsTerminal, Write};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use rmcp::service::{ElicitationError, Peer};
use rmcp::RoleServer;
use serde::Deserialize;
use tokio::time::timeout;

use crate::audit_log::OperatorDecision;
use crate::config::{AllowMutations, ConfirmVia, McpConfig};

/// TTY prompt wall-clock timeout. No response = treated as deny per
/// the existing [`OperatorDecision::Timeout`] semantics.
const TTY_PROMPT_TIMEOUT: Duration = Duration::from_secs(30);

/// Hard cap on rendered prompt-fragment length. Anything past this is
/// truncated with `…` — defends against hostile alias names / URIs
/// that try to push the y/N prompt off-screen.
const TTY_FRAGMENT_MAX_CHARS: usize = 240;

/// Return `true` for Unicode bidi / format / zero-width characters
/// that are not control codes (so [`char::is_control`] would miss
/// them) but can still be used to spoof rendered prompt text on a
/// terminal that respects them.
///
/// Covers the practical attack surface called out by Trojan-Source
/// (CVE-2021-42574) and follow-on research: explicit directional
/// overrides + isolates, the Mongolian Vowel Separator, the zero-width
/// joiner/non-joiner, and the ZWNBSP / BOM.
const fn is_bidi_or_zero_width_format(c: char) -> bool {
    matches!(
        c,
        // Directional formatting
        '\u{200E}' | '\u{200F}'           // LRM, RLM
        | '\u{202A}'..='\u{202E}'         // LRE, RLE, PDF, LRO, RLO
        | '\u{2066}'..='\u{2069}'         // LRI, RLI, FSI, PDI
        // Zero-width / joiner / separator / BOM
        | '\u{200B}'..='\u{200D}'         // ZWSP, ZWNJ, ZWJ
        | '\u{180E}'                      // MVS (Mongolian Vowel Separator)
        | '\u{FEFF}'                      // ZWNBSP / BOM
    )
}

/// Sanitize a string for safe display on the operator's `/dev/tty`.
///
/// Every agent-controlled fragment (alias name, target URI, registry
/// name, `agent_reason`) flows through this before reaching the prompt.
/// Defends against terminal-injection attacks (M6 in the v0.16 Phase 7
/// security audit) where a hostile alias name like
/// `"OK\n\r[secretenv mcp] Approve? [Y/n] "` could spoof a prior
/// approved prompt, and against Trojan-Source-style bidi/zero-width
/// attacks (v0.16.1 F-2) where invisible RTL overrides reorder the
/// rendered prompt to deceive the operator (e.g. an alias name
/// rendered as `"safe-key"` but actually `"yek-evas\u{202E}"` so the
/// destination URI appears to be a familiar trusted host).
///
/// Behavior:
/// - C0 control chars (`U+0000`..=`U+001F`) other than TAB are
///   replaced with `?`.
/// - DEL (`U+007F`) and C1 control chars (`U+0080`..=`U+009F`) are
///   replaced with `?`.
/// - Bidi formatting / zero-width / joiner / BOM chars (per
///   [`is_bidi_or_zero_width_format`]) are replaced with `?`.
/// - TAB and SPACE are preserved (legitimate whitespace).
/// - Inputs longer than [`TTY_FRAGMENT_MAX_CHARS`] are truncated and
///   marked with `…`.
#[must_use]
pub fn sanitize_for_tty(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(TTY_FRAGMENT_MAX_CHARS + 1));
    for (n, c) in s.chars().enumerate() {
        if n >= TTY_FRAGMENT_MAX_CHARS {
            out.push('…');
            break;
        }
        let safe = if c == '\t' || c == ' ' {
            c
        } else if c.is_control() || is_bidi_or_zero_width_format(c) {
            '?'
        } else {
            c
        };
        out.push(safe);
    }
    out
}

/// Description of a pending mutation passed to [`enforce_mutation_policy`].
///
/// Field set is the minimum needed for a useful TTY prompt + a
/// complete audit-log entry.
///
/// # SEC-INV-12 wording (refined by Phase 9 audit FINDING-F-4)
///
/// `agent_reason` is **never** included in:
/// - the JSON-RPC tool-result payload returned to the agent
/// - an `OTel` span attribute (`SecretEnvSpan` never records it)
///
/// Operator-facing surfaces MAY render it:
/// - the `/dev/tty` confirmation prompt body
/// - the MCP elicitation modal body (rendered by the IDE per
///   [`crate::config::ConfirmVia::Elicitation`])
///
/// Both surfaces are local to the operator. The protocol-level
/// boundary (server → agent's tool-result) holds; the operator-facing
/// boundary (server → operator-facing IDE chrome) intentionally
/// surfaces the reason so the operator can evaluate intent.
#[derive(Debug, Clone)]
pub struct MutationRequest<'a> {
    /// Tool name (e.g. `"set_alias"`). Used in the prompt and the
    /// audit-log entry.
    pub tool_name: &'a str,
    /// One-line summary of what the tool will do if approved (e.g.
    /// `"create alias `stripe-key` → `vault-prod://...`"`). Used in
    /// the prompt only.
    pub action_summary: &'a str,
    /// The agent's stated reason for requesting the mutation.
    /// Verbatim in the audit log; never echoed back.
    pub agent_reason: &'a str,
}

/// Empty-form schema for the elicit RPC. The MCP elicitation spec
/// defines three native button outcomes — Accept / Decline / Cancel —
/// which already encode the operator's decision. Adding a boolean
/// `approved` field would force the IDE to render a checkbox the
/// operator must tick BEFORE clicking Accept (a redundant two-step
/// interaction per Phase 7e Phase 8b walkthrough finding).
///
/// # v0.16.1 F-11 investigation outcome — deferred to v0.16.2
///
/// Phase 8b FINDING-11: VS Code Copilot advertises MCP elicitation
/// but renders NO UI for our empty-schema elicit requests
/// (`MutationApproval {}`). Mutation calls time out after 30s
/// server-side, audit log records `decision: "timeout"`. Claude
/// Code renders the Accept/Decline buttons correctly with the same
/// empty schema, so the issue is Copilot-specific.
///
/// v0.16.1 hygiene cycle investigated three candidate fixes:
///   (a) Add a `confirm: bool` no-op field to force Copilot to
///       render the modal. Risk: unknown impact on other 5 IDEs
///       that currently work; needs empirical re-validation of all
///       6 elicitation surfaces (Claude Code, Gemini, Cline,
///       Codex, OpenCode, Copilot).
///   (b) Detect Copilot from rmcp's `clientInfo.name` at the
///       initialize handshake and serve a different schema. Risk:
///       client-name strings are not stable across versions;
///       fragile.
///   (c) `--copilot-compat-schema` CLI flag. Risk: yet another
///       per-IDE workaround alongside the existing Phase 7f
///       `--allow-mutations always` overrides.
///
/// Without a live Copilot session to A/B-test (a), shipping any of
/// these speculatively risks regressing the IDEs that currently
/// work. **Deferred to v0.16.2** with the spec:
///
/// 1. Set up a Copilot test fixture in `scripts/smoke-test/`.
/// 2. A/B test option (a) against all 6 elicitation IDEs.
/// 3. Ship the variant that works for Copilot AND preserves the
///    UX on the other 5 — or formally close as upstream-fix-only.
///
/// Until then, the Phase 7f `--allow-mutations always` override
/// (shipped in `IDE_PROFILES["vscode-copilot"]` — see
/// `[[reference_v0.16_phase8b_results]]`) is the documented
/// workaround.
///
/// With an empty schema, the modal shows only the body message + the
/// three native buttons. Single click = decision:
///
/// | Button | rmcp returns | `OperatorDecision` |
/// |---|---|---|
/// | Accept | `Ok(Some(MutationApproval {}))` | `Approved` |
/// | Decline | `Err(UserDeclined)` | `Denied` |
/// | Cancel | `Err(UserCancelled)` | `Denied` |
///
/// # `JsonSchema` impl
///
/// Hand-written rather than `#[derive(JsonSchema)]` because schemars
/// 1.0 emits `{"type": "object"}` for fieldless structs (no
/// `properties` key). The MCP elicitation validator requires
/// `properties` to be present even when empty — derive output fails
/// validation server-side with `missing field properties`. Phase 7e
/// follow-up after the Claude Code walkthrough surfaced the error.
#[derive(Debug, Deserialize)]
struct MutationApproval {}

impl schemars::JsonSchema for MutationApproval {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "MutationApproval".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "object",
            "properties": {},
            "additionalProperties": false,
        })
    }
}

rmcp::elicit_safe!(MutationApproval);

/// Apply the [`McpConfig::allow_mutations`] policy to one mutation
/// request. Returns the [`OperatorDecision`] the handler should write
/// to the audit log, or an error if the policy refuses outright.
///
/// The `peer` argument is the MCP server's link to the client and is
/// used by [`ConfirmVia::Elicitation`] / [`ConfirmVia::Auto`] to surface
/// approval dialogs through the IDE. Pass `None` only in code paths
/// that cannot reach a peer (the `Auto` resolver will then degrade
/// elicitation → tty).
///
/// # Errors
///
/// - [`AllowMutations::Never`] — returns an error describing the
///   policy. Handler should surface this back to the agent as a
///   structured refusal.
/// - [`ConfirmVia::None`] when policy is `Confirm` — returns an
///   error (`Confirm` without a surface is a config bug).
/// - [`ConfirmVia::Notification`] — currently a stub (deferred to a
///   later phase); returns an error so a config setting it doesn't
///   silently auto-approve.
/// - [`ConfirmVia::Elicitation`] without a peer that advertises the
///   elicitation capability — returns an error pointing the operator
///   at `allow_mutations = "always"` or a client that supports MCP
///   elicitation.
/// - [`ConfirmVia::Auto`] in a context with neither an
///   elicitation-capable client nor a TTY on `stdin` — same kind of
///   refusal error.
/// - TTY open / read failure when policy is `Confirm` + surface
///   resolves to `Tty` — returns an error so the mutation does not
///   proceed.
///
/// On `AllowMutations::Always` returns `Ok(AutoApproved)` without
/// any I/O.
pub async fn enforce_mutation_policy(
    mcp_config: &McpConfig,
    request: &MutationRequest<'_>,
    peer: Option<&Peer<RoleServer>>,
) -> Result<OperatorDecision> {
    match mcp_config.allow_mutations {
        AllowMutations::Never => {
            bail!(
                "MCP server policy `allow_mutations = \"never\"` refuses tool `{}`. \
                 Set `[mcp].allow_mutations = \"confirm\"` or `\"always\"` to enable.",
                request.tool_name
            );
        }
        AllowMutations::Always => Ok(OperatorDecision::AutoApproved),
        AllowMutations::Confirm => {
            let resolved = resolve_confirm_via(mcp_config.confirm_via, peer)?;
            match resolved {
                ConfirmVia::Elicitation => {
                    let peer = peer.ok_or_else(|| {
                        anyhow!(
                            "elicitation requested but no MCP peer is available — \
                             this is a wiring bug; the tool handler must pass \
                             RequestContext.peer through",
                        )
                    })?;
                    prompt_via_elicitation(request, peer).await
                }
                ConfirmVia::Tty => prompt_via_tty(request).await,
                ConfirmVia::Notification => bail!(
                    "MCP server policy is `confirm` with `confirm_via = \"notification\"`, \
                     which is not yet implemented. Set `confirm_via = \"elicitation\"` \
                     (preferred for IDE-driven hosts) or `\"tty\"` (standalone shell)."
                ),
                ConfirmVia::None => bail!(
                    "MCP server policy is `confirm` with `confirm_via = \"none\"` — no \
                     confirmation surface is configured, so the mutation cannot proceed. \
                     Set `confirm_via = \"elicitation\"`/`\"tty\"`/`\"auto\"` or \
                     `allow_mutations = \"always\"`."
                ),
                ConfirmVia::Auto => {
                    // resolve_confirm_via never returns Auto — unreachable.
                    unreachable!("Auto should have been resolved to a concrete surface")
                }
            }
        }
    }
}

/// Resolve the configured [`ConfirmVia`] value to a concrete surface
/// at request time. The [`ConfirmVia::Auto`] variant is the v0.16
/// Phase 7c default and picks based on runtime context.
///
/// # Resolution order is LOAD-BEARING (Phase 9 audit R-5)
///
/// The priority is deliberate and SHOULD NOT be reordered without a
/// new security audit. The chain encodes a defense-in-depth posture:
///
/// 1. **Elicitation** (client declares MCP elicitation capability at
///    the initialize handshake): the IDE-rendered modal is the
///    safest surface — operator sees the action description, agent
///    reason, and tool name in the native IDE UI; the protocol-level
///    boundary keeps the prompt out of the agent's tool-result path.
/// 2. **TTY** (`stdin` is a terminal): the operator launched the
///    server directly from a shell. The `/dev/tty`-based prompt is
///    visible because no IDE is interposing. Phase 7c FINDING-4
///    confirmed: this path DEADLOCKS when the parent process owns
///    the controlling TTY in raw mode (TUI host IDEs); the
///    `is_terminal()` check at this layer ensures we only fall
///    through to TTY when no such parent exists.
/// 3. **Refuse with helpful error**: if neither surface is
///    available, the mutation is denied with a clear pointer at
///    remediation — operator picks either an elicitation-capable
///    client OR explicitly opts into `allow_mutations = "always"`
///    (audit-log-only mode) by editing config or passing
///    `--allow-mutations always` on the IDE's mcpServers args.
///
/// **Reordering risk**: swapping 1↔2 would re-introduce the Phase 7
/// FINDING-4 deadlock for IDE-hosted servers. Demoting 3 to "silent
/// auto-approve" would defeat the entire confirmation gate.
///
/// Explicit (non-Auto) values pass through unchanged so operators can
/// pin a specific surface for testing or to opt out of capability
/// detection.
fn resolve_confirm_via(
    configured: ConfirmVia,
    peer: Option<&Peer<RoleServer>>,
) -> Result<ConfirmVia> {
    if configured != ConfirmVia::Auto {
        return Ok(configured);
    }
    if let Some(peer) = peer {
        if !peer.supported_elicitation_modes().is_empty() {
            return Ok(ConfirmVia::Elicitation);
        }
    }
    if std::io::stdin().is_terminal() {
        return Ok(ConfirmVia::Tty);
    }
    bail!(
        "MCP server policy is `confirm` with `confirm_via = \"auto\"` but the \
         current runtime offers no usable confirmation surface: the client did \
         not declare MCP elicitation capability AND stdin is not a TTY. Either \
         (a) use an MCP client that supports elicitation (Claude Code, Cursor, \
         Cline, Gemini, recent VS Code Copilot — see `secretenv mcp setup \
         --list-ides`), or (b) set `[mcp].allow_mutations = \"always\"` if the \
         agent runtime is trusted and the audit log is sufficient gating."
    )
}

/// Surface the approval prompt through the MCP client's elicitation
/// UI. Used by IDE-driven hosts where `/dev/tty` would deadlock
/// (FINDING-4 in v0.16 Phase 7 security audit + Phase 8b).
async fn prompt_via_elicitation(
    request: &MutationRequest<'_>,
    peer: &Peer<RoleServer>,
) -> Result<OperatorDecision> {
    // The full message is the dialog body the IDE renders. Sanitize
    // the same way we do for the TTY prompt — agent-controlled
    // fragments (alias names, target URIs) flow through here too.
    let safe_tool = sanitize_for_tty(request.tool_name);
    let safe_summary = sanitize_for_tty(request.action_summary);
    let safe_reason = sanitize_for_tty(request.agent_reason);
    let message = format!(
        "Approve secretenv mutation?\n\n\
         Tool: {safe_tool}\n\
         Action: {safe_summary}\n\
         Agent reason: {safe_reason}",
    );

    // rmcp 1.7's typed `elicit_with_timeout` auto-generates the JSON
    // schema from `MutationApproval` (via the `elicit_safe!` macro)
    // and parses the client's response back into the struct. Maps
    // every documented `ElicitationError` variant onto an
    // `OperatorDecision` per Phase 7c task #2 design.
    match peer.elicit_with_timeout::<MutationApproval>(message, Some(TTY_PROMPT_TIMEOUT)).await {
        Ok(Some(MutationApproval {})) => Ok(OperatorDecision::Approved),
        Ok(None) | Err(ElicitationError::UserDeclined | ElicitationError::UserCancelled) => {
            Ok(OperatorDecision::Denied)
        }
        Err(ElicitationError::Service(rmcp::ServiceError::Timeout { .. })) => {
            Ok(OperatorDecision::Timeout)
        }
        Err(ElicitationError::CapabilityNotSupported) => bail!(
            "MCP client did not declare elicitation capability at the initialize \
             handshake, but `confirm_via = \"elicitation\"` was selected. Use \
             `confirm_via = \"auto\"` to fall through to TTY when supported, or \
             set `allow_mutations = \"always\"` for trusted agent runtimes."
        ),
        Err(e) => Err(anyhow!("elicitation request failed: {e}")),
    }
}

async fn prompt_via_tty(request: &MutationRequest<'_>) -> Result<OperatorDecision> {
    // SEC-INV-20 / M6: sanitize agent-controlled fragments before
    // they reach /dev/tty. `tool_name` is a string literal in handler
    // code (safe by construction) but `action_summary` interpolates
    // alias names + URIs from the agent's tool-call payload.
    let safe_tool = sanitize_for_tty(request.tool_name);
    let safe_summary = sanitize_for_tty(request.action_summary);
    let prompt = format!(
        "\n[secretenv mcp] Tool `{safe_tool}` wants to: {safe_summary}\n  Approve? [y/N] ",
    );

    match timeout(TTY_PROMPT_TIMEOUT, read_tty_line(prompt)).await {
        Err(_) => Ok(OperatorDecision::Timeout),
        Ok(Err(e)) => Err(e),
        Ok(Ok(line)) => {
            let trimmed = line.trim();
            if trimmed.eq_ignore_ascii_case("y") || trimmed.eq_ignore_ascii_case("yes") {
                Ok(OperatorDecision::Approved)
            } else {
                Ok(OperatorDecision::Denied)
            }
        }
    }
}

/// Open `/dev/tty` once (`O_RDWR`), drop any pre-buffered input via
/// `tcflush(TCIFLUSH)`, write the prompt, then read exactly one line
/// and return it.
///
/// # v0.16.1 F-6 TTY TOCTOU fix
///
/// The previous implementation opened `/dev/tty` twice — once
/// write-only for the prompt, once read-only for the response. Two
/// independent `open(2)` calls against `/dev/tty` create a TOCTOU
/// window: the kernel resolves `/dev/tty` to the controlling
/// terminal at open-time, and between the two opens, the controlling
/// terminal can change (most relevantly, if the parent IDE has been
/// killed and a different terminal has been re-attached, or if a
/// `setsid` happened). It also lets pre-buffered keystrokes typed
/// before the prompt appeared race the read — which is exactly what
/// an attacker who can write to the same TTY would do to force a
/// `y\n` response.
///
/// The fix is the textbook one: a single `open("/dev/tty",
/// O_RDWR)` and a `tcflush(TCIFLUSH)` immediately before reading.
///
/// Runs the blocking I/O on `tokio::task::spawn_blocking` so it
/// integrates with the `timeout` wrapper above without holding a
/// runtime thread.
#[cfg(unix)]
async fn read_tty_line(prompt: String) -> Result<String> {
    tokio::task::spawn_blocking(move || -> Result<String> {
        use std::os::fd::AsFd;

        let mut tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .context(
                "opening /dev/tty (O_RDWR) for prompt + response — is this an interactive session?",
            )?;
        tty.write_all(prompt.as_bytes()).context("writing prompt to /dev/tty")?;
        tty.flush().context("flushing /dev/tty")?;

        // Drop any input buffered before the prompt appeared so a
        // racy `y\n` typed beforehand cannot be replayed.
        // QueueSelector::IFlush == TCIFLUSH on POSIX.
        rustix::termios::tcflush(tty.as_fd(), rustix::termios::QueueSelector::IFlush)
            .context("tcflush(/dev/tty, TCIFLUSH) before reading response")?;

        let mut buf = String::new();
        BufReader::new(tty).read_line(&mut buf).context("reading line from /dev/tty")?;
        Ok(buf)
    })
    .await
    .map_err(|e| anyhow!("tokio join error during TTY prompt: {e}"))?
}

#[cfg(not(unix))]
async fn read_tty_line(_prompt: String) -> Result<String> {
    Err(anyhow!(
        "TTY confirmation prompts are POSIX-only — set [mcp].confirm_via = \"elicitation\" \
         or run inside an MCP client that advertises the elicitation capability."
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn req<'a>() -> MutationRequest<'a> {
        MutationRequest {
            tool_name: "set_alias",
            action_summary: "create alias `test`",
            agent_reason: "unit test",
        }
    }

    #[tokio::test]
    async fn never_refuses() {
        let cfg = McpConfig { allow_mutations: AllowMutations::Never, ..McpConfig::default() };
        let err = enforce_mutation_policy(&cfg, &req(), None).await.unwrap_err();
        assert!(format!("{err:#}").contains("refuses tool"));
    }

    #[tokio::test]
    async fn always_auto_approves_without_io() {
        let cfg = McpConfig { allow_mutations: AllowMutations::Always, ..McpConfig::default() };
        let decision = enforce_mutation_policy(&cfg, &req(), None).await.unwrap();
        assert_eq!(decision, OperatorDecision::AutoApproved);
    }

    #[tokio::test]
    async fn confirm_notification_is_unimplemented() {
        let cfg = McpConfig {
            allow_mutations: AllowMutations::Confirm,
            confirm_via: ConfirmVia::Notification,
            ..McpConfig::default()
        };
        let err = enforce_mutation_policy(&cfg, &req(), None).await.unwrap_err();
        assert!(format!("{err:#}").contains("not yet implemented"));
    }

    #[tokio::test]
    async fn confirm_auto_without_peer_or_tty_refuses() {
        // Phase 7c FINDING-4 fix: when `confirm_via = "auto"` and neither
        // an elicitation-capable peer nor a TTY-attached stdin is
        // available, the policy MUST refuse rather than fall through
        // to a deadlocking surface. In the test harness stdin is
        // typically a pipe (cargo test), not a TTY — making this the
        // "no usable surface" path.
        let cfg = McpConfig {
            allow_mutations: AllowMutations::Confirm,
            confirm_via: ConfirmVia::Auto,
            ..McpConfig::default()
        };
        // Skip on platforms where stdin happens to be a TTY (rare in
        // CI / `cargo test`, but possible in an interactive `cargo
        // test ... -- --nocapture` session).
        if std::io::stdin().is_terminal() {
            return;
        }
        let err = enforce_mutation_policy(&cfg, &req(), None).await.unwrap_err();
        assert!(format!("{err:#}").contains("no usable confirmation surface"));
    }

    #[tokio::test]
    async fn confirm_elicitation_without_peer_is_wiring_bug() {
        // Explicit `Elicitation` without a peer should surface the
        // "wiring bug" error rather than silently accept/refuse — the
        // tool handler forgot to thread RequestContext.peer through.
        let cfg = McpConfig {
            allow_mutations: AllowMutations::Confirm,
            confirm_via: ConfirmVia::Elicitation,
            ..McpConfig::default()
        };
        let err = enforce_mutation_policy(&cfg, &req(), None).await.unwrap_err();
        assert!(format!("{err:#}").contains("no MCP peer is available"));
    }

    #[test]
    fn resolve_explicit_value_passes_through() {
        assert_eq!(resolve_confirm_via(ConfirmVia::Tty, None).unwrap(), ConfirmVia::Tty);
        assert_eq!(
            resolve_confirm_via(ConfirmVia::Notification, None).unwrap(),
            ConfirmVia::Notification,
        );
        assert_eq!(
            resolve_confirm_via(ConfirmVia::Elicitation, None).unwrap(),
            ConfirmVia::Elicitation,
        );
        assert_eq!(resolve_confirm_via(ConfirmVia::None, None).unwrap(), ConfirmVia::None);
    }

    #[test]
    fn sanitize_strips_carriage_return_and_linefeed() {
        let hostile = "OK\n\r[secretenv mcp] Approve? [Y/n] ";
        let safe = sanitize_for_tty(hostile);
        assert!(!safe.contains('\n'));
        assert!(!safe.contains('\r'));
        assert!(safe.contains("OK"));
        assert!(safe.contains("??"));
    }

    #[test]
    fn sanitize_strips_ansi_escape() {
        let hostile = "alias\x1b[2KApproved";
        let safe = sanitize_for_tty(hostile);
        assert!(!safe.contains('\x1b'));
        assert!(safe.starts_with("alias?"));
    }

    #[test]
    fn sanitize_preserves_space_and_tab() {
        let s = "hello world\twith\ttabs";
        assert_eq!(sanitize_for_tty(s), s);
    }

    #[test]
    fn sanitize_preserves_unicode_non_control() {
        let s = "alias `µ→★` ok";
        assert_eq!(sanitize_for_tty(s), s);
    }

    #[test]
    fn sanitize_replaces_del() {
        assert_eq!(sanitize_for_tty("a\x7fb"), "a?b");
    }

    #[test]
    fn sanitize_replaces_bel() {
        assert_eq!(sanitize_for_tty("ring\x07ring"), "ring?ring");
    }

    #[test]
    fn sanitize_caps_long_input() {
        let long = "x".repeat(500);
        let safe = sanitize_for_tty(&long);
        // 240 'x' chars + '…' ellipsis = 241 chars
        assert_eq!(safe.chars().count(), 241);
        assert!(safe.ends_with('…'));
    }

    #[test]
    fn sanitize_short_input_unchanged() {
        let s = "short and fine";
        assert_eq!(sanitize_for_tty(s), s);
    }

    #[test]
    fn sanitize_strips_rtl_override() {
        // The classic Trojan-Source attack: an RTL override reverses
        // the visible order of everything after it on the line.
        let hostile = "alias\u{202E}deltauris-trusted";
        let safe = sanitize_for_tty(hostile);
        assert_eq!(safe, "alias?deltauris-trusted");
        assert!(!safe.contains('\u{202E}'));
    }

    #[test]
    fn sanitize_strips_directional_isolates() {
        // Directional isolates (U+2066..U+2069) can hide segments
        // from the operator's bidi-resolution context — equally
        // dangerous on prompt display.
        let hostile = "\u{2066}safe\u{2067}hostile\u{2069}-uri";
        let safe = sanitize_for_tty(hostile);
        assert_eq!(safe, "?safe?hostile?-uri");
    }

    #[test]
    fn sanitize_strips_zero_width_joiners() {
        // Zero-width joiner / non-joiner / ZWSP let an attacker
        // construct an alias name that looks like an existing safe
        // one but compares unequal — operator sees `stripe-key`,
        // backend sees `stripe\u{200B}-key`.
        let hostile = "stripe\u{200B}-key";
        assert_eq!(sanitize_for_tty(hostile), "stripe?-key");
        assert_eq!(sanitize_for_tty("a\u{200C}b\u{200D}c"), "a?b?c");
    }

    #[test]
    fn sanitize_strips_byte_order_mark() {
        // BOM at the start of an alias name is a classic
        // copy-paste-from-Word smuggle.
        let hostile = "\u{FEFF}alias";
        assert_eq!(sanitize_for_tty(hostile), "?alias");
    }

    #[test]
    fn sanitize_preserves_legitimate_unicode() {
        // Bidi sanitization must NOT clobber legitimate non-ASCII
        // identifiers (RTL alphabets, CJK, accented Latin, emoji).
        // Only the bidi-format codepoints listed in
        // is_bidi_or_zero_width_format() are stripped.
        let s = "café-مفتاح-鍵-🔑";
        assert_eq!(sanitize_for_tty(s), s);
    }

    #[tokio::test]
    async fn confirm_none_refuses() {
        let cfg = McpConfig {
            allow_mutations: AllowMutations::Confirm,
            confirm_via: ConfirmVia::None,
            ..McpConfig::default()
        };
        let err = enforce_mutation_policy(&cfg, &req(), None).await.unwrap_err();
        assert!(format!("{err:#}").contains("no confirmation surface"));
    }
}
