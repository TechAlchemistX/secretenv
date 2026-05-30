// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! The [`SecretEnvSpan`] typed attribute builder — the structural
//! enforcement point for the ALLOW/DENY matrix.
//!
//! Adding a new attribute requires adding a method on this struct.
//! There is no `set_attribute(&str, &str)` public method — call
//! sites cannot smuggle a new key past code review by typing a
//! string. v0.17 wires the methods to real OTel span attributes
//! 1:1 via the typed setters below.
//!
//! # Coverage today
//!
//! v0.17 ships real emission for the 26 setters that callers in
//! `secretenv-core` / `secretenv-migrate` / `secretenv-mcp` /
//! `secretenv-cli` actively need. The remaining attributes in
//! `docs/reference/opentelemetry.md` §2 (matrix entries with no
//! current setter) are reserved by the schema; the matching setters
//! are added as callers materialise — adding a new setter is a
//! PR-reviewed code change, which is the structural enforcement
//! point. There is never a generic `set_attribute(&str, &str)`
//! escape hatch on `SecretEnvSpan`.

use opentelemetry::global::{self, BoxedSpan};
use opentelemetry::trace::{Span as _, Tracer as _};
use opentelemetry::KeyValue;

use crate::metrics::{FetchOutcome, RedactMode, ResolutionOutcome};
use crate::{BackendErrorStderr, RedactionSource, RedactionStream, SecretEnvErrorKind};

/// OTel `Tracer` name. Single instance per process; the global
/// `TracerProvider` (installed by [`crate::init`]) hands back a
/// no-op `BoxedTracer` when telemetry is unconfigured, so calls
/// remain safe and cheap in the no-collector default.
const TRACER_NAME: &str = "secretenv";

/// RAII guard returned by [`SecretEnvSpan::start`]. Held by callers
/// alongside [`SecretEnvSpan`]; both drop at end of scope.
///
/// In v0.17 the OTel span lives inside [`SecretEnvSpan`] (its `Drop`
/// calls `span.end()`), so `SpanGuard` is structurally vestigial.
/// It is retained as a sealed marker type to keep the v0.14+ call
/// shape (`let (mut span, _guard) = SecretEnvSpan::start(...)`)
/// working without an API churn that would touch every call site.
///
/// The `_private` field is the sealed-construction marker — it
/// keeps `SpanGuard` un-constructible from outside this crate so
/// the only path to obtain one is through [`SecretEnvSpan::start`].
#[derive(Debug)]
#[must_use = "dropping the SpanGuard ends the surrounding span's scope"]
pub struct SpanGuard {
    _private: (),
}

impl Drop for SpanGuard {
    fn drop(&mut self) {
        // No-op. The OTel span ends via SecretEnvSpan's Drop; this
        // type exists to preserve the v0.14+ call-site shape.
    }
}

/// Builder for a SecretEnv span. Each `record_*` method corresponds
/// 1:1 with an ALLOW attribute in `docs/reference/opentelemetry.md`
/// §2.
///
/// When telemetry is unconfigured, the underlying `BoxedSpan` is the
/// SDK's no-op span and every `record_*` call is a cheap vtable
/// dispatch that does nothing.
#[derive(Debug)]
pub struct SecretEnvSpan {
    name: &'static str,
    span: BoxedSpan,
}

/// Closed set of mutation span names that participate in the
/// SEC-INV-22 non-droppable rule (see [`crate::sampler`]).
///
/// v0.18 Phase 2 structural lift: in v0.17 the span name was a
/// `&'static str` chosen at the call site, and the sampler kept a
/// parallel `&[&str]` allowlist. The two could drift — a typo at a
/// new mutation call site would create a span the operator believed
/// was non-droppable but which the sampler treated as ordinary.
/// Phase 7b at `6e5cdd7` caught the drift with `mutation_real_name_sampled`
/// but that test asserted a constant against itself; a NEW call site
/// with a different typo would still slip past it.
///
/// Phase 2 makes the binding structural: the sampler matches on this
/// enum (via [`as_str`](Self::as_str)) instead of a private allowlist,
/// and the only way to start a mutation span is
/// [`SecretEnvSpan::start_mutation`], which takes a variant of this
/// enum. The compiler enforces that the span name and the sampler
/// whitelist are the same enumeration.
///
/// Adding a new mutation span = adding a variant here. The sampler,
/// the call site entry point, and the canonical name list all flow
/// from the variant set; nothing else needs to change.
///
/// Closes [[v0.17-deferred-items#Sec-F-5]] / [[v0.17-deferred-items#Code-L3]]
/// / Phase 7 H-1 follow-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MutationSpanName {
    /// MCP `set_alias` tool — registry write.
    McpSetAlias,
    /// MCP `delete_alias` tool — registry write.
    McpDeleteAlias,
    /// MCP `migrate_alias` tool — invokes the migrate transaction.
    McpMigrateAlias,
    /// MCP `gen_password` tool — generated value is the secret.
    McpGenPassword,
    /// Migrate `read` phase — source-side state read.
    MigrateRead,
    /// Migrate `write` phase — dest-side state write.
    MigrateWrite,
    /// Migrate `pointer_flip` phase — registry alias swap commits the migrate.
    MigratePointerFlip,
    /// Migrate `delete` phase — source-side delete after a successful
    /// migrate (only fires when `--delete-source` is set).
    MigrateDelete,
}

impl MutationSpanName {
    /// Canonical OTel span name. Read by both the tracer (when
    /// starting the span via [`SecretEnvSpan::start_mutation`]) and
    /// the sampler (when deciding whether to force-record the span).
    ///
    /// The match is exhaustive so adding a variant without naming it
    /// is a compile error.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::McpSetAlias => "secretenv.mcp.tool.set_alias",
            Self::McpDeleteAlias => "secretenv.mcp.tool.delete_alias",
            Self::McpMigrateAlias => "secretenv.mcp.tool.migrate_alias",
            Self::McpGenPassword => "secretenv.mcp.tool.gen_password",
            Self::MigrateRead => "secretenv.migrate.read",
            Self::MigrateWrite => "secretenv.migrate.write",
            Self::MigratePointerFlip => "secretenv.migrate.pointer_flip",
            Self::MigrateDelete => "secretenv.migrate.delete",
        }
    }

    /// Every variant, in canonical order. Drives the sampler's
    /// matching predicate AND the Phase 2 regression test that walks
    /// the variant set to assert structural binding.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::McpSetAlias,
            Self::McpDeleteAlias,
            Self::McpMigrateAlias,
            Self::McpGenPassword,
            Self::MigrateRead,
            Self::MigrateWrite,
            Self::MigratePointerFlip,
            Self::MigrateDelete,
        ]
    }
}

/// Closed enum of the CLI subcommands that emit a `secretenv.command`
/// attribute. v0.18 Phase 7 M-4: structural type safety in place of
/// the v0.17 `&str` interface to [`SecretEnvSpan::record_command`].
///
/// `#[non_exhaustive]` so adding a future subcommand variant is
/// non-breaking for external consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SecretEnvCommand {
    /// `secretenv run` — resolve + execve.
    Run,
    /// `secretenv get` — resolve + print to stdout.
    Get,
    /// `secretenv migrate` (top-level) and `secretenv registry migrate`.
    Migrate,
    /// `secretenv doctor` — diagnostic / fix.
    Doctor,
    /// `secretenv redact` — post-hoc scrubber.
    Redact,
    /// `secretenv mcp` — model context protocol server.
    Mcp,
    /// `secretenv registry` — registry management subcommands
    /// (set / unset / list / history / etc.).
    Registry,
}

impl SecretEnvCommand {
    /// Canonical attribute value for the `secretenv.command` OTel
    /// attribute. Matches the kebab-case CLI subcommand name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::Get => "get",
            Self::Migrate => "migrate",
            Self::Doctor => "doctor",
            Self::Redact => "redact",
            Self::Mcp => "mcp",
            Self::Registry => "registry",
        }
    }
}

/// Closed enum of the 15 known backend types.
///
/// Has an `Unknown` fallback for forward-compatibility. v0.18 Phase 7
/// M-4: structural type safety in place of the v0.17 `&str` interface
/// to [`SecretEnvSpan::record_backend_type`].
///
/// Construction from a runtime string (the value returned by a
/// `Backend::backend_type()` impl) goes through [`Self::from_runtime_str`]
/// so call sites can wrap a one-liner around the existing trait method.
/// An unrecognised string lands in [`Self::Unknown`] preserving the
/// original text — never panics, never drops the value silently.
///
/// `#[non_exhaustive]` so a future backend type can join the closed
/// set without breaking external consumers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BackendType {
    /// `local` — file-system backend.
    Local,
    /// `aws-ssm` — AWS Systems Manager Parameter Store.
    AwsSsm,
    /// `aws-secrets` — AWS Secrets Manager.
    AwsSecrets,
    /// `1password` — 1Password CLI (`op`).
    OnePassword,
    /// `vault` — HashiCorp Vault.
    Vault,
    /// `gcp` — Google Cloud Secret Manager.
    Gcp,
    /// `azure` — Azure Key Vault.
    Azure,
    /// `keychain` — macOS Keychain (`security`).
    Keychain,
    /// `doppler` — Doppler.
    Doppler,
    /// `infisical` — Infisical CLI.
    Infisical,
    /// `keeper` — Keeper Commander CLI.
    Keeper,
    /// `cf-kv` — Cloudflare Workers KV.
    CfKv,
    /// `openbao` — OpenBao (Vault fork).
    OpenBao,
    /// `conjur` — CyberArk Conjur.
    Conjur,
    /// `bitwarden-sm` — Bitwarden Secrets Manager.
    BitwardenSm,
    /// Forward-compat fallback for a backend type string that the
    /// closed set above doesn't recognise. Preserves the original
    /// runtime string so the attribute still emits accurately. Should
    /// never fire for shipping backends; a future backend should add
    /// a real variant and update [`Self::from_runtime_str`].
    Unknown(String),
}

impl BackendType {
    /// Parse a runtime `backend_type()` string (returned by the
    /// `Backend` trait method on each backend impl) into the closed
    /// enum. Falls back to [`Self::Unknown`] preserving the original
    /// string for any value not in the canonical set.
    #[must_use]
    pub fn from_runtime_str(s: &str) -> Self {
        match s {
            "local" => Self::Local,
            "aws-ssm" => Self::AwsSsm,
            "aws-secrets" => Self::AwsSecrets,
            "1password" => Self::OnePassword,
            "vault" => Self::Vault,
            "gcp" => Self::Gcp,
            "azure" => Self::Azure,
            "keychain" => Self::Keychain,
            "doppler" => Self::Doppler,
            "infisical" => Self::Infisical,
            "keeper" => Self::Keeper,
            "cf-kv" => Self::CfKv,
            "openbao" => Self::OpenBao,
            "conjur" => Self::Conjur,
            "bitwarden-sm" => Self::BitwardenSm,
            other => Self::Unknown(other.to_owned()),
        }
    }

    /// Render as the canonical OTel attribute value. Owned `String`
    /// because the `Unknown` variant carries one.
    #[must_use]
    pub fn into_attribute_value(self) -> String {
        match self {
            Self::Local => "local".to_owned(),
            Self::AwsSsm => "aws-ssm".to_owned(),
            Self::AwsSecrets => "aws-secrets".to_owned(),
            Self::OnePassword => "1password".to_owned(),
            Self::Vault => "vault".to_owned(),
            Self::Gcp => "gcp".to_owned(),
            Self::Azure => "azure".to_owned(),
            Self::Keychain => "keychain".to_owned(),
            Self::Doppler => "doppler".to_owned(),
            Self::Infisical => "infisical".to_owned(),
            Self::Keeper => "keeper".to_owned(),
            Self::CfKv => "cf-kv".to_owned(),
            Self::OpenBao => "openbao".to_owned(),
            Self::Conjur => "conjur".to_owned(),
            Self::BitwardenSm => "bitwarden-sm".to_owned(),
            Self::Unknown(s) => s,
        }
    }
}

// =====================================================================
// v0.18 Phase 4 closed enums — Arch-M6 subset (5 of 6 schema-reserved
// spans). Each enum drives one or more typed `record_*` setters on
// `SecretEnvSpan`. Pattern matches MutationSpanName / SecretEnvCommand /
// BackendType from Phases 2-3.
// =====================================================================

/// Outcome of a `secretenv.manifest.load` span. v0.18 Phase 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ManifestOutcome {
    /// Manifest loaded + validated successfully.
    Ok,
    /// No `secretenv.toml` found by the upward search.
    NotFound,
    /// File exists but is not parseable TOML or fails the typed
    /// deserialization.
    ParseError,
    /// Parses but fails [`crate::SecretDecl`]-shape validation
    /// (e.g. an alias `from` field not a `secretenv://<alias>` URI).
    ValidationError,
}

impl ManifestOutcome {
    /// Canonical attribute value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::NotFound => "not_found",
            Self::ParseError => "parse_error",
            Self::ValidationError => "validation_error",
        }
    }
}

/// Kind of registry selection that drove a `secretenv.registry.load`
/// span.
///
/// Mirrors `secretenv_core::RegistrySelection` from the consumer
/// side without leaking the underlying type into this crate. v0.18
/// Phase 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RegistrySelectionKind {
    /// `RegistrySelection::Name(_)` — selected by `[registries.<name>]`.
    ByName,
    /// `RegistrySelection::Uri(_)` — direct backend URI.
    Uri,
}

impl RegistrySelectionKind {
    /// Canonical attribute value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ByName => "by_name",
            Self::Uri => "uri",
        }
    }
}

/// Depth of a backend probe. v0.18 Phase 4 + the rolling D-3.1
/// `backend.probe.level` setter slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BackendProbeLevel {
    /// Connectivity-only probe — the backend's `check()` path.
    Connectivity,
    /// Full probe — connectivity AND permission/scope verification.
    Full,
}

impl BackendProbeLevel {
    /// Canonical attribute value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connectivity => "connectivity",
            Self::Full => "full",
        }
    }
}

/// Outcome of a backend probe. v0.18 Phase 4 + the rolling D-3.1
/// `backend.probe.outcome` setter slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BackendProbeOutcome {
    /// Probe succeeded.
    Success,
    /// Probe timed out per [`crate::sampler`] / `with_timeout` bound.
    Timeout,
    /// Backend reachable but refused the probe (auth / permission).
    PermissionDenied,
    /// Other error — backend-level fault.
    Error,
}

impl BackendProbeOutcome {
    /// Canonical attribute value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Timeout => "timeout",
            Self::PermissionDenied => "permission_denied",
            Self::Error => "error",
        }
    }
}

/// Depth of a `secretenv doctor` invocation. v0.18 Phase 4 + the
/// rolling D-3.1 `doctor.check_level` setter slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DoctorCheckLevel {
    /// Level 1 + 2 (config + auth probe) only.
    Quick,
    /// Level 1 + 2 + `--fix` remediation pass.
    Standard,
    /// Level 1 + 2 + 3 (`--extensive` — registry/source reachability).
    Extensive,
}

impl DoctorCheckLevel {
    /// Canonical attribute value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Quick => "quick",
            Self::Standard => "standard",
            Self::Extensive => "extensive",
        }
    }
}

impl SecretEnvSpan {
    /// Start a new span with a static-str name (e.g. `"redact.match"`,
    /// `"resolve.alias"`, `"backend.get"`). Returns the typed builder
    /// alongside a [`SpanGuard`] kept by the caller for scope.
    ///
    /// **For mutation spans, use [`Self::start_mutation`] instead.**
    /// Mutation spans participate in the SEC-INV-22 non-droppable
    /// rule; the typed entry point binds the span name and the
    /// sampler whitelist to the same closed enum so they cannot
    /// drift. v0.18 Phase 2 Sec-F-5 / Code-L3.
    #[must_use = "the span must be held for its scope; \
                  dropping it immediately ends the span"]
    pub fn start(name: &'static str) -> (Self, SpanGuard) {
        let tracer = global::tracer(TRACER_NAME);
        let span = tracer.start(name);
        (Self { name, span }, SpanGuard { _private: () })
    }

    /// Start a **mutation** span — one that participates in the
    /// SEC-INV-22 non-droppable rule.
    ///
    /// v0.18 Phase 2 Sec-F-5 / Code-L3 / Phase 7 H-1 follow-up: this
    /// is the sole entry point for mutation spans. The closed
    /// [`MutationSpanName`] enum is shared between this constructor
    /// and [`crate::sampler::MutationNonDroppableSampler`], so a new
    /// mutation tool's span is automatically force-sampled by the
    /// sampler without any second-place update — adding a variant
    /// to the enum is the entire change.
    #[must_use = "the span must be held for its scope; \
                  dropping it immediately ends the span"]
    pub fn start_mutation(name: MutationSpanName) -> (Self, SpanGuard) {
        Self::start(name.as_str())
    }

    /// `secretenv.version` — the SecretEnv release that produced
    /// the span. ALLOW.
    pub fn record_version(&mut self, v: &str) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.version", v.to_owned()));
        self
    }

    /// `secretenv.run_id` — UUIDv4 per invocation. ALLOW.
    pub fn record_run_id(&mut self, id: &str) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.run_id", id.to_owned()));
        self
    }

    /// `secretenv.command` — closed enum of CLI subcommands. ALLOW.
    /// v0.18 Phase 7 M-4: was `&str`; closed enum now binds the
    /// attribute value to a compile-checked set so call sites
    /// cannot smuggle a typo.
    pub fn record_command(&mut self, cmd: SecretEnvCommand) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.command", cmd.as_str()));
        self
    }

    /// `secretenv.exit_code`. ALLOW.
    pub fn record_exit_code(&mut self, code: i32) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.exit_code", i64::from(code)));
        self
    }

    /// `secretenv.duration_ms`. ALLOW.
    pub fn record_duration_ms(&mut self, ms: u64) -> &mut Self {
        // OTel attribute values use i64; ms beyond i64::MAX would mean
        // a span lasted ~292 million years, which is not a real case.
        self.span.set_attribute(KeyValue::new(
            "secretenv.duration_ms",
            i64::try_from(ms).unwrap_or(i64::MAX),
        ));
        self
    }

    /// `secretenv.alias.name`. ALLOW.
    pub fn record_alias_name(&mut self, name: &str) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.alias.name", name.to_owned()));
        self
    }

    /// `secretenv.alias.env_var`. ALLOW.
    pub fn record_alias_env_var(&mut self, env: &str) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.alias.env_var", env.to_owned()));
        self
    }

    /// `secretenv.alias.count`. ALLOW.
    pub fn record_alias_count(&mut self, n: u64) -> &mut Self {
        self.span.set_attribute(KeyValue::new(
            "secretenv.alias.count",
            i64::try_from(n).unwrap_or(i64::MAX),
        ));
        self
    }

    /// `secretenv.alias.cascade_layer_index`. ALLOW.
    pub fn record_cascade_layer_index(&mut self, idx: u32) -> &mut Self {
        self.span
            .set_attribute(KeyValue::new("secretenv.alias.cascade_layer_index", i64::from(idx)));
        self
    }

    /// `secretenv.alias.outcome` — closed enum. ALLOW.
    pub fn record_alias_outcome(&mut self, outcome: AliasOutcome) -> &mut Self {
        self.span
            .set_attribute(KeyValue::new("secretenv.alias.outcome", outcome.as_attribute_value()));
        self
    }

    /// `secretenv.backend.type`. ALLOW. v0.18 Phase 7 M-4: was
    /// `&str`; now consumes [`BackendType`], a closed enum of the
    /// 15 known backend types with an `Unknown(String)` fallback
    /// for forward compatibility (a future backend's `backend_type()`
    /// string that hasn't been added to the enum yet still emits
    /// without panicking).
    pub fn record_backend_type(&mut self, ty: BackendType) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.backend.type", ty.into_attribute_value()));
        self
    }

    /// `secretenv.backend.instance_name`. ALLOW.
    pub fn record_backend_instance(&mut self, name: &str) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.backend.instance_name", name.to_owned()));
        self
    }

    /// `secretenv.backend.region`. ALLOW.
    pub fn record_backend_region(&mut self, region: &str) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.backend.region", region.to_owned()));
        self
    }

    /// `secretenv.backend.cli.name`. ALLOW.
    pub fn record_backend_cli_name(&mut self, cli: &str) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.backend.cli.name", cli.to_owned()));
        self
    }

    /// `secretenv.backend.cli.version`. ALLOW.
    pub fn record_backend_cli_version(&mut self, version: &str) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.backend.cli.version", version.to_owned()));
        self
    }

    /// `secretenv.backend.auth_method` — closed enum. ALLOW.
    pub fn record_backend_auth_method(&mut self, m: AuthMethod) -> &mut Self {
        self.span
            .set_attribute(KeyValue::new("secretenv.backend.auth_method", m.as_attribute_value()));
        self
    }

    /// `secretenv.backend.error.kind`. ALLOW. Closed enum
    /// [`SecretEnvErrorKind`] — emits the kebab-case attribute value.
    /// Method name kept as `record_error_kind` (no callers to break);
    /// emitted key matches `docs/reference/opentelemetry.md` §2.3.
    pub fn record_error_kind(&mut self, kind: SecretEnvErrorKind) -> &mut Self {
        self.span.set_attribute(KeyValue::new(
            "secretenv.backend.error.kind",
            kind.as_attribute_value(),
        ));
        self
    }

    /// `secretenv.backend.error.message` — opt-in scrubbed backend
    /// stderr text. Dual-state ALLOW per `docs/reference/opentelemetry.md`
    /// §2: default DENY (`opt_in = false` → attribute structurally
    /// absent); opt-in scrubbed-ALLOW (`opt_in = true` → emit the
    /// scrubbed payload). The opt-in is driven by the CLI flag
    /// `--otel-include-error-detail` on `secretenv run` (and the
    /// corresponding [`crate::init::RunOptions`] field). v0.18 D-5.1.
    ///
    /// SEC-INV-20 enforcement is structural: the `msg` parameter is
    /// `&BackendErrorStderr`, and that type's only constructor runs
    /// the shape-based scrubber (URI shapes / AWS 12-digit account
    /// IDs / high-entropy tokens). A caller that holds a
    /// `BackendErrorStderr` has, by construction, scrubbed the input.
    pub fn record_backend_error_message_scrubbed(
        &mut self,
        msg: &BackendErrorStderr,
        opt_in: bool,
    ) -> &mut Self {
        if opt_in {
            self.span.set_attribute(KeyValue::new(
                "secretenv.backend.error.message",
                msg.as_str().to_owned(),
            ));
        }
        self
    }

    // ----- v0.18 Phase 4: schema-reserved span attribute setters -----

    /// `secretenv.manifest.path` — workspace-relative path to the
    /// manifest file. Method name carries the contract (relative
    /// only — never an absolute path) per Phase 9b Sec F-1 basename
    /// guard discipline. ALLOW. v0.18 Phase 4.
    pub fn record_manifest_path_relative(&mut self, path: &std::path::Path) -> &mut Self {
        self.span.set_attribute(KeyValue::new(
            "secretenv.manifest.path",
            path.to_string_lossy().into_owned(),
        ));
        self
    }

    /// `secretenv.manifest.alias_count` — number of `SecretDecl::Alias`
    /// entries in the manifest. ALLOW. v0.18 Phase 4.
    pub fn record_manifest_alias_count(&mut self, n: u64) -> &mut Self {
        self.span.set_attribute(KeyValue::new(
            "secretenv.manifest.alias_count",
            i64::try_from(n).unwrap_or(i64::MAX),
        ));
        self
    }

    /// `secretenv.manifest.default_count` — number of `SecretDecl::Default`
    /// entries in the manifest. ALLOW. v0.18 Phase 4.
    pub fn record_manifest_default_count(&mut self, n: u64) -> &mut Self {
        self.span.set_attribute(KeyValue::new(
            "secretenv.manifest.default_count",
            i64::try_from(n).unwrap_or(i64::MAX),
        ));
        self
    }

    /// `secretenv.manifest.outcome` — closed enum [`ManifestOutcome`].
    /// ALLOW. v0.18 Phase 4.
    pub fn record_manifest_outcome(&mut self, outcome: ManifestOutcome) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.manifest.outcome", outcome.as_str()));
        self
    }

    /// `secretenv.registry.selection` — closed enum
    /// [`RegistrySelectionKind`]. ALLOW. v0.18 Phase 4.
    pub fn record_registry_selection(&mut self, kind: RegistrySelectionKind) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.registry.selection", kind.as_str()));
        self
    }

    /// `secretenv.registry.source_count` — number of cascade-layer
    /// sources contributing to the resolved `AliasMap`. ALLOW. v0.18
    /// Phase 4.
    pub fn record_registry_source_count(&mut self, n: u64) -> &mut Self {
        self.span.set_attribute(KeyValue::new(
            "secretenv.registry.source_count",
            i64::try_from(n).unwrap_or(i64::MAX),
        ));
        self
    }

    /// `secretenv.registry.source_index` — zero-based index of the
    /// current cascade-layer source within the source list. ALLOW.
    /// v0.18 Phase 4.
    pub fn record_registry_source_index(&mut self, idx: u32) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.registry.source_index", i64::from(idx)));
        self
    }

    /// `secretenv.backend.probe.level` — closed enum
    /// [`BackendProbeLevel`]. ALLOW. v0.18 Phase 4.
    pub fn record_backend_probe_level(&mut self, level: BackendProbeLevel) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.backend.probe.level", level.as_str()));
        self
    }

    /// `secretenv.backend.probe.outcome` — closed enum
    /// [`BackendProbeOutcome`]. ALLOW. v0.18 Phase 4.
    pub fn record_backend_probe_outcome(&mut self, outcome: BackendProbeOutcome) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.backend.probe.outcome", outcome.as_str()));
        self
    }

    /// `secretenv.backend.fetch.attempt` — 1-based retry counter for
    /// the current fetch attempt. ALLOW. v0.18 Phase 4.
    pub fn record_backend_fetch_attempt(&mut self, attempt: u32) -> &mut Self {
        self.span
            .set_attribute(KeyValue::new("secretenv.backend.fetch.attempt", i64::from(attempt)));
        self
    }

    /// `secretenv.doctor.check_level` — closed enum
    /// [`DoctorCheckLevel`]. ALLOW. v0.18 Phase 4.
    pub fn record_doctor_check_level(&mut self, level: DoctorCheckLevel) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.doctor.check_level", level.as_str()));
        self
    }

    /// `secretenv.doctor.backend_count` — total number of backends
    /// the doctor pass evaluated. ALLOW. v0.18 Phase 4.
    pub fn record_doctor_backend_count(&mut self, n: u64) -> &mut Self {
        self.span.set_attribute(KeyValue::new(
            "secretenv.doctor.backend_count",
            i64::try_from(n).unwrap_or(i64::MAX),
        ));
        self
    }

    /// `secretenv.doctor.failure_count` — number of backends in a
    /// non-Authenticated state after the doctor pass. ALLOW. v0.18
    /// Phase 4.
    pub fn record_doctor_failure_count(&mut self, n: u64) -> &mut Self {
        self.span.set_attribute(KeyValue::new(
            "secretenv.doctor.failure_count",
            i64::try_from(n).unwrap_or(i64::MAX),
        ));
        self
    }

    /// `secretenv.run.command_name` — argv[0] only. ALLOW.
    pub fn record_process_command_name(&mut self, name: &str) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.run.command_name", name.to_owned()));
        self
    }

    /// `secretenv.run.env_var_count`. ALLOW.
    pub fn record_process_env_var_count(&mut self, n: u64) -> &mut Self {
        self.span.set_attribute(KeyValue::new(
            "secretenv.run.env_var_count",
            i64::try_from(n).unwrap_or(i64::MAX),
        ));
        self
    }

    /// `secretenv.run.dry_run`. ALLOW.
    pub fn record_run_dry_run(&mut self, v: bool) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.run.dry_run", v));
        self
    }

    /// `secretenv.run.verbose`. ALLOW.
    pub fn record_run_verbose(&mut self, v: bool) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.run.verbose", v));
        self
    }

    /// `secretenv.run.outcome` — closed enum. ALLOW.
    pub fn record_run_outcome(&mut self, outcome: ResolutionOutcome) -> &mut Self {
        self.span
            .set_attribute(KeyValue::new("secretenv.run.outcome", outcome.as_attribute_value()));
        self
    }

    /// `secretenv.run.failed_alias_count`. ALLOW. Aggregate, never per-alias.
    pub fn record_run_failed_alias_count(&mut self, n: u64) -> &mut Self {
        self.span.set_attribute(KeyValue::new(
            "secretenv.run.failed_alias_count",
            i64::try_from(n).unwrap_or(i64::MAX),
        ));
        self
    }

    /// `secretenv.resolution.outcome` — closed enum. ALLOW.
    pub fn record_resolution_outcome(&mut self, outcome: ResolutionOutcome) -> &mut Self {
        self.span.set_attribute(KeyValue::new(
            "secretenv.resolution.outcome",
            outcome.as_attribute_value(),
        ));
        self
    }

    /// `secretenv.resolution.latency_ms`. ALLOW.
    pub fn record_resolution_latency_ms(&mut self, ms: u64) -> &mut Self {
        self.span.set_attribute(KeyValue::new(
            "secretenv.resolution.latency_ms",
            i64::try_from(ms).unwrap_or(i64::MAX),
        ));
        self
    }

    /// `secretenv.backend.fetch.outcome` — closed enum. ALLOW.
    pub fn record_backend_fetch_outcome(&mut self, outcome: FetchOutcome) -> &mut Self {
        self.span.set_attribute(KeyValue::new(
            "secretenv.backend.fetch.outcome",
            outcome.as_attribute_value(),
        ));
        self
    }

    /// `secretenv.backend.fetch.duration_ms`. ALLOW.
    pub fn record_backend_fetch_duration_ms(&mut self, ms: u64) -> &mut Self {
        self.span.set_attribute(KeyValue::new(
            "secretenv.backend.fetch.duration_ms",
            i64::try_from(ms).unwrap_or(i64::MAX),
        ));
        self
    }

    /// `secretenv.registry.name`. ALLOW.
    pub fn record_registry_name(&mut self, name: &str) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.registry.name", name.to_owned()));
        self
    }

    /// `secretenv.mcp.tool_name`. ALLOW. Closed enum at the contract
    /// level (the 14 v0.16 tool names); call sites pass the tool's
    /// `&'static str` name from the tool registry.
    pub fn record_mcp_tool_name(&mut self, name: &str) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.mcp.tool_name", name.to_owned()));
        self
    }

    /// `secretenv.mcp.client_name`. ALLOW. Closed enum of known IDE
    /// + agent clients (`claude-code`, `cursor`, ...) plus `unknown`.
    pub fn record_mcp_client_name(&mut self, name: &str) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.mcp.client_name", name.to_owned()));
        self
    }

    /// `secretenv.mcp.argument_alias_name`. ALLOW. Mutation tools
    /// (`set_alias` / `delete_alias` / `migrate_alias`) record the
    /// alias-name argument here so the audit span carries WHICH alias
    /// was touched. Topology (`argument_uri`, `argument_reason`)
    /// stays DENY per SEC-INV-12.
    pub fn record_mcp_argument_alias_name(&mut self, name: &str) -> &mut Self {
        self.span
            .set_attribute(KeyValue::new("secretenv.mcp.argument_alias_name", name.to_owned()));
        self
    }

    /// `secretenv.redact.match_count`. ALLOW.
    pub fn record_redact_match_count(&mut self, n: u64) -> &mut Self {
        self.span.set_attribute(KeyValue::new(
            "secretenv.redact.match_count",
            i64::try_from(n).unwrap_or(i64::MAX),
        ));
        self
    }

    /// `secretenv.redact.byte_count`. ALLOW.
    pub fn record_redact_byte_count(&mut self, bytes: u64) -> &mut Self {
        self.span.set_attribute(KeyValue::new(
            "secretenv.redact.byte_count",
            i64::try_from(bytes).unwrap_or(i64::MAX),
        ));
        self
    }

    // `record_redact_alias_name` was deliberately removed in v0.14
    // Phase 9 per SEC-INV-19. The redact alias name remains in the
    // operator-local terminal substitution token (`[redacted:<alias>]`,
    // rendered by `secretenv_core::redact::SubstitutionToken`) but is
    // DENY for OTel attribute emission. See
    // [[v0.14-plus-security-invariants]] §2.5 and §9 for the council
    // resolution that overruled the alternative ALLOW position.
    //
    // A compile-fail test at `tests/no_redact_alias_in_otel.rs`
    // verifies this method does not exist; adding it back without
    // also amending SEC-INV-19 will fail CI.

    /// `secretenv.redact.mode` — closed enum. ALLOW.
    pub fn record_redact_mode(&mut self, mode: RedactMode) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.redact.mode", mode.as_attribute_value()));
        self
    }

    /// `secretenv.redact.stream`. ALLOW.
    pub fn record_redact_stream(&mut self, s: RedactionStream) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.redact.stream", s.as_attribute_value()));
        self
    }

    /// `secretenv.redact.source`. ALLOW.
    pub fn record_redact_source(&mut self, src: RedactionSource) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.redact.source", src.as_attribute_value()));
        self
    }

    // ---- migrate surface (v0.15 — `secretenv registry migrate`) ----

    /// `secretenv.migrate.phase`. ALLOW. Closed enum
    /// [`MigratePhase`] — emits the kebab-case attribute value.
    pub fn record_migrate_phase(&mut self, phase: MigratePhase) -> &mut Self {
        self.span
            .set_attribute(KeyValue::new("secretenv.migrate.phase", phase.as_attribute_value()));
        self
    }

    /// `secretenv.migrate.outcome`. ALLOW. Closed enum
    /// [`MigrateOutcome`] — emits the kebab-case attribute value.
    pub fn record_migrate_outcome(&mut self, outcome: MigrateOutcome) -> &mut Self {
        self.span.set_attribute(KeyValue::new(
            "secretenv.migrate.outcome",
            outcome.as_attribute_value(),
        ));
        self
    }

    /// `secretenv.migrate.source_backend_type`. ALLOW. Backend type
    /// strings like `"aws-ssm"`, `"vault"` — backend TYPE only, never
    /// the backend INSTANCE name (instance names can carry
    /// environment hints like `prod` that fingerprint the operator's
    /// infra topology and stay DENY).
    pub fn record_migrate_source_backend_type(&mut self, ty: &str) -> &mut Self {
        self.span
            .set_attribute(KeyValue::new("secretenv.migrate.source_backend_type", ty.to_owned()));
        self
    }

    /// `secretenv.migrate.dest_backend_type`. ALLOW. Same shape as
    /// source — TYPE only, not instance name.
    pub fn record_migrate_dest_backend_type(&mut self, ty: &str) -> &mut Self {
        self.span
            .set_attribute(KeyValue::new("secretenv.migrate.dest_backend_type", ty.to_owned()));
        self
    }

    /// `secretenv.migrate.delete_source`. ALLOW. Whether
    /// `--delete-source` was specified for this migration. The
    /// attribute is the flag's value, NOT the actual deletion
    /// outcome (success/failure surfaces via
    /// [`record_migrate_outcome`]).
    pub fn record_migrate_delete_source(&mut self, delete: bool) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.migrate.delete_source", delete));
        self
    }

    /// `secretenv.migrate.transaction_id`. ALLOW. Per-invocation
    /// UUIDv4-shaped id correlating the three-step transaction
    /// (read → write → pointer-flip) across spans. Operators use
    /// this to grep recovery logs after a partial-failure exit.
    pub fn record_migrate_transaction_id(&mut self, id: &str) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.migrate.transaction_id", id.to_owned()));
        self
    }

    /// `secretenv.migrate.collapsed`. ALLOW. v0.18 M-9.
    ///
    /// `true` when the source + dest backend pair lets the
    /// three-phase transaction (read → write → pointer-flip) collapse
    /// into a single backend-side transaction (e.g. same-backend
    /// migrations where the backend exposes an atomic `cas_set`
    /// surface). `false` for the regular three-phase flow.
    ///
    /// v0.18 emits this attribute as `false` at the parent migrate
    /// span unconditionally — backend-pair collapse detection is not
    /// yet wired (no backend currently exposes `cas_set`). The
    /// attribute reserves the slot so future collapse paths can
    /// flip it without spec churn.
    pub fn record_migrate_collapsed(&mut self, collapsed: bool) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.migrate.collapsed", collapsed));
        self
    }

    /// The span name, for tests + diagnostic logging.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    // NOTE: there is deliberately no `set_attribute(k: &str, v: &str)`
    // here. The v0.14+ synthesis §3 decision: set-site enforcement
    // is the only protection that holds under careless contributors
    // — exporter-side filtering is fail-open and trivially
    // bypassed by misnamed keys.
}

impl Drop for SecretEnvSpan {
    fn drop(&mut self) {
        // SEC-INV-22's per-span emission point. End() is the contract
        // the OTel `BatchSpanProcessor` listens on; without it the
        // span never enters the export queue.
        self.span.end();
    }
}

/// Closed enum for `secretenv.alias.outcome`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AliasOutcome {
    /// Resolved + fetched successfully.
    Ok,
    /// Resolved from a manifest default; no backend fetch.
    Default,
    /// Resolved but the backend fetch failed.
    Failed,
    /// Dry-run path; no fetch attempted.
    DryRun,
}

impl AliasOutcome {
    /// Stable kebab-case attribute value.
    #[must_use]
    pub const fn as_attribute_value(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Default => "default",
            Self::Failed => "failed",
            Self::DryRun => "dry-run",
        }
    }
}

/// Closed enum for `secretenv.backend.auth_method`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthMethod {
    /// Bearer token in env var.
    EnvToken,
    /// CLI-managed session (`op signin`, `aws sso login`, etc.).
    CliSession,
    /// IAM role / metadata-server-discovered identity.
    InstanceRole,
    /// Service-account JSON key file.
    ServiceAccountKey,
    /// OAuth flow with refreshable token (e.g. wrangler).
    OauthRefresh,
    /// Local filesystem — no auth.
    None,
    /// Auth method unknown to the backend's introspection probe.
    Unknown,
}

impl AuthMethod {
    /// Stable kebab-case attribute value.
    #[must_use]
    pub const fn as_attribute_value(self) -> &'static str {
        match self {
            Self::EnvToken => "env-token",
            Self::CliSession => "cli-session",
            Self::InstanceRole => "instance-role",
            Self::ServiceAccountKey => "service-account-key",
            Self::OauthRefresh => "oauth-refresh",
            Self::None => "none",
            Self::Unknown => "unknown",
        }
    }
}

/// Closed enum for `secretenv.migrate.phase`. v0.15 — see
/// [[build-plan-v0.15-migrate]] for the three-step migrate transaction
/// (read → write → pointer-flip) plus the optional fourth cleanup step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MigratePhase {
    /// Step 0 — capability and write-permission probe on the
    /// destination backend.
    Probe,
    /// Step 1 — read the source value.
    Read,
    /// Step 2 — write the value to the destination.
    Write,
    /// Step 3 — atomically flip the registry pointer (commit).
    PointerFlip,
    /// Step 4 (opt-in) — delete the source value after a successful
    /// commit. Only reached when `--delete-source` is set.
    DeleteSource,
}

impl MigratePhase {
    /// Stable kebab-case attribute value.
    #[must_use]
    pub const fn as_attribute_value(self) -> &'static str {
        match self {
            Self::Probe => "probe",
            Self::Read => "read",
            Self::Write => "write",
            Self::PointerFlip => "pointer-flip",
            Self::DeleteSource => "delete-source",
        }
    }
}

/// Closed enum for `secretenv.migrate.outcome`. v0.15.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MigrateOutcome {
    /// Three-step (or four-step under `--delete-source`) transaction
    /// committed successfully.
    Ok,
    /// Three-step transaction committed successfully but the opt-in
    /// fourth step (source-delete under `--delete-source`) failed.
    /// Migration itself is complete; cleanup is the operator's call.
    /// Distinct from `Ok` so OTel queries can surface "migrate
    /// succeeded but source cleanup failed" without scraping logs.
    OkWithCleanupFailure,
    /// Write succeeded but pointer-flip failed; operator must run
    /// recovery. NEVER auto-rollback by deletion per SEC-INV-09.
    PartialFailure,
    /// Source read failed; nothing was written; nothing to recover.
    SourceReadFailed,
    /// Destination write failed before commit; nothing to recover.
    DestWriteFailed,
    /// Destination probe failed up front (write capability missing or
    /// `Gated`-without-opt-in); no read or write attempted.
    ProbeFailed,
    /// Operator aborted the confirmation prompt.
    Aborted,
    /// Dry-run path; no read, write, or commit attempted.
    DryRun,
}

impl MigrateOutcome {
    /// Stable kebab-case attribute value.
    #[must_use]
    pub const fn as_attribute_value(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::OkWithCleanupFailure => "ok-with-cleanup-failure",
            Self::PartialFailure => "partial-failure",
            Self::SourceReadFailed => "source-read-failed",
            Self::DestWriteFailed => "dest-write-failed",
            Self::ProbeFailed => "probe-failed",
            Self::Aborted => "aborted",
            Self::DryRun => "dry-run",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn span_records_silently_when_no_provider() {
        // With no TracerProvider installed, the NoopTracer's BoxedSpan
        // accepts every record_* call without panic and without
        // allocating a real span.
        let (mut span, _guard) = SecretEnvSpan::start("redact.match");
        span.record_version("0.17.0")
            .record_run_id("11111111-1111-1111-1111-111111111111")
            .record_command(SecretEnvCommand::Run)
            .record_redact_match_count(3)
            .record_alias_outcome(AliasOutcome::Ok);
        assert_eq!(span.name(), "redact.match");
    }

    #[test]
    fn enum_attribute_values_are_kebab_case() {
        assert_eq!(AliasOutcome::DryRun.as_attribute_value(), "dry-run");
        assert_eq!(AuthMethod::ServiceAccountKey.as_attribute_value(), "service-account-key");
        assert_eq!(MigratePhase::PointerFlip.as_attribute_value(), "pointer-flip");
        assert_eq!(MigratePhase::DeleteSource.as_attribute_value(), "delete-source");
        assert_eq!(MigrateOutcome::PartialFailure.as_attribute_value(), "partial-failure");
        assert_eq!(MigrateOutcome::SourceReadFailed.as_attribute_value(), "source-read-failed");
        assert_eq!(MigrateOutcome::ProbeFailed.as_attribute_value(), "probe-failed");
    }

    #[test]
    fn migrate_recorders_compile_and_chain() {
        let (mut span, _guard) = SecretEnvSpan::start("registry.migrate");
        span.record_migrate_phase(MigratePhase::Probe)
            .record_migrate_outcome(MigrateOutcome::Ok)
            .record_migrate_source_backend_type("aws-ssm")
            .record_migrate_dest_backend_type("vault")
            .record_migrate_delete_source(false)
            .record_migrate_transaction_id("11111111-1111-1111-1111-111111111111");
        assert_eq!(span.name(), "registry.migrate");
    }
}
