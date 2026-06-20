# OpenTelemetry

SecretEnv emits traces and metrics for secret resolution, backend probes, MCP tool calls, redactions, and migrations. Telemetry is **opt-in**: set `OTEL_EXPORTER_OTLP_ENDPOINT` to point at any OTLP-compatible collector (Jaeger, Tempo, Honeycomb, Datadog, etc.). With no endpoint, SecretEnv installs no exporter and has zero startup overhead.

This document is the **audit-facing contract**. Every emitted attribute has an explicit ALLOW/DENY classification enforced at compile time: the typed `SecretEnvSpan` builder exposes one method per ALLOW attribute and no generic `set_attribute` escape hatch.

---

## 1. Overview

| | |
|---|---|
| **Protocol** | OTLP over gRPC (default) or HTTP/protobuf |
| **Signals** | Traces + metrics + logs (logs bridged from `tracing` events) |
| **Default behavior** | No-op when `OTEL_EXPORTER_OTLP_ENDPOINT` is unset |
| **Service name** | `secretenv` (override via `OTEL_SERVICE_NAME`) |
| **Sampler** | `parentbased_always_on`; mutation spans non-droppable |
| **Propagation** | W3C tracecontext + baggage (inbound only in v0.17) |
| **Flush guarantee** | 1-second bounded `force_flush()` before `exec()` |

SecretEnv does **not** require a collector to be useful. The `secretenv doctor --trace` subcommand renders an in-memory span table for any operator who wants per-invocation visibility without standing up infrastructure. Setting `OTEL_TRACES_EXPORTER=console` writes spans to stderr.

---

## 2. Attribute schema

**ALLOW** attributes have typed setters on `SecretEnvSpan` and appear on spans. **DENY** attributes have no setter; compile-time enforcement prevents emission.

### 2.1 SecretEnv core

| Attribute | ALLOW/DENY | Notes |
|---|---|---|
| `secretenv.version` | ALLOW | Static binary version |
| `secretenv.run_id` | ALLOW | UUIDv4 per invocation |
| `secretenv.command` | ALLOW | Closed enum: `run` / `get` / `migrate` / `doctor` / `mcp` / `redact` / `registry` |
| `secretenv.exit_code` | ALLOW | int |
| `secretenv.duration_ms` | ALLOW | int |
| `secretenv.process.command_name` | ALLOW | Basename of the invoking process `argv[0]` (path stripped); the process-level sibling of `run.command_name` |
| `secretenv.process.argv` | **DENY** | Full argv may contain secrets |
| `secretenv.process.env_var_count` | ALLOW | Aggregate count of environment variables |

### 2.2 Alias

| Attribute | ALLOW/DENY | Notes |
|---|---|---|
| `secretenv.alias.name` | ALLOW | Operator-stated; hot-path diagnostic |
| `secretenv.alias.env_var` | ALLOW | Env var name (e.g. `STRIPE_KEY`); never the value |
| `secretenv.alias.count` | ALLOW | Aggregate |
| `secretenv.alias.cascade_layer_index` | ALLOW | Which cascade layer satisfied the lookup |
| `secretenv.alias.outcome` | ALLOW | Closed enum: `ok` / `default` / `failed` / `dry-run` |
| `secretenv.alias.is_default` | ALLOW | bool |
| `secretenv.alias.uri` / `.uri.raw` / `.uri.path` | **DENY** | Topology leak |
| `secretenv.alias.uri_scheme` | **DENY** | Scheme + path together reconstruct topology |
| `secretenv.value` / `.value.length` / `.value.hash` | **DENY** | Value oracle / length oracle / rainbow-table correlator |

### 2.3 Backend

| Attribute | ALLOW/DENY | Notes |
|---|---|---|
| `secretenv.backend.type` | ALLOW | Backend family (closed enum) |
| `secretenv.backend.instance_name` | ALLOW | Operator-chosen config label |
| `secretenv.backend.address` | **DENY** | Internal network URL |
| `secretenv.backend.namespace` | **DENY** | Vault Enterprise namespace etc.; topology |
| `secretenv.backend.region` | ALLOW | Coarse (`us-east-1`); not topology |
| `secretenv.backend.account_id` | **DENY** | AWS account IDs are sensitive |
| `secretenv.backend.profile_name` | ALLOW | Operator-chosen label |
| `secretenv.backend.cli.name` | ALLOW | Binary name (e.g. `op`, `vault`) |
| `secretenv.backend.cli.version` | ALLOW | Useful for triage |
| `secretenv.backend.cli.identity` | **DENY** | Account email / ARN |
| `secretenv.backend.auth_method` | ALLOW | Closed enum: `env-token` / `cli-session` / `instance-role` / `service-account-key` / `oauth-refresh` / `none` / `unknown`; never the credential |
| `secretenv.backend.probe.level` | ALLOW | Closed enum `l1-cli` / `l2-auth` / `l3-read` (per-backend probe depth, shared with the `backend.probe.count` metric). Distinct from `secretenv.doctor.check_level` (the doctor invocation mode). The run-path `secretenv.backend.probe` span emits `l3-read` (it wraps a real read; v0.20 will stage true L1/L2/L3 probing). |
| `secretenv.backend.probe.outcome` | ALLOW | Closed enum `ok` / `cli-missing` / `not-authenticated` / `registry-unreachable` / `timeout` / `unknown` (shared with the `backend.probe.count` metric) |
| `secretenv.backend.error.kind` | ALLOW | Closed enum `SecretEnvErrorKind` |
| `secretenv.backend.error.message` | **DENY by default** | Per-run opt-in via `--otel-include-error-detail`; even then, scrubbed before any emission |
| `secretenv.backend.error.cli_stderr` | **DENY** | Raw stderr; topology + credential leak risk |
| `secretenv.backend.fetch.outcome` | ALLOW | Operational |
| `secretenv.backend.fetch.timeout_ms` | ALLOW | |
| `secretenv.backend.fetch.attempt` | ALLOW | |
| `secretenv.backend.fetch.duration_ms` | ALLOW | |

### 2.4 Registry & manifest

| Attribute | ALLOW/DENY | Notes |
|---|---|---|
| `secretenv.registry.name` | ALLOW | Registry config name |
| `secretenv.registry.selection` | ALLOW | `by_name` / `uri` (never the URI itself) |
| `secretenv.registry.source_count` | ALLOW | Aggregate |
| `secretenv.registry.source_index` | ALLOW | Aggregate |
| `secretenv.registry.source_uri` | **DENY** | Registry document URI; topology |
| `secretenv.manifest.path` | ALLOW (basename only) | Filename basename only (e.g. `secretenv.toml`); never an absolute path. Empty/`/`/`..` paths emit the `<no-basename>` sentinel |
| `secretenv.manifest.alias_count` | ALLOW | Aggregate |
| `secretenv.manifest.default_count` | ALLOW | Aggregate |
| `secretenv.manifest.outcome` | ALLOW | Closed enum: `ok` / `not_found` / `parse_error` / `validation_error` |

### 2.5 Resolution & run

| Attribute | ALLOW/DENY | Notes |
|---|---|---|
| `secretenv.resolution.outcome` | ALLOW | |
| `secretenv.resolution.cache_hit` | ALLOW | |
| `secretenv.resolution.attempt` | ALLOW | |
| `secretenv.resolution.latency_ms` | ALLOW | |
| `secretenv.run.dry_run` | ALLOW | bool |
| `secretenv.run.verbose` | ALLOW | bool |
| `secretenv.run.command_name` | ALLOW | Basename of `argv[0]` only, any absolute or relative path prefix is stripped before emission to avoid leaking host filesystem layout |
| `secretenv.run.command_argv` | **DENY** | Full argv may contain secrets |
| `secretenv.run.env_var_count` | ALLOW | Aggregate |
| `secretenv.run.env_var_value` | **DENY** | |
| `secretenv.run.outcome` | ALLOW | |
| `secretenv.run.failed_alias_count` | ALLOW | Aggregate |

### 2.6 Redact

| Attribute | ALLOW/DENY | Notes |
|---|---|---|
| `secretenv.redact.mode` | ALLOW | `runtime` / `post-hoc` / `disabled` |
| `secretenv.redact.match_count` | ALLOW | Aggregate |
| `secretenv.redact.byte_count` | ALLOW | Aggregate |
| `secretenv.redact.stream` | ALLOW | `stdout` / `stderr` / `file` |
| `secretenv.redact.line_number` | ALLOW | |
| `secretenv.redact.replacement_token` | ALLOW | The literal token written in place of the match |
| `secretenv.redact.match_context` | ALLOW | `exact` / `substring` / `base64-form` |
| `secretenv.redact.source` | ALLOW | Closed enum: `mode-a` (runtime pipe) / `mode-b` (post-hoc file rewrite). Distinguishes which redaction path scrubbed the match for percentile-by-mode triage. |
| `secretenv.redact.alias_name` | **DENY in OTel** | The alias name appears in the operator-local redaction token; it does **not** appear as an OTel attribute. (Resolves the conflict between the OTel spec's permissive position and the security invariant; security wins for OTel emission.) |
| `secretenv.redact.matched_value` / `.value_length` | **DENY** | |

### 2.7 Migrate

| Attribute | ALLOW/DENY | Notes |
|---|---|---|
| `secretenv.migrate.alias_name` | **DENY** | Fail-closed guard; migrate spans use `secretenv.alias.name` (via `record_alias_name`) rather than a migrate-scoped variant |
| `secretenv.migrate.source_backend_type` | ALLOW | |
| `secretenv.migrate.dest_backend_type` | ALLOW | |
| `secretenv.migrate.source_uri` | **DENY** | Topology |
| `secretenv.migrate.dest_uri` | **DENY** | Topology |
| `secretenv.migrate.source_backend_instance` / `.dest_backend_instance` | **DENY** | Instance names carry env hints (`prod`/`staging`) that fingerprint topology; only backend TYPE is ALLOW |
| `secretenv.migrate.value` | **DENY** | The migrated secret value never appears on any attribute; explicit fail-closed guard row |
| `secretenv.migrate.phase` | ALLOW | Closed enum: `probe` / `read` / `write` / `pointer-flip` / `delete-source` |
| `secretenv.migrate.outcome` | ALLOW | Closed enum |
| `secretenv.migrate.partial_failure_stage` | ALLOW | Closed enum (same as `phase`); reserved. Schema slot is locked but no typed setter is wired yet (a caller lands when the partial-failure path emits it) |
| `secretenv.migrate.delete_source` | ALLOW | bool |
| `secretenv.migrate.transaction_id` | ALLOW | UUIDv4 |
| `secretenv.migrate.collapsed` | ALLOW | bool; `true` when the transaction collapses into a single backend-side atomic operation (no backend exposes this yet; emitted as `false` in v0.18) |

### 2.8 MCP

| Attribute | ALLOW/DENY | Notes |
|---|---|---|
| `secretenv.mcp.tool_name` | ALLOW | Closed enum of registered tools |
| `secretenv.mcp.client_name` | ALLOW | Bounded enum: `claude-code` / `cursor` / `codex` / `vscode-copilot` / `continue` / `cline` / `unknown` |
| `secretenv.mcp.client_version` | ALLOW | |
| `secretenv.mcp.transport` | ALLOW | `stdio` / `http` / `sse` |
| `secretenv.mcp.session_id` | ALLOW | Per-server-session UUID |
| `secretenv.mcp.outcome` | ALLOW | `success` / `error` / `denied` |
| `secretenv.mcp.mutation_confirmed` | ALLOW | bool |
| `secretenv.mcp.argument_alias_name` | ALLOW | Mutation audit needs this |
| `secretenv.mcp.argument_uri` | **DENY** | URI topology |
| `secretenv.mcp.argument_reason` | **DENY** | Prompt-injection vehicle; appears in audit log only, never as an OTel attribute |
| `secretenv.mcp.resolved_value` / `.tool.output_raw` | **DENY** | |

### 2.9 Doctor & gen

| Attribute | ALLOW/DENY | Notes |
|---|---|---|
| `secretenv.doctor.check_level` | ALLOW | |
| `secretenv.doctor.backend_count` | ALLOW | Aggregate |
| `secretenv.doctor.failure_count` | ALLOW | Aggregate |
| `secretenv.gen.password.length` | ALLOW | |
| `secretenv.gen.password.charset_name` | ALLOW | Charset NAME only (e.g. `alphanumeric`); not the charset string |
| `secretenv.gen.password.value` | **DENY** | Obvious |
| `secretenv.gen.password.entropy_bits` | **DENY** | Partial length oracle |

### 2.10 OTel resource

| Attribute | ALLOW/DENY | Notes |
|---|---|---|
| `service.name` | ALLOW | OTel standard resource |
| `service.version` | ALLOW | OTel standard resource |
| `host.name` / `host.arch` / `os.type` / `process.pid` | ALLOW | OTel standard resource conventions. **Note:** `host.name` is set from `hostname::get()`, which on corporate CI runners and bare-metal hosts may surface an FQDN like `ip-10-0-1-23.us-west-2.compute.internal` or `runner-prod-build-42.corp.example.com`, those carry network topology hints. Operators who want to scrub or pin this attribute can override via `OTEL_RESOURCE_ATTRIBUTES=host.name=<override>` at the process env layer; it's last-write-wins against our default emission. |
| `deployment.environment.name` | ALLOW (opt-in only) | NOT auto-inferred from `CI=true`; operator-supplied via `[otel]` config or `OTEL_RESOURCE_ATTRIBUTES` |

**Matrix totals:** 74 ALLOW · 31 DENY (30 hard-DENY + 1 DENY-by-default) · **105 attributes**, mirrors the authoritative `secretenv-telemetry::policy::CANONICAL` table one-for-one. (A few rows group sibling attributes, e.g. the three `.alias.uri*` variants and the three `.value*` variants share a row, so the visible row count is lower than 105.)

---

## 3. Redaction taxonomy (Tier 1 / Tier 2)

- **Tier 1, never emitted.** Secret values, raw backend stderr, raw MCP output, full argv, env var values, account IDs, internal addresses, URI paths. The `SecretEnvSpan` builder makes such emission a compile error.
- **Tier 2, trusted surfaces only.** Operator-stated identifiers, closed-enum outcomes, aggregate counts, timing. Appear on spans, metrics, and `--verbose` output.

**Set-site enforcement.** Every ALLOW attribute has one typed method on `SecretEnvSpan` (e.g. `record_alias_name`, `record_backend_type`). v0.17 ships 26 active setters; the remaining ALLOW attributes are schema-locked and gain setters as callers wire them (metrics, operator UX, or downstream cycles). Adding a setter is a PR-reviewed code change tied to doc entry. No generic `set_attribute(key, value)` escape hatch exists. A CI gate (`scripts/check_tracing_leaks.sh`) fails the build on any `Secret::expose_secret`, `{value}`, `{uri.raw}`, or `{secret}` inside `tracing::*!` macro arguments.

**Scrubbing of `backend.error.message`.** This is **DENY by default**, enabled per-run via `--otel-include-error-detail`. When opted in, the scrubber replaces URIs with `<uri-stripped>`, AWS account numbers with `<aws-account-stripped>`, and high-entropy tokens (32+ chars, base64-safe alphabet) with `<token-stripped>`. Raw backend stderr (`backend.error.cli_stderr`) is always DENY. (v0.19: shipped both scrubber and emission; prior versions had the flag but emission was a no-op.)

---

## 4. Span topology

Root spans correspond to top-level invocations; child spans to logical phases. Span names are stable and part of the audit contract.

**v0.17+ status:**
- **Emitted:** `secretenv.run`, `secretenv.resolution`, `secretenv.backend.fetch`, `secretenv.redact.filter_event`, `secretenv.registry.migrate` (+ 5 phase children: `probe`/`read`/`write`/`pointer_flip`/`delete`), `secretenv.doctor.backend`, `secretenv.mcp.tool.<name>` (all 14 tools), `secretenv.manifest.load`, `secretenv.registry.load`, `secretenv.backend.probe`, `secretenv.exec.prepare`, `secretenv.doctor.registry` (v0.18+).
- **Schema-reserved, not emitted:** `secretenv.exec.flush` (deferred to v0.20; `execve` hand-off covered by explicit `flush_before_exec`), `secretenv.doctor` root, `secretenv.mcp.policy.evaluate`, `secretenv.mcp.confirm`, `secretenv.registry.transaction`, `secretenv.audit.append` (MCP events captured in `audit_log.rs` but not as OTel spans). None affect the security invariants.

### 4.1 `secretenv.run`

```
secretenv.run
├── secretenv.manifest.load
├── secretenv.registry.load
├── secretenv.resolution            (one per alias)
│   ├── secretenv.backend.probe
│   └── secretenv.backend.fetch
├── secretenv.exec.prepare
└── secretenv.exec.flush             (force_flush before execve)
```

### 4.2 `secretenv.registry.migrate`

```
secretenv.registry.migrate
├── secretenv.migrate.probe          (both backends; mutation non-droppable)
├── secretenv.migrate.read           (mutation non-droppable)
├── secretenv.migrate.write          (mutation non-droppable)
├── secretenv.migrate.pointer_flip   (mutation non-droppable)
└── secretenv.migrate.delete         (optional; gated on --delete-source)
```

### 4.3 `secretenv.doctor`

```
secretenv.doctor                     (root; one per `secretenv doctor` invocation)
├── secretenv.doctor.registry        (one per registry; SIBLING of doctor.backend)
├── secretenv.doctor.backend         (one per backend instance)
│   └── secretenv.backend.probe
└── …
```

> **Topology note:** `secretenv.doctor.registry`
> is emitted as a SIBLING of `secretenv.doctor.backend`, not a parent.
> This matches the §4.1 flat-topology compromise: parent-child linkage
> between higher-level orchestration spans and per-resource spans is
> deferred to **v0.20** under the hierarchical-topology pass.
> Earlier revisions of this spec drew the relationship as parent-child;
> that diagram was aspirational, not implemented.

### 4.4 `secretenv.mcp.tool.<name>`

```
secretenv.mcp.tool.set_alias        (or .delete_alias / .migrate_alias / .gen_password / etc.)
├── secretenv.mcp.policy.evaluate
├── secretenv.mcp.confirm            (when ConfirmVia requires it)
├── secretenv.registry.transaction
└── secretenv.audit.append
```

Mutation tool spans (`set_alias`, `delete_alias`, `migrate_alias`, `gen_password`) are non-droppable. See §6.

---

## 5. Metric inventory

| Name | Instrument | Unit | Key attributes | Cardinality notes |
|---|---|---|---|---|
| `secretenv.resolution.duration` | Histogram | `ms` | `registry.name`, `run.outcome`, `alias_count_bucket` | `alias_count` is bucketed (1-5, 6-10, 11-20, 20+); `alias.name` is **NOT** an attribute |
| `secretenv.resolution.count` | Counter | `{resolution}` | `registry.name`, `run.outcome` | Low |
| `secretenv.backend.probe.count` | Counter | `{probe}` | `backend.type`, `backend.instance_name`, `probe.level`, `probe.outcome` | O(instances × 18) |
| `secretenv.backend.fetch.duration` | Histogram | `ms` | `backend.type`, `backend.instance_name`, `fetch.outcome` | O(backends × 3); `alias.name` explicitly excluded |
| `secretenv.redact.events` | Counter | `{event}` | `redact.mode`, `redact.match_context` | Low; `alias.name` excluded |
| `secretenv.mcp.tool.calls` | Counter | `{call}` | `mcp.tool_name`, `mcp.outcome` | Low (closed enum tool names) |
| `secretenv.mcp.tool.duration` | Histogram | `ms` | `mcp.tool_name`, `mcp.outcome` | Low |
| `secretenv.doctor.failure.count` | Counter | `{failure}` | `backend.type`, `backend.instance_name`, `probe.outcome` | Low (failure only; success silent) |
| `secretenv.migrate.operation.count` | Counter | `{operation}` | `migrate.phase`, `migrate.outcome` | Low |
| `secretenv.registry.alias_count` | Gauge (synchronous) | `{alias}` | `registry.name`, `registry.source_index` | Low |

**Histogram buckets:**
- Resolution duration: `50, 100, 250, 500, 1000, 2000, 5000, 10000, 30000` ms
- Backend fetch duration: `50, 100, 250, 500, 1000, 2000, 5000, 10000` ms
- MCP tool duration: `10, 50, 100, 250, 500, 1000, 5000` ms

**Critical cardinality rule:** `secretenv.alias.name` MUST NOT appear as an attribute on any histogram or gauge. It appears only on per-resolution span data and (opt-in) on the `secretenv.alias.resolution.count` counter when the operator sets `SECRETENV_OTEL_ALIAS_METRICS=1`. The opt-in is off by default; orgs with 200+ aliases keep the default.

---

## 6. Sampling

**Default sampler:** `parentbased_always_on`. Secret resolution is rare and high-value (50/developer-day, 500/CI-day typical); sampling drops audit value with minimal cardinality gain.

**Mutation spans are non-droppable.** A custom sampler returns `RecordAndSample` for mutations regardless of parent sampler:

- `secretenv.mcp.tool.set_alias`, `delete_alias`, `migrate_alias`, `gen_password`
- `secretenv.migrate.read`, `write`, `pointer_flip`, `delete`

The canonical set is `MutationSpanName` (`secretenv_telemetry::span`), the single source of truth for span names and sampler whitelist. `secretenv.migrate.probe` is excluded (read-only). This ensures mutation events are never absent from the trace stream.

**Override:**

```bash
OTEL_TRACES_SAMPLER=traceidratio
OTEL_TRACES_SAMPLER_ARG=0.1    # 10% for high-volume CI; mutations still emit at 100%
```

---

## 7. Exporter configuration

| Variable | Effect | Default |
|---|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | gRPC or HTTP/protobuf OTLP endpoint | unset → no-op |
| `OTEL_EXPORTER_OTLP_HEADERS` | `key=value,key=value` auth headers | unset |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `grpc` or `http/protobuf` | `grpc` |
| `OTEL_EXPORTER_OTLP_TIMEOUT` | Export timeout (ms) | `10000` |
| `OTEL_TRACES_EXPORTER` | `otlp` / `console` / `none` | `otlp` if endpoint set |
| `OTEL_METRICS_EXPORTER` | `otlp` / `console` / `none` | `otlp` if endpoint set |
| `OTEL_LOGS_EXPORTER` | `otlp` / `console` / `none` | `otlp` if endpoint set |
| `OTEL_SERVICE_NAME` | Override service name | `secretenv` |
| `OTEL_RESOURCE_ATTRIBUTES` | Additional resource attributes | unset |
| `OTEL_TRACES_SAMPLER` | Sampler name | `parentbased_always_on` |
| `OTEL_TRACES_SAMPLER_ARG` | Sampler arg | none |
| `OTEL_PROPAGATORS` | Context propagators | `tracecontext,baggage` |

**Service name.** Default is `secretenv`. Per-project naming: `OTEL_RESOURCE_ATTRIBUTES=service.name=payments-secretenv`. SecretEnv does not auto-derive from git repo (cardinality explosion + breaks fork comparison).

**Merge precedence:** `OTEL_*` env vars > machine `[otel]` > `secretenv.toml` `[otel]` > defaults.

**No-op default.** When none of `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_TRACES_EXPORTER`, `OTEL_METRICS_EXPORTER` is set, no exporter is installed. Zero startup overhead. OTel deps remain linked but inert.

**Flush before exec().** Before `execve()`, SecretEnv calls `force_flush()` with a **1-second `tokio::time::timeout`**. Slow/unreachable collectors drop spans silently and emit `tracing::debug!` (`otel flush timed out`). Data loss acceptable; latency cliff is not. The `exec_flush.rs` test verifies the bound.

**W3C trace context propagation.** Inbound only. SecretEnv honors `TRACEPARENT` and `TRACESTATE` env vars from parent CI, attaching its root span as a child. Outbound propagation to child processes is deferred (requires instrumenting child binaries; not SecretEnv's responsibility).

---

## 8. Operator UX without a collector

No collector required for observability:

### 8.1 `secretenv run --verbose`

Per-alias resolution timing on stderr:

```
$ secretenv run --verbose -- ./deploy.sh
secretenv: STRIPE_KEY           resolved   124ms  aws-ssm/payments
secretenv: SENTRY_DSN           resolved    87ms  aws-ssm/payments
secretenv: HONEYCOMB_API_KEY    resolved   211ms  1password/personal
secretenv: 3 aliases resolved in 422ms
```

### 8.2 `secretenv doctor --trace`

Local span table. Dry-run resolution against configured registries, in-memory capture, table render:

```
$ secretenv doctor --trace
Spans (dry-run resolution pass):
  secretenv.run                       456ms  outcome=success  aliases=3
    secretenv.resolution              124ms  alias=STRIPE_KEY  outcome=resolved
      secretenv.backend.probe           8ms  backend=aws-ssm   outcome=ok
      secretenv.backend.fetch         108ms  backend=aws-ssm   outcome=ok
    secretenv.resolution               87ms  alias=SENTRY_DSN  outcome=resolved
      ...
```

### 8.3 `OTEL_TRACES_EXPORTER=console`

Writes full span tree to stderr in OTel JSON form. Useful for schema comparison (§2):

```
$ OTEL_TRACES_EXPORTER=console secretenv run -- echo hello
{"name":"secretenv.run","trace_id":"...","span_id":"...","attributes":{...}}
{"name":"secretenv.resolution","parent_span_id":"...","attributes":{...}}
...
```

### 8.4 `secretenv doctor --extensive`

Verifies the configured OTLP endpoint is reachable and accepts a probe span. Reports endpoint, transport, RTT, and any TLS / auth errors.

```
$ secretenv doctor --extensive
OTel collector:
  endpoint    grpc://127.0.0.1:4317
  reachable   yes (RTT 4ms)
  probe span  exported successfully
```

---

## 9. Compliance & audit considerations

**OTel traces are operational data, not compliance audit logs.** No integrity guarantee, no append-only enforcement, no signing. For regulated environments (SOC2, ISO27001, HIPAA), use the **backend's audit trail** (Vault audit log, AWS CloudTrail, 1Password Business events, GCP Cloud Audit Logs).

SecretEnv's MCP layer maintains an append-only audit log at `~/.config/secretenv/audit.log` (configurable via `[mcp].audit_log_path`), with `flock(LOCK_EX)` serialization and rotation. The MCP audit log is the compliance artifact for MCP mutations; OTel spans are operational data.

**Verifiable: no secret value in any OTel attribute.** `SecretEnvSpan` has one typed setter per ALLOW attribute, no generic `set_attribute`. Enforced via: `tests/no_escape_hatch.rs` (absent `set_attribute`), `tests/no_redact_alias_in_otel.rs` (no `set_redact_alias_name`), CI gate `scripts/check_tracing_leaks.sh` (fails on `Secret::expose_secret`, `{value}`, `{uri.raw}`, `{secret}` in `tracing::*!`). Structural, not runtime.

---

## 10. FAQ

**Does SecretEnv emit secret values to my collector?**
No. This is enforced at compile time. `SecretEnvSpan` has no value-shaped setter and no generic `set_attribute` escape hatch. Any value-shaped attribute requires a typed setter, which PR review rejects.

**What happens when no OTLP endpoint is configured?**
No-op. No exporter, no `TracerProvider`, no spans. Zero overhead. OTel deps remain linked but inert.

**Can I use Prometheus?**
Use the OTel Collector with a Prometheus scrape endpoint on the collector side. SecretEnv does not ship a Prometheus pull exporter (CLI binaries cannot reliably expose HTTP servers). OTel collector is the supported source.

**Why is `alias.name` ALLOWED but `alias.uri` DENIED?**
`alias.name` is the operator's diagnostic handle (first incident question). URIs reveal backend topology (`aws-ssm:///payments/stripe/prod-rotation-2`), enabling credential enumeration and competitive intelligence.

**What is the flush guarantee before `exec()`?**
1-second timeout. If `force_flush()` does not complete, pending spans drop with a `tracing::debug!` message. Data loss acceptable; latency cliff is not.

**Does SecretEnv propagate trace context to my child process?**
No. Inbound only: SecretEnv honors `TRACEPARENT`/`TRACESTATE` from parent CI, attaching its root span to the parent trace. Outbound propagation (setting env vars for the child) is v1.0+ (requires child-side instrumentation).

**How do I disable OTel without unsetting `OTEL_EXPORTER_OTLP_ENDPOINT`?**
Set `OTEL_TRACES_EXPORTER=none` (or per-signal variant). SecretEnv does not ship a `[telemetry] enabled = false` config toggle (committed `false` would silently disable team-wide, a footgun). Env var is the correct kill switch.

---

## Related

- [Redaction](redact.md): redaction modes and the `secretenv.redact.*` attributes
- [Registry migrate](migrate.md): emits the migrate span tree
- [MCP server](mcp.md): emits `secretenv.mcp.tool.<name>` spans
- [CLI Reference: `secretenv doctor`](cli-reference-full.md#secretenv-doctor): `doctor --trace` renders a local span table without a collector
