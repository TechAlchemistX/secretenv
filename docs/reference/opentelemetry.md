# OpenTelemetry

SecretEnv emits OpenTelemetry traces, metrics, and logs for every secret resolution, backend probe, MCP tool call, redaction event, and migration. Telemetry is **opt-in** — set `OTEL_EXPORTER_OTLP_ENDPOINT` to point at any OTLP-compatible collector (Jaeger, Tempo, Honeycomb, Datadog, the OTel collector itself). With no endpoint configured, SecretEnv installs no exporter and has zero startup overhead.

This document is the **audit-facing contract**. Every attribute SecretEnv emits is enumerated below with an explicit ALLOW/DENY classification. The classifications are enforced at compile time: the typed `SecretEnvSpan` builder in `secretenv-telemetry` exposes one method per ALLOW attribute and no method for any DENY attribute. There is no `set_attribute(key, value)` escape hatch.

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

The full attribute matrix. **ALLOW** attributes have a typed setter on `SecretEnvSpan` and may appear on emitted spans. **DENY** attributes have no setter and cannot be emitted; the typed builder enforces this at compile time.

### 2.1 SecretEnv core

| Attribute | ALLOW/DENY | Notes |
|---|---|---|
| `secretenv.version` | ALLOW | Static binary version |
| `secretenv.run_id` | ALLOW | UUIDv4 per invocation |
| `secretenv.command` | ALLOW | Closed enum: `run` / `get` / `migrate` / `doctor` / `mcp` / `redact` |
| `secretenv.exit_code` | ALLOW | int |
| `secretenv.duration_ms` | ALLOW | int |

### 2.2 Alias

| Attribute | ALLOW/DENY | Notes |
|---|---|---|
| `secretenv.alias.name` | ALLOW | Operator-stated; hot-path diagnostic |
| `secretenv.alias.env_var` | ALLOW | Env var name (e.g. `STRIPE_KEY`); never the value |
| `secretenv.alias.count` | ALLOW | Aggregate |
| `secretenv.alias.cascade_layer_index` | ALLOW | Which cascade layer satisfied the lookup |
| `secretenv.alias.outcome` | ALLOW | Closed enum: `resolved` / `not_found` / `default` |
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
| `secretenv.backend.auth_method` | ALLOW | Closed enum: `oidc` / `token` / `iam` / `env`; never the credential |
| `secretenv.backend.probe.level` | ALLOW | `l1_cli` / `l2_auth` / `l3_read` |
| `secretenv.backend.probe.outcome` | ALLOW | Closed enum |
| `secretenv.backend.error.kind` | ALLOW | Closed enum `SecretEnvErrorKind` |
| `secretenv.backend.error.message` | **DENY by default** | Per-run opt-in via `--otel-include-error-detail`; even then, scrubbed via SEC-INV-20 before any emission |
| `secretenv.backend.error.cli_stderr` | **DENY** | Raw stderr; topology + credential leak risk |
| `secretenv.backend.fetch.outcome` | ALLOW | Operational |
| `secretenv.backend.fetch.timeout_ms` | ALLOW | |
| `secretenv.backend.fetch.attempt` | ALLOW | |
| `secretenv.backend.fetch.duration_ms` | ALLOW | |

### 2.4 Registry & manifest

| Attribute | ALLOW/DENY | Notes |
|---|---|---|
| `secretenv.registry.name` | ALLOW | Registry config name |
| `secretenv.registry.selection` | ALLOW | `named` / `direct-uri` (never the URI itself) |
| `secretenv.registry.source_count` | ALLOW | Aggregate |
| `secretenv.registry.source_index` | ALLOW | Aggregate |
| `secretenv.registry.source_uri` | **DENY** | Registry document URI; topology |
| `secretenv.manifest.path` | ALLOW (relative only) | Relative to CWD; never absolute |
| `secretenv.manifest.alias_count` | ALLOW | Aggregate |
| `secretenv.manifest.default_count` | ALLOW | Aggregate |

### 2.5 Resolution & run

| Attribute | ALLOW/DENY | Notes |
|---|---|---|
| `secretenv.resolution.outcome` | ALLOW | |
| `secretenv.resolution.cache_hit` | ALLOW | |
| `secretenv.resolution.attempt` | ALLOW | |
| `secretenv.resolution.latency_ms` | ALLOW | |
| `secretenv.run.dry_run` | ALLOW | bool |
| `secretenv.run.verbose` | ALLOW | bool |
| `secretenv.run.command_name` | ALLOW | Basename of `argv[0]` only — any absolute or relative path prefix is stripped before emission to avoid leaking host filesystem layout (Phase 9b Sec F-1) |
| `secretenv.run.command_argv` | **DENY** | Full argv may contain secrets |
| `secretenv.run.env_var_count` | ALLOW | Aggregate |
| `secretenv.run.env_var_value` | **DENY** | |
| `secretenv.run.outcome` | ALLOW | |
| `secretenv.run.failed_alias_count` | ALLOW | Aggregate |

### 2.6 Redact

| Attribute | ALLOW/DENY | Notes |
|---|---|---|
| `secretenv.redact.mode` | ALLOW | `runtime` / `post_hoc` / `disabled` |
| `secretenv.redact.match_count` | ALLOW | Aggregate |
| `secretenv.redact.byte_count` | ALLOW | Aggregate |
| `secretenv.redact.stream` | ALLOW | `stdout` / `stderr` |
| `secretenv.redact.line_number` | ALLOW | |
| `secretenv.redact.replacement_token` | ALLOW | The literal token written in place of the match |
| `secretenv.redact.match_context` | ALLOW | `exact` / `substring` / `base64_form` |
| `secretenv.redact.source` | ALLOW | Closed enum: `mode-a` (runtime pipe) / `mode-b` (post-hoc file rewrite) / `stripped`. Distinguishes which redaction path scrubbed the match for percentile-by-mode triage. |
| `secretenv.redact.alias_name` | **DENY in OTel** | SEC-INV-19. The alias name appears in the operator-local redaction token; it does **not** appear as an OTel attribute. (Resolves the conflict between the OTel spec's permissive position and the security invariant; security wins for OTel emission.) |
| `secretenv.redact.matched_value` / `.value_length` | **DENY** | |

### 2.7 Migrate

| Attribute | ALLOW/DENY | Notes |
|---|---|---|
| `secretenv.migrate.alias_name` | ALLOW | |
| `secretenv.migrate.source_backend_type` | ALLOW | |
| `secretenv.migrate.dest_backend_type` | ALLOW | |
| `secretenv.migrate.source_uri` | **DENY** | Topology |
| `secretenv.migrate.dest_uri` | **DENY** | Topology |
| `secretenv.migrate.phase` | ALLOW | Closed enum: `probe` / `read` / `write` / `pointer_flip` / `delete` |
| `secretenv.migrate.outcome` | ALLOW | Closed enum |
| `secretenv.migrate.partial_failure_stage` | ALLOW | Closed enum (same as `phase`) |
| `secretenv.migrate.delete_source` | ALLOW | bool |
| `secretenv.migrate.transaction_id` | ALLOW | UUIDv4 |

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
| `secretenv.mcp.argument_reason` | **DENY** | SEC-INV-12. Prompt-injection vehicle; appears in audit log only, never as an OTel attribute |
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
| `host.name` / `host.arch` / `os.type` / `process.pid` | ALLOW | OTel standard resource conventions |
| `deployment.environment.name` | ALLOW (opt-in only) | NOT auto-inferred from `CI=true`; operator-supplied via `[otel]` config or `OTEL_RESOURCE_ATTRIBUTES` |

**Matrix totals:** 51 ALLOW · 25 DENY · 76 entries.

---

## 3. Redaction taxonomy (Tier 1 / Tier 2)

SecretEnv classifies every data element into one of two tiers:

- **Tier 1 — Never emitted to any surface.** Secret values themselves, raw backend stderr, raw MCP tool output, full argv, environment variable values, backend account IDs, internal addresses, URI paths. No code path inside SecretEnv emits a Tier 1 element to telemetry — and the `SecretEnvSpan` builder makes such emission a compile error rather than a runtime check.
- **Tier 2 — Emitted to trusted surfaces only.** Operator-stated identifiers (alias names, registry names, instance labels), closed-enum operational outcomes, aggregate counts, timing data. These appear on spans, on metrics, and in the operator's terminal under `--verbose`.

**Set-site enforcement (SEC-INV-04).** Every ALLOW attribute that any code path emits has exactly one typed method on `SecretEnvSpan` (e.g. `record_alias_name`, `record_backend_type`). v0.17 ships the 26 setters active callers in `secretenv-core` / `secretenv-migrate` / `secretenv-mcp` / `secretenv-cli` need; the remaining ALLOW attributes listed in §2 are part of the locked schema and gain typed setters as Phase 4/6 work (metrics, operator UX) or downstream cycles wire callers for them — adding a new setter is itself a PR-reviewed code change, so a setter cannot land without the corresponding doc entry. The builder does **not** expose a generic `set_attribute(key: &str, value: &str)`, so no call site can smuggle an attribute that lacks a setter. A CI grep gate (`scripts/check_tracing_leaks.sh`) fails the build if any call site references `Secret::expose_secret`, `{value}`, `{uri.raw}`, or `{secret}` inside a `tracing::*!` macro argument list.

**Scrubbing of `backend.error.message`.** The single exception to the "no free-string attribute" rule is `backend.error.message`, which is **DENY by default**. Operators may opt in per-run via `--otel-include-error-detail`. Even when opted in, the message is passed through the SEC-INV-20 scrubber before emission: URI-shaped substrings, AWS 12-digit account numbers, and high-entropy tokens (> 20 chars mixed case + digits) are replaced with `<redacted>`. Raw backend stderr (`backend.error.cli_stderr`) remains DENY in all cases.

> **v0.17 status.** The `--otel-include-error-detail` flag is **not yet shipped** — `backend.error.message` is unconditionally DENY in v0.17 (structurally enforced by absence of the `SecretEnvSpan::record_error_message` setter). The flag + scrubber wiring lands in v0.18. The DENY-by-default posture above is therefore the only posture in v0.17. Tracked at [[v0.17-deferred-items]] as the only spec-promised surface explicitly deferred from v0.17.0.

---

## 4. Span topology

Root spans correspond to top-level invocations. Child spans correspond to logical phases. Span names are stable and form part of the audit contract.

> **v0.17 shipped subset.** v0.17 ships the load-bearing spans:
> `secretenv.run`, `secretenv.resolution`, `secretenv.backend.fetch`,
> `secretenv.redact.filter_event`, `secretenv.registry.migrate` (+ its
> 5 phase children: `probe` / `read` / `write` / `pointer_flip` /
> `delete`), `secretenv.doctor.backend`, and `secretenv.mcp.tool.<name>`
> for all 14 MCP tools. The following **11 spans** appear in the
> topology trees below as schema-reserved but are **not emitted**
> in v0.17:
>
> - §4.1 run subtree: `secretenv.manifest.load`,
>   `secretenv.registry.load`, `secretenv.backend.probe` (as a child
>   under resolution), `secretenv.exec.prepare`, `secretenv.exec.flush`
> - §4.3 doctor subtree: `secretenv.doctor` root,
>   `secretenv.doctor.registry`
> - §4.4 MCP subtree: `secretenv.mcp.policy.evaluate`,
>   `secretenv.mcp.confirm`, `secretenv.registry.transaction`,
>   `secretenv.audit.append`
>
> The hand-off to `execve` is covered by an explicit
> `flush_before_exec` call rather than an `exec.flush` span. The MCP
> policy/confirm/audit events are captured in `audit_log.rs` as
> structured records but not as OTel spans. These will land as
> v0.17.x hygiene chips; their absence does not affect any SEC-INV
> invariant.

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
secretenv.doctor
├── secretenv.doctor.registry        (one per registry)
└── secretenv.doctor.backend         (one per backend instance)
    └── secretenv.backend.probe
```

### 4.4 `secretenv.mcp.tool.<name>`

```
secretenv.mcp.tool.set_alias        (or .delete_alias / .migrate_alias / .gen_password / etc.)
├── secretenv.mcp.policy.evaluate
├── secretenv.mcp.confirm            (when ConfirmVia requires it)
├── secretenv.registry.transaction
└── secretenv.audit.append
```

Mutation tool spans (`set_alias`, `delete_alias`, `migrate_alias`, `gen_password`) are non-droppable — see §6.

---

## 5. Metric inventory

| Name | Instrument | Unit | Key attributes | Cardinality notes |
|---|---|---|---|---|
| `secretenv.resolution.duration` | Histogram | `ms` | `registry.name`, `run.outcome`, `alias_count_bucket` | `alias_count` is bucketed (1-5, 6-10, 11-20, 20+); `alias.name` is **NOT** an attribute |
| `secretenv.resolution.count` | Counter | `{resolution}` | `registry.name`, `run.outcome` | Low |
| `secretenv.backend.probe.count` | Counter | `{probe}` | `backend.type`, `backend.instance_name`, `probe.level`, `probe.outcome` | O(instances × 12) |
| `secretenv.backend.fetch.duration` | Histogram | `ms` | `backend.type`, `backend.instance_name`, `fetch.outcome` | O(backends × 3); `alias.name` explicitly excluded |
| `secretenv.redact.events` | Counter | `{event}` | `redact.mode`, `redact.match_context` | Low; `alias.name` excluded per SEC-INV-19 |
| `secretenv.mcp.tool.calls` | Counter | `{call}` | `mcp.tool_name`, `mcp.outcome` | Low (closed enum tool names) |
| `secretenv.mcp.tool.duration` | Histogram | `ms` | `mcp.tool_name`, `mcp.outcome` | Low |
| `secretenv.doctor.failure.count` | Counter | `{failure}` | `backend.type`, `backend.instance_name`, `probe.outcome` | Low (failure only; success silent) |
| `secretenv.migrate.operation.count` | Counter | `{operation}` | `migrate.phase`, `migrate.outcome` | Low |
| `secretenv.registry.alias_count` | Gauge (observed) | `{alias}` | `registry.name`, `registry.source_index` | Low |

**Histogram buckets:**
- Resolution duration: `50, 100, 250, 500, 1000, 2000, 5000, 10000, 30000` ms
- Backend fetch duration: `50, 100, 250, 500, 1000, 2000, 5000, 10000` ms
- MCP tool duration: `10, 50, 100, 250, 500, 1000, 5000` ms

**Critical cardinality rule:** `secretenv.alias.name` MUST NOT appear as an attribute on any histogram or gauge. It appears only on per-resolution span data and (opt-in) on the `secretenv.alias.resolution.count` counter when the operator sets `SECRETENV_OTEL_ALIAS_METRICS=1`. The opt-in is off by default; orgs with 200+ aliases keep the default.

---

## 6. Sampling

**Default sampler:** `parentbased_always_on`. Secret resolution is a rare, high-value event (50/developer-day, 500/CI-day typical). Sampling drops audit value without meaningful cardinality benefit.

**Mutation spans are non-droppable.** A custom sampler wrapper returns `RecordAndSample` for spans whose name matches the mutation set, regardless of the parent sampler decision:

- `secretenv.mcp.tool.set_alias`
- `secretenv.mcp.tool.delete_alias`
- `secretenv.mcp.tool.migrate_alias`
- `secretenv.mcp.tool.gen_password`
- `secretenv.migrate.read`
- `secretenv.migrate.write`
- `secretenv.migrate.pointer_flip`

This implements SEC-INV-22: mutation events are never absent from the trace stream, even when the operator has configured aggressive ratio sampling for high-volume CI.

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

**Service name.** Default is `secretenv`. Operators using per-project naming should set `OTEL_RESOURCE_ATTRIBUTES=service.name=payments-secretenv`. SecretEnv deliberately does **not** auto-derive the service name from the git repo name — that introduces cardinality explosions in trace backends and breaks comparison across forks.

**Merge precedence (highest wins):** `OTEL_*` env vars > machine config `[otel]` > `secretenv.toml` `[otel]` > SecretEnv defaults.

**No-op default.** When none of `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_TRACES_EXPORTER`, `OTEL_METRICS_EXPORTER` is set, SecretEnv installs no exporter. Zero startup overhead. Zero noise. The OTel deps are still linked in but no `TracerProvider` is created.

**Flush before exec().** Before `secretenv run` calls `execve()` to hand off to the child binary, SecretEnv invokes `force_flush()` on the configured exporter with a **bounded 1-second `tokio::time::timeout`**. If the collector is slow or unreachable, pending spans are dropped silently and a `tracing::debug!` event is emitted (`otel flush timed out; dropping pending spans`). A down or slow collector degrades to data loss, never to a latency cliff on every `secretenv run` invocation. The SEC-INV-22 test `exec_flush.rs` verifies this bound.

**W3C trace context propagation.** Inbound only in v0.17. SecretEnv honors `TRACEPARENT` and `TRACESTATE` env vars set by parent CI systems, attaching SecretEnv's root span as a child of the parent trace. SecretEnv does **not** propagate context out to the child process started by `secretenv run` — wiring arbitrary child binaries into the trace tree requires instrumenting those binaries, which is not SecretEnv's responsibility. Child-process propagation is deferred to v1.0+.

---

## 8. Operator UX without a collector

You do not need a collector to get observability value from SecretEnv. Three modes ship in v0.17:

### 8.1 `secretenv run --verbose`

Per-alias resolution timing on stderr. No collector required.

```
$ secretenv run --verbose -- ./deploy.sh
secretenv: STRIPE_KEY           resolved   124ms  aws-ssm/payments
secretenv: SENTRY_DSN           resolved    87ms  aws-ssm/payments
secretenv: HONEYCOMB_API_KEY    resolved   211ms  1password/personal
secretenv: 3 aliases resolved in 422ms
```

### 8.2 `secretenv doctor --trace`

Local span table render. Runs a dry-run resolution pass against the configured registries, captures spans to an in-process `InMemorySpanExporter`, and renders the result. No OTLP endpoint required.

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

For ad-hoc debugging of a single invocation, the stdout exporter writes the full span tree to stderr in OTel's standard JSON form. Useful when comparing emitted spans to the schema in §2.

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

**OTel traces are operational data, not compliance audit logs.** SecretEnv's OTel emission has no integrity guarantee, no append-only enforcement, no signing, and no replay protection. Traces are best-effort observational data for operators and SREs. For regulated environments (SOC2, ISO27001, HIPAA), use the **backend's own audit trail** as the compliance artifact:

- **Vault** — Vault audit log (file or socket sink)
- **OpenBao** — same as Vault
- **AWS Secrets Manager / SSM** — AWS CloudTrail events
- **1Password** — 1Password Business audit events
- **GCP Secret Manager** — Cloud Audit Logs

SecretEnv's MCP layer additionally maintains its own append-only audit log at `~/.config/secretenv/audit.log` (configurable via `[mcp].audit_log_path`), with `flock(LOCK_EX)` serialization and size-based rotation. The MCP audit log is the compliance artifact for MCP-mediated mutations; OTel spans on those mutations are operational data only.

**Verifiable claim: no secret value reaches any OTel attribute.** The `SecretEnvSpan` builder exposes one typed setter per ALLOW attribute and no generic `set_attribute` method. The `secretenv-telemetry/tests/no_escape_hatch.rs` compile-test asserts the absence of `set_attribute`. The `secretenv-telemetry/tests/no_redact_alias_in_otel.rs` test asserts `set_redact_alias_name` does not exist (SEC-INV-19). The CI grep gate `scripts/check_tracing_leaks.sh` fails the build on any reference to `Secret::expose_secret`, `{value}`, `{uri.raw}`, or `{secret}` inside a `tracing::*!` macro. These are structural enforcements, not runtime checks.

---

## 10. FAQ

**Does SecretEnv emit secret values to my collector?**
No. SEC-INV-04 enforces this at compile time. The `SecretEnvSpan` builder has no method to set a value-shaped attribute, and there is no `set_attribute(key, value)` escape hatch. Adding a value-shaped attribute requires writing a typed setter, which a PR review would reject.

**What happens when no OTLP endpoint is configured?**
No-op. SecretEnv installs no exporter, creates no `TracerProvider`, and emits no spans. Zero startup overhead. The OTel deps are linked in but inert.

**Can I use Prometheus?**
Use the OpenTelemetry Collector with a Prometheus scrape endpoint on the collector side. SecretEnv does not ship a Prometheus pull exporter — a CLI binary cannot reliably expose an HTTP server given its short lifetime. The OTel collector is the supported scrape source.

**Why is `alias.name` ALLOWED but `alias.uri` DENIED?**
Alias names are the operator's diagnostic handle — "which secret failed to resolve" is the first question on any incident, and `alias.name` is the answer. Alias URIs reveal backend topology (`aws-ssm:///payments/stripe/prod-rotation-2`), which is a credential-enumeration surface and a competitive-intelligence leak.

**What is the flush guarantee before `exec()`?**
1-second bounded timeout. If `force_flush()` does not complete within 1s, pending spans drop and a `tracing::debug!` message is emitted. A slow collector cannot turn `secretenv run` into a latency cliff. Trade-off accepted: better data loss than `exec()` blocking.

**Does SecretEnv propagate trace context to my child process?**
No. SecretEnv honors `TRACEPARENT` / `TRACESTATE` env vars set by a parent CI system (inbound propagation), attaching its root span to the parent trace. SecretEnv does **not** set those env vars for the child started by `secretenv run` — instrumenting arbitrary child binaries to honor W3C context is the child's responsibility. Outbound propagation is a v1.0+ item.

**How do I disable OTel without unsetting `OTEL_EXPORTER_OTLP_ENDPOINT`?**
Set `OTEL_TRACES_EXPORTER=none` (or the per-signal variant). SecretEnv deliberately does not ship a `[telemetry] enabled = false` config-file toggle — a committed `false` value would silently disable OTel team-wide, which is a footgun. The env var is the correct kill switch.

---

## Related

- [`docs/reference/redact.md`](redact.md) — redaction modes; how matches relate to `secretenv.redact.*` attributes
- [`docs/reference/migrate.md`](migrate.md) — `secretenv registry migrate`; emits the migrate span tree
- [`docs/reference/mcp.md`](mcp.md) — MCP tool surface; emits `secretenv.mcp.tool.<name>` spans
- [`docs/reference/configuration.md`](configuration.md) — `[otel]` table in `secretenv.toml`
