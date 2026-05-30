// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 3 integration test: drives `SecretEnvSpan::record_*` methods
//! against an `InMemorySpanExporter` and asserts that every recorder
//! emits the expected `OTel` attribute key / value to the underlying
//! span.
//!
//! This is the verifiable proof of the doc's claim that "every ALLOW
//! attribute setter wires 1:1 to a typed `OTel` attribute" —
//! exercised through the same global tracer the production CLI uses.

use opentelemetry::global;
use opentelemetry::Value;
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SimpleSpanProcessor};

use secretenv_telemetry::{
    AliasOutcome, AuthMethod, BackendType, MigrateOutcome, MigratePhase, RedactionSource,
    RedactionStream, SecretEnvCommand, SecretEnvErrorKind, SecretEnvSpan,
};

/// Build + install an exporter-backed global `TracerProvider`,
/// returning the exporter so the caller can read flushed spans after
/// dropping the span.
fn install_in_memory_exporter() -> InMemorySpanExporter {
    let exporter = InMemorySpanExporter::default();
    let provider = SdkTracerProvider::builder()
        .with_span_processor(SimpleSpanProcessor::new(exporter.clone()))
        .build();
    // Replace whatever the noop default was. Subsequent set_tracer_provider
    // calls (e.g. by `secretenv_telemetry::init` in a different process)
    // would override us; in this test binary we are the sole writer.
    global::set_tracer_provider(provider);
    exporter
}

fn attr<'a>(span: &'a opentelemetry_sdk::trace::SpanData, key: &str) -> Option<&'a Value> {
    span.attributes.iter().find(|kv| kv.key.as_str() == key).map(|kv| &kv.value)
}

#[test]
fn every_active_setter_emits_its_typed_attribute() {
    let exporter = install_in_memory_exporter();

    {
        let (mut span, _guard) = SecretEnvSpan::start("secretenv.test");
        span.record_version("0.17.0")
            .record_run_id("11111111-1111-1111-1111-111111111111")
            .record_command(SecretEnvCommand::Run)
            .record_exit_code(42)
            .record_duration_ms(1500)
            .record_alias_name("STRIPE_KEY")
            .record_alias_env_var("STRIPE_API_KEY")
            .record_alias_count(7)
            .record_cascade_layer_index(2)
            .record_alias_outcome(AliasOutcome::Ok)
            .record_backend_type(BackendType::AwsSsm)
            .record_backend_instance("payments")
            .record_backend_region("us-east-1")
            .record_backend_cli_name("aws")
            .record_backend_cli_version("2.34.35")
            .record_backend_auth_method(AuthMethod::CliSession)
            .record_error_kind(SecretEnvErrorKind::BackendAuthFailed)
            .record_process_command_name("deploy.sh")
            .record_process_env_var_count(12)
            .record_redact_match_count(3)
            .record_redact_byte_count(120)
            .record_redact_stream(RedactionStream::Stdout)
            .record_redact_source(RedactionSource::ModeA)
            .record_migrate_phase(MigratePhase::PointerFlip)
            .record_migrate_outcome(MigrateOutcome::Ok)
            .record_migrate_source_backend_type("aws-ssm")
            .record_migrate_dest_backend_type("vault")
            .record_migrate_delete_source(true)
            .record_migrate_transaction_id("22222222-2222-2222-2222-222222222222");
    } // span drops → ends → SimpleSpanProcessor flushes synchronously

    let Ok(spans) = exporter.get_finished_spans() else {
        panic!("InMemorySpanExporter unreadable");
    };
    assert_eq!(spans.len(), 1, "exactly one span emitted");
    let s = &spans[0];

    assert_eq!(s.name.as_ref(), "secretenv.test");

    // Strings.
    assert_eq!(attr(s, "secretenv.version"), Some(&Value::from("0.17.0".to_owned())));
    assert_eq!(
        attr(s, "secretenv.run_id"),
        Some(&Value::from("11111111-1111-1111-1111-111111111111".to_owned())),
    );
    assert_eq!(attr(s, "secretenv.command"), Some(&Value::from("run".to_owned())));
    assert_eq!(attr(s, "secretenv.alias.name"), Some(&Value::from("STRIPE_KEY".to_owned())));
    assert_eq!(attr(s, "secretenv.alias.env_var"), Some(&Value::from("STRIPE_API_KEY".to_owned())),);
    assert_eq!(attr(s, "secretenv.backend.type"), Some(&Value::from("aws-ssm".to_owned())));
    assert_eq!(
        attr(s, "secretenv.backend.instance_name"),
        Some(&Value::from("payments".to_owned())),
    );
    assert_eq!(attr(s, "secretenv.backend.region"), Some(&Value::from("us-east-1".to_owned())));
    assert_eq!(attr(s, "secretenv.backend.cli.name"), Some(&Value::from("aws".to_owned())));
    assert_eq!(attr(s, "secretenv.backend.cli.version"), Some(&Value::from("2.34.35".to_owned())),);
    assert_eq!(attr(s, "secretenv.run.command_name"), Some(&Value::from("deploy.sh".to_owned())));
    assert_eq!(
        attr(s, "secretenv.migrate.source_backend_type"),
        Some(&Value::from("aws-ssm".to_owned())),
    );
    assert_eq!(
        attr(s, "secretenv.migrate.dest_backend_type"),
        Some(&Value::from("vault".to_owned())),
    );
    assert_eq!(
        attr(s, "secretenv.migrate.transaction_id"),
        Some(&Value::from("22222222-2222-2222-2222-222222222222".to_owned())),
    );

    // Integers.
    assert_eq!(attr(s, "secretenv.exit_code"), Some(&Value::I64(42)));
    assert_eq!(attr(s, "secretenv.duration_ms"), Some(&Value::I64(1500)));
    assert_eq!(attr(s, "secretenv.alias.count"), Some(&Value::I64(7)));
    assert_eq!(attr(s, "secretenv.alias.cascade_layer_index"), Some(&Value::I64(2)));
    assert_eq!(attr(s, "secretenv.run.env_var_count"), Some(&Value::I64(12)));
    assert_eq!(attr(s, "secretenv.redact.match_count"), Some(&Value::I64(3)));
    assert_eq!(attr(s, "secretenv.redact.byte_count"), Some(&Value::I64(120)));

    // Bool.
    assert_eq!(attr(s, "secretenv.migrate.delete_source"), Some(&Value::Bool(true)));

    // Closed-enum kebab-case strings.
    assert_eq!(attr(s, "secretenv.alias.outcome"), Some(&Value::from("ok")));
    assert_eq!(attr(s, "secretenv.backend.auth_method"), Some(&Value::from("cli-session")));
    assert_eq!(attr(s, "secretenv.backend.error.kind"), Some(&Value::from("backend-auth-failed")),);
    assert_eq!(attr(s, "secretenv.migrate.phase"), Some(&Value::from("pointer-flip")));
    assert_eq!(attr(s, "secretenv.migrate.outcome"), Some(&Value::from("ok")));

    // Redaction stream + source enum values exist (exact value strings
    // live in their respective enum impls; we just confirm presence to
    // avoid duplicating the enum's canonical kebab here).
    assert!(attr(s, "secretenv.redact.stream").is_some());
    assert!(attr(s, "secretenv.redact.source").is_some());

    // SEC-INV-19 negative check: the alias-name attribute on a redact
    // span never exists, because the setter does not exist. We assert
    // its absence here for belt-and-suspenders defense in case a
    // future refactor accidentally introduces one.
    assert!(attr(s, "secretenv.redact.alias_name").is_none());
}
