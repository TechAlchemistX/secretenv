// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Probe definitions + execution for `detect_password_managers`.
//!
//! Every supported backend type lists the CLI binary it depends on
//! plus the argv that probes authentication. Probes are run
//! concurrently with a per-probe timeout (`PROBE_TIMEOUT_SECS`);
//! their output is intentionally discarded — only exit status is
//! returned to the agent. Capturing stdout/stderr could leak data
//! (e.g. `op account list` echoes account metadata; `aws sts
//! get-caller-identity` echoes an account ID + ARN).

use std::process::Stdio;
use std::time::Duration;

use futures::future::join_all;
use tokio::process::Command;
use tokio::time::timeout;

use crate::boundary::{AuthStatus, PasswordManagerDetection};

/// Per-probe wall-clock cap. Long enough for a network round-trip
/// (cloud auth probes hit the provider), short enough that 14
/// concurrent probes total under 5s.
const PROBE_TIMEOUT_SECS: u64 = 4;

/// One supported-backend probe specification.
struct ProbeSpec {
    backend_type: &'static str,
    cli_binary: &'static str,
    auth_probe_argv: &'static [&'static str],
}

/// Every backend CLI the v0.16 build line knows how to probe.
/// Mirrors `secretenv-cli/src/backends_init.rs` factory list; the
/// `local` factory has no CLI / no auth so it is intentionally not
/// listed.
const PROBES: &[ProbeSpec] = &[
    ProbeSpec {
        backend_type: "1password",
        cli_binary: "op",
        auth_probe_argv: &["op", "account", "list"],
    },
    ProbeSpec {
        backend_type: "vault",
        cli_binary: "vault",
        auth_probe_argv: &["vault", "token", "lookup"],
    },
    ProbeSpec {
        backend_type: "openbao",
        cli_binary: "bao",
        auth_probe_argv: &["bao", "token", "lookup"],
    },
    ProbeSpec {
        backend_type: "aws-ssm",
        cli_binary: "aws",
        auth_probe_argv: &["aws", "sts", "get-caller-identity"],
    },
    ProbeSpec {
        backend_type: "aws-secrets",
        cli_binary: "aws",
        auth_probe_argv: &["aws", "sts", "get-caller-identity"],
    },
    ProbeSpec {
        backend_type: "gcp",
        cli_binary: "gcloud",
        auth_probe_argv: &["gcloud", "auth", "print-access-token"],
    },
    ProbeSpec {
        backend_type: "azure",
        cli_binary: "az",
        auth_probe_argv: &["az", "account", "show"],
    },
    ProbeSpec {
        backend_type: "keychain",
        cli_binary: "security",
        auth_probe_argv: &["security", "list-keychains"],
    },
    ProbeSpec {
        backend_type: "doppler",
        cli_binary: "doppler",
        auth_probe_argv: &["doppler", "me"],
    },
    ProbeSpec {
        backend_type: "infisical",
        cli_binary: "infisical",
        auth_probe_argv: &["infisical", "user"],
    },
    ProbeSpec {
        backend_type: "keeper",
        cli_binary: "keeper",
        auth_probe_argv: &["keeper", "this-device"],
    },
    ProbeSpec {
        backend_type: "cf-kv",
        cli_binary: "wrangler",
        auth_probe_argv: &["wrangler", "whoami"],
    },
    ProbeSpec {
        backend_type: "conjur",
        cli_binary: "conjur",
        auth_probe_argv: &["conjur", "whoami"],
    },
    ProbeSpec {
        backend_type: "bitwarden-sm",
        cli_binary: "bws",
        auth_probe_argv: &["bws", "project", "list"],
    },
];

/// Run every probe concurrently and return one detection per spec.
/// Probes inherit the server's env so credentials like
/// `BWS_ACCESS_TOKEN` / `VAULT_TOKEN` are visible.
pub async fn run_all_probes() -> Vec<PasswordManagerDetection> {
    join_all(PROBES.iter().map(probe_one)).await
}

async fn probe_one(spec: &ProbeSpec) -> PasswordManagerDetection {
    let argv: Vec<String> = spec.auth_probe_argv.iter().map(|s| (*s).to_owned()).collect();
    let status = run_with_timeout(spec).await;

    PasswordManagerDetection {
        backend_type: spec.backend_type.to_owned(),
        cli_binary: spec.cli_binary.to_owned(),
        auth_status: status,
        auth_probe_argv: argv,
    }
}

async fn run_with_timeout(spec: &ProbeSpec) -> AuthStatus {
    let mut cmd = Command::new(spec.auth_probe_argv[0]);
    cmd.args(&spec.auth_probe_argv[1..]);
    // Drop output bytes — Null sinks both pipes so the probe cannot
    // leak data into our log buffers. stdin null so probes that read
    // from stdin (some interactive flows) fail fast instead of hanging.
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());

    let probe_fut = async {
        match cmd.status().await {
            Ok(st) if st.success() => AuthStatus::Authenticated,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => AuthStatus::CliNotInstalled,
            Ok(_) | Err(_) => AuthStatus::NotAuthenticated,
        }
    };

    timeout(Duration::from_secs(PROBE_TIMEOUT_SECS), probe_fut)
        .await
        .unwrap_or(AuthStatus::NotAuthenticated)
}
