// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared probe machinery for `doctor` + `resolve_status`.
//!
//! Both tools need a live [`BackendRegistry`] at call time. Builds
//! one via [`secretenv_backends_init::build_registry`] from the
//! handler's loaded [`Config`], then runs [`Backend::check`] against
//! each instance concurrently with a per-backend timeout.
//!
//! Failure to build the registry (e.g. an invalid `[backends.*]`
//! block) is surfaced as a synthesized `Error` status per instance
//! rather than bailing the whole tool call — the agent then knows
//! which instance is broken.

use std::collections::HashMap;
use std::time::Duration;

use futures::future::join_all;
use secretenv_core::{Backend, BackendStatus, Config, DEFAULT_CHECK_TIMEOUT};
use tokio::time::timeout;

use crate::boundary::{AuthStatus, DoctorBackendStatus};

/// Build registry + run `check()` against every configured backend
/// instance. Returns one [`DoctorBackendStatus`] per instance,
/// sorted by instance name.
///
/// If `build_registry` itself fails (typically a misconfigured
/// `[backends.*]` block — wrong type, missing required field), this
/// returns a single synthesized status entry describing the
/// configuration error so the agent can surface it.
pub async fn probe_all_backends(config: &Config) -> Vec<DoctorBackendStatus> {
    let registry = match secretenv_backends_init::build_registry(config) {
        Ok(r) => r,
        Err(e) => {
            // Synthesize a single-entry response so the tool call
            // doesn't fail — the agent gets a structured error.
            return vec![DoctorBackendStatus {
                instance_name: "<registry-build-failed>".to_owned(),
                backend_type: "<unknown>".to_owned(),
                status: AuthStatus::NotAuthenticated,
                cli_version: None,
                identity_hint: None,
                remediation_hint: Some(
                    "Fix the [backends.*] block flagged in error_message, then retry.".to_owned(),
                ),
                error_message: Some(crate::error::safe_error_message(&e)),
            }];
        }
    };

    let backend_meta: HashMap<String, String> = config
        .backends
        .iter()
        .map(|(name, cfg)| (name.clone(), cfg.backend_type.clone()))
        .collect();

    let probes = registry.all().map(|backend| {
        let name = backend.instance_name().to_owned();
        let ty = backend_meta.get(&name).cloned().unwrap_or_else(|| "<unknown>".to_owned());
        async move {
            let status = run_check_with_timeout(backend).await;
            map_backend_status(name, ty, status)
        }
    });
    let mut out: Vec<DoctorBackendStatus> = join_all(probes).await;
    out.sort_by(|a, b| a.instance_name.cmp(&b.instance_name));
    out
}

async fn run_check_with_timeout(backend: &dyn Backend) -> BackendStatus {
    timeout(Duration::from_secs(DEFAULT_CHECK_TIMEOUT.as_secs()), backend.check())
        .await
        .unwrap_or_else(|_| BackendStatus::Error {
            message: format!("check() timed out after {}s", DEFAULT_CHECK_TIMEOUT.as_secs()),
        })
}

fn map_backend_status(
    instance_name: String,
    backend_type: String,
    status: BackendStatus,
) -> DoctorBackendStatus {
    match status {
        BackendStatus::Ok { cli_version, identity } => DoctorBackendStatus {
            instance_name,
            backend_type,
            status: AuthStatus::Authenticated,
            cli_version: Some(cli_version),
            identity_hint: Some(identity),
            remediation_hint: None,
            error_message: None,
        },
        BackendStatus::CliMissing { cli_name, install_hint } => DoctorBackendStatus {
            instance_name,
            backend_type,
            status: AuthStatus::CliNotInstalled,
            cli_version: None,
            identity_hint: None,
            remediation_hint: Some(format!("install `{cli_name}`: {install_hint}")),
            error_message: None,
        },
        BackendStatus::NotAuthenticated { hint } => DoctorBackendStatus {
            instance_name,
            backend_type,
            status: AuthStatus::NotAuthenticated,
            cli_version: None,
            identity_hint: None,
            remediation_hint: Some(hint),
            error_message: None,
        },
        BackendStatus::Error { message } => DoctorBackendStatus {
            instance_name,
            backend_type,
            status: AuthStatus::NotAuthenticated,
            cli_version: None,
            identity_hint: None,
            remediation_hint: Some("backend reported an error — see error_message".to_owned()),
            error_message: Some(message),
        },
    }
}
