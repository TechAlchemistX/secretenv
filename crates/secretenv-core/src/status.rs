//! Backend health status reported by the `doctor` command.
//!
//! Every backend reports its Level 1 + Level 2 health via a
//! [`BackendStatus`]. Level 1 checks that the native CLI is installed;
//! Level 2 checks that it is authenticated. The four variants are
//! rendered differently by `doctor` (colored ticks, install hints,
//! auth hints) and serialized into a stable shape by `doctor --json`.

/// The health status of a single backend instance, produced by a
/// backend's `check` implementation.
#[derive(Debug, Clone)]
pub enum BackendStatus {
    /// CLI is installed, authenticated, and reachable.
    Ok {
        /// Version string reported by the CLI (e.g. `aws-cli/2.15.0`).
        cli_version: String,
        /// Human-readable identity the CLI is currently signed in as
        /// (e.g. `profile=dev account=123456789 region=us-east-1`).
        identity: String,
    },
    /// The backend's native CLI is not on `PATH`.
    CliMissing {
        /// The binary name the backend looked for (e.g. `aws`, `op`).
        cli_name: String,
        /// A short hint describing how to install the CLI.
        install_hint: String,
    },
    /// The CLI is installed but not signed in.
    NotAuthenticated {
        /// A short hint describing how to authenticate (e.g. `op signin`).
        hint: String,
    },
    /// Any other failure — unreachable service, permission error, etc.
    Error {
        /// A short human-readable description of the failure.
        message: String,
    },
}

impl BackendStatus {
    /// Returns `true` if this status is [`Ok`](Self::Ok).
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        matches!(self, Self::Ok { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_ok_is_true_only_for_ok_variant() {
        let ok = BackendStatus::Ok {
            cli_version: "aws-cli/2.15.0".into(),
            identity: "profile=dev".into(),
        };
        let cli_missing = BackendStatus::CliMissing {
            cli_name: "aws".into(),
            install_hint: "brew install awscli".into(),
        };
        let not_auth = BackendStatus::NotAuthenticated { hint: "run: op signin".into() };
        let err = BackendStatus::Error { message: "service unreachable".into() };

        assert!(ok.is_ok());
        assert!(!cli_missing.is_ok());
        assert!(!not_auth.is_ok());
        assert!(!err.is_ok());
    }
}
