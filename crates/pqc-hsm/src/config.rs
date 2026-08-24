// SPDX-License-Identifier: BUSL-1.1
//! Boot-time signer selection — `SignerKind` + `SignerConfig`.
//!
//! The pqcd `DevnetConfig` gains a `signer_kind: SignerKind` field
//! defaulting to `LocalKeystore` (zero-config back-compat) and a
//! `signer_config: SignerConfig` carrying backend-specific connection
//! params. The mapping from these to a constructed `Box<dyn
//! CommitSigner>` lives in the impl crate (`pqc-hsm`) — `pqcd` consumes
//! the resulting trait object only.
//!
//! See the private design notes at runtime".

use serde::{Deserialize, Serialize};

/// Which `CommitSigner` backend to instantiate at startup.
///
/// `serde(rename_all = "snake_case")` keeps node.json idiomatic:
///   `"signer_kind": "local_keystore"`, not `"LocalKeystore"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SignerKind {
    /// In-process ML-DSA signing from a 32-byte seed kept in a
    /// `pqcd::keystore::Keystore`. Default — back-compat with every
    /// existing devnet, testnet, and viper-pq-1 deployment.
    #[default]
    LocalKeystore,
    /// PKCS#11 → SoftHSM2. RSA-2048 placeholder mechanism per
    /// HSM-KICKOFF-RUNBOOK §1.2 (SoftHSM2 has not yet shipped ML-DSA).
    /// CI-only — never production. Stretch goal.
    SoftHsm,
    /// AWS CloudHSM-backed signer. Real ML-DSA-65 via the cluster's
    /// `CKM_ML_DSA_*` mechanism. Production target. Implementation
    /// deferred per the worktree scope (no AWS account in unattended
    /// runs).
    AwsCloudHsm,
}

/// Backend-specific connection parameters. Mirrors `SignerKind` —
/// either matches via `(SignerKind::LocalKeystore, SignerConfig::LocalKeystore)`
/// or pqcd refuses to start with a clear error pointing at the offending
/// field.
///
/// `#[serde(tag = "kind", rename_all = "snake_case")]` produces an
/// idiomatic JSON shape:
///
/// ```json
/// {
///   "kind": "local_keystore"
/// }
/// ```
///
/// or (when the SoftHSM backend lands):
///
/// ```json
/// {
///   "kind": "soft_hsm",
///   "module_path": "/usr/lib/softhsm/libsofthsm2.so",
///   "slot_id": 0,
///   "user_pin": "1234",
///   "key_label": "viper-dev-probe-key"
/// }
/// ```
///
/// LocalKeystore carries no params — the `pqcd::keystore::Keystore`
/// is already constructed via the existing
/// `devnet.keystore_path` / `devnet.validators[].commit_seed_hex`
/// path, and `LocalKeystoreSigner` adapts entries from it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SignerConfig {
    /// In-process keystore — no extra params. The trait wraps an
    /// existing `KeystoreEntry` lookup.
    #[default]
    LocalKeystore,

    /// SoftHSM2 PKCS#11 backend (stretch goal).
    SoftHsm {
        /// Absolute path to the PKCS#11 module shared library.
        /// Typical SoftHSM install: `/usr/lib/softhsm/libsofthsm2.so`.
        module_path: String,
        /// PKCS#11 slot ID containing the initialised token.
        slot_id: u64,
        /// User PIN. DEV ONLY — production HSMs use IAM / KMS-released
        /// secrets, not a node.json field. The runbook calls this out.
        user_pin: String,
        /// Object label of the key pair to find in the slot.
        key_label: String,
    },

    /// AWS CloudHSM cluster-backed signer (future).
    AwsCloudHsm {
        /// AWS region the cluster lives in (e.g. `"eu-west-1"`).
        region: String,
        /// Cluster ID (e.g. `"cluster-abc123def"`).
        cluster_id: String,
        /// HSM key label set during `cloudhsm-cli key
        /// generate-asymmetric-pair --label …`.
        key_label: String,
    },
}

impl SignerConfig {
    /// True when the config payload matches the kind. The pqcd boot
    /// path uses this to refuse a mismatched (kind, config) pair before
    /// instantiating any signers.
    pub fn matches_kind(&self, kind: SignerKind) -> bool {
        matches!(
            (self, kind),
            (Self::LocalKeystore, SignerKind::LocalKeystore)
                | (Self::SoftHsm { .. }, SignerKind::SoftHsm)
                | (Self::AwsCloudHsm { .. }, SignerKind::AwsCloudHsm)
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn default_signer_kind_is_local_keystore() {
        // Back-compat anchor: a node.json without `signer_kind` MUST
        // boot the in-process keystore signer.
        assert_eq!(SignerKind::default(), SignerKind::LocalKeystore);
    }

    #[test]
    fn default_signer_config_is_local_keystore() {
        assert!(matches!(
            SignerConfig::default(),
            SignerConfig::LocalKeystore
        ));
    }

    #[test]
    fn matches_kind_accepts_aligned_pairs() {
        assert!(SignerConfig::LocalKeystore.matches_kind(SignerKind::LocalKeystore));
        assert!(SignerConfig::SoftHsm {
            module_path: "/usr/lib/softhsm/libsofthsm2.so".into(),
            slot_id: 0,
            user_pin: "1234".into(),
            key_label: "k".into(),
        }
        .matches_kind(SignerKind::SoftHsm));
    }

    #[test]
    fn matches_kind_rejects_mismatched_pair() {
        // (LocalKeystore, SoftHsm) MUST be rejected — pqcd refuses to
        // start with a clear error rather than silently picking one.
        assert!(!SignerConfig::LocalKeystore.matches_kind(SignerKind::SoftHsm));
        assert!(!SignerConfig::SoftHsm {
            module_path: "x".into(),
            slot_id: 0,
            user_pin: "x".into(),
            key_label: "x".into(),
        }
        .matches_kind(SignerKind::LocalKeystore));
    }

    #[test]
    fn local_keystore_kind_round_trips_through_serde_json() {
        let kind = SignerKind::LocalKeystore;
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, r#""local_keystore""#);
        let back: SignerKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, kind);
    }

    #[test]
    fn signer_config_round_trips_local_keystore() {
        let cfg = SignerConfig::LocalKeystore;
        let json = serde_json::to_string(&cfg).unwrap();
        assert_eq!(json, r#"{"kind":"local_keystore"}"#);
        let back: SignerConfig = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, SignerConfig::LocalKeystore));
    }
}
