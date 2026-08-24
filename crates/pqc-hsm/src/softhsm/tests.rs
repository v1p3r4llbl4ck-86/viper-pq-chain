// SPDX-License-Identifier: BUSL-1.1
//! Tests for `softhsm`.

#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use crate::canary::CANARY_PREIMAGE;

/// Returns `Some((module_path, slot_id, pin, label))` if the env
/// declares a real SoftHSM2 token to test against, otherwise
/// `None`. The CI runner provides:
///   - `SOFTHSM2_CONF` — config file path, set by `softhsm-dev-setup.sh`
///   - `VIPER_HSM_TEST_MODULE` — override module path (default to
///     SoftHSM2's typical install location)
///   - `VIPER_HSM_TEST_SLOT` — slot id (default 0)
///   - `VIPER_HSM_TEST_PIN`  — USER PIN (default 1234, matches setup script)
///   - `VIPER_HSM_TEST_LABEL` — key label (default `viper-dev-probe-key`)
fn softhsm_test_env() -> Option<(String, u64, String, String)> {
    if std::env::var("SOFTHSM2_CONF").is_err() {
        return None;
    }
    let module = std::env::var("VIPER_HSM_TEST_MODULE")
        .unwrap_or_else(|_| "/usr/lib/softhsm/libsofthsm2.so".to_string());
    if !std::path::Path::new(&module).exists() {
        return None;
    }
    let slot: u64 = std::env::var("VIPER_HSM_TEST_SLOT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let pin = std::env::var("VIPER_HSM_TEST_PIN").unwrap_or_else(|_| "1234".to_string());
    let label =
        std::env::var("VIPER_HSM_TEST_LABEL").unwrap_or_else(|_| "viper-dev-probe-key".to_string());
    Some((module, slot, pin, label))
}

/// Skip-with-clear-message helper. Tests use `eprintln!` (NOT
/// `panic!` or `assert!`) so the runner reports green even on
/// hosts without softhsm2 — per the kickoff runbook integration
/// posture.
fn require_softhsm() -> Option<(String, u64, String, String)> {
    match softhsm_test_env() {
        Some(env) => Some(env),
        None => {
            eprintln!(
                "[skip] SoftHSM2 not configured \
                 (SOFTHSM2_CONF unset or module path missing) — test skipped"
            );
            None
        }
    }
}

#[test]
fn open_succeeds_against_provisioned_token() {
    let Some((module, slot, pin, label)) = require_softhsm() else {
        return;
    };
    let signer =
        SoftHsmSigner::open(&module, slot, &pin, &label).expect("open against provisioned token");
    assert_eq!(signer.kind(), SignerKind::SoftHsm);
    assert!(!signer.public_key().is_empty(), "SPKI bytes cached");
    assert_eq!(signer.validator_address().len(), 32);
}

#[test]
fn sign_round_trips_canary() {
    let Some((module, slot, pin, label)) = require_softhsm() else {
        return;
    };
    let signer = SoftHsmSigner::open(&module, slot, &pin, &label).unwrap();
    let sig = signer.sign_commit(CANARY_PREIMAGE).unwrap();
    // RSA-2048 PKCS#1 v1.5 → 256 bytes exactly.
    assert_eq!(sig.len(), 256, "RSA-2048 signature is 256 bytes");

    // Determinism check: SHA256_RSA_PKCS is deterministic.
    let sig2 = signer.sign_commit(CANARY_PREIMAGE).unwrap();
    assert_eq!(sig, sig2, "RSA-PKCS#1 v1.5 is deterministic");
}

#[test]
fn self_test_passes_for_softhsm_signer() {
    let Some((module, slot, pin, label)) = require_softhsm() else {
        return;
    };
    let signer = SoftHsmSigner::open(&module, slot, &pin, &label).unwrap();
    signer
        .self_test()
        .expect("SoftHSM canary self-test must pass against a real token");
}

#[test]
fn open_with_missing_key_label_returns_backend_mismatch() {
    let Some((module, slot, pin, _)) = require_softhsm() else {
        return;
    };
    let err = SoftHsmSigner::open(&module, slot, &pin, "nonexistent-label-xyzzy").unwrap_err();
    assert!(
        matches!(err, SignerError::BackendMismatch(_)),
        "missing key label must surface BackendMismatch, got: {err:?}"
    );
}

#[test]
fn open_with_wrong_pin_returns_hsm_unavailable() {
    let Some((module, slot, _, label)) = require_softhsm() else {
        return;
    };
    let err = SoftHsmSigner::open(&module, slot, "0000-wrong", &label).unwrap_err();
    // Wrong PIN surfaces as a login failure → HsmUnavailable
    // (transient — operator can retry with the correct PIN).
    assert!(
        matches!(err, SignerError::HsmUnavailable(_)),
        "bad PIN must surface HsmUnavailable, got: {err:?}"
    );
}

#[test]
fn open_with_invalid_module_path_returns_hsm_unavailable() {
    // This test runs unconditionally — does not require SoftHSM
    // because we're testing the failure path on a missing .so.
    let err = SoftHsmSigner::open("/nonexistent/path/libsofthsm2.so", 0, "1234", "any-label")
        .unwrap_err();
    assert!(
        matches!(err, SignerError::HsmUnavailable(_)),
        "missing module must surface HsmUnavailable, got: {err:?}"
    );
}

#[test]
fn signer_is_object_safe_under_dyn_dispatch() {
    // Compile-time pin: the consensus loop carries
    // Vec<Box<dyn CommitSigner>>. This test forces dyn-dispatch
    // and runs only the parts that don't need a live HSM.
    let Some((module, slot, pin, label)) = require_softhsm() else {
        return;
    };
    let signer: Box<dyn CommitSigner> =
        Box::new(SoftHsmSigner::open(&module, slot, &pin, &label).unwrap());
    assert_eq!(signer.kind(), SignerKind::SoftHsm);
    assert_eq!(signer.alg_id(), AlgId::MlDsa65); // placeholder, see docs
    assert!(!signer.public_key().is_empty());
}
