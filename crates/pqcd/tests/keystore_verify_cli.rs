// SPDX-License-Identifier: BUSL-1.1
//! Integration tests for `pqcd keystore verify <path>`.
//!
//! Drives the binary as a subprocess so the test exercises the actual
//! argv parsing path + the production loader, not just the library
//! function. This catches regressions in either layer (someone refactors
//! Keystore::load_from_file, or someone reorders the argv match in
//! main.rs and breaks the path-arg position).
//!
//! Why subprocess rather than calling the `cmd_keystore_verify` fn
//! directly: the function is private to the binary crate. Calling it
//! would require exposing it through the lib, and we'd test only the
//! parser-free fast path. Subprocess matches operator reality.

use pqc_crypto::{ml_dsa_public_key_from_seed, AlgId};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Cargo provides this env var for any binary in the same crate.
fn pqcd_bin() -> &'static str {
    env!("CARGO_BIN_EXE_pqcd")
}

fn unique_path(label: &str) -> std::path::PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!(
        "pqcd-keystore-verify-{label}-{}-{now}-{n}.json",
        std::process::id()
    ))
}

fn write_json(path: &std::path::Path, body: serde_json::Value) {
    std::fs::write(path, serde_json::to_vec_pretty(&body).unwrap())
        .expect("write keystore fixture");
}

#[test]
fn verify_accepts_well_formed_single_validator_keystore() {
    let path = unique_path("happy");
    let seed = [0xA1u8; 32];
    let pk = ml_dsa_public_key_from_seed(AlgId::MlDsa65, &seed).expect("derive pk");

    write_json(
        &path,
        serde_json::json!({
            "validators": [
                {
                    "address_hex": hex::encode([0x42u8; 32]),
                    "sig_alg_id": AlgId::MlDsa65.as_u16(),
                    "commit_seed_hex": hex::encode(seed),
                    "key_version": 1,
                }
            ]
        }),
    );

    let out = Command::new(pqcd_bin())
        .args(["keystore", "verify"])
        .arg(&path)
        .output()
        .expect("run pqcd");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        out.status.success(),
        "expected success, got status={:?} stdout={stdout} stderr={stderr}",
        out.status,
    );
    assert!(
        stdout.contains("distinct validator addresses: 1"),
        "stdout missing distinct count, got: {stdout}"
    );
    assert!(
        stdout.contains("total entries (sum across versions): 1"),
        "stdout missing total entries line, got: {stdout}"
    );
    assert!(
        stdout.contains(&format!("pk.len={}", pk.len())),
        "stdout missing pk.len for ML-DSA-65 (expected {}), got: {stdout}",
        pk.len(),
    );
    assert!(
        stdout.contains("alg_id=2"), // ML-DSA-65 numeric
        "stdout missing alg_id=2, got: {stdout}"
    );
    assert!(
        stdout.trim_end().ends_with("OK"),
        "stdout missing trailing OK, got: {stdout}"
    );

    std::fs::remove_file(&path).ok();
}

#[test]
fn verify_reports_multi_version_entries_for_same_address() {
    // Phase 4 Gap A — two staged versions for the same address. The
    // verify subcommand must show both with distinct key_version values
    // so the operator can confirm a rotation is fully staged before
    // restart.
    let path = unique_path("multi_version");
    let addr = [0x77u8; 32];
    let v1_seed = [0x11u8; 32];
    let v2_seed = [0x22u8; 32];

    write_json(
        &path,
        serde_json::json!({
            "validators": [
                {
                    "address_hex": hex::encode(addr),
                    "sig_alg_id": AlgId::MlDsa65.as_u16(),
                    "commit_seed_hex": hex::encode(v1_seed),
                    "key_version": 1,
                },
                {
                    "address_hex": hex::encode(addr),
                    "sig_alg_id": AlgId::MlDsa65.as_u16(),
                    "commit_seed_hex": hex::encode(v2_seed),
                    "key_version": 2,
                }
            ]
        }),
    );

    let out = Command::new(pqcd_bin())
        .args(["keystore", "verify"])
        .arg(&path)
        .output()
        .expect("run pqcd");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout={stdout}");
    assert!(
        stdout.contains("distinct validator addresses: 1"),
        "expected 1 distinct address, got: {stdout}"
    );
    assert!(
        stdout.contains("total entries (sum across versions): 2"),
        "expected 2 total entries, got: {stdout}"
    );
    assert!(
        stdout.contains("key_version=1"),
        "expected key_version=1 line, got: {stdout}"
    );
    assert!(
        stdout.contains("key_version=2"),
        "expected key_version=2 line, got: {stdout}"
    );

    std::fs::remove_file(&path).ok();
}

#[test]
fn verify_refuses_empty_validators_array() {
    // A schema-mismatched migration that produces an empty validators
    // array MUST exit non-zero. This is the central guarantee of the
    // pre-deploy check: silently accepting an empty file would let the
    // operator restart pqcd into a chain-halt.
    let path = unique_path("empty");
    write_json(&path, serde_json::json!({ "validators": [] }));

    let out = Command::new(pqcd_bin())
        .args(["keystore", "verify"])
        .arg(&path)
        .output()
        .expect("run pqcd");

    assert!(
        !out.status.success(),
        "empty validators must produce non-zero exit, got success"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("zero validator entries"),
        "stderr should mention 'zero validator entries', got: {stderr}"
    );

    std::fs::remove_file(&path).ok();
}

#[test]
fn verify_refuses_malformed_json() {
    let path = unique_path("bad_json");
    std::fs::write(&path, "not even close to json").expect("write fixture");

    let out = Command::new(pqcd_bin())
        .args(["keystore", "verify"])
        .arg(&path)
        .output()
        .expect("run pqcd");

    assert!(!out.status.success(), "malformed JSON must exit non-zero");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("parse"),
        "stderr should mention parse, got: {stderr}"
    );

    std::fs::remove_file(&path).ok();
}

#[test]
fn verify_refuses_missing_path_argument() {
    let out = Command::new(pqcd_bin())
        .args(["keystore", "verify"])
        .output()
        .expect("run pqcd");

    assert!(!out.status.success(), "missing path arg must exit non-zero");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Usage:"),
        "stderr should print usage, got: {stderr}"
    );
}

#[test]
fn verify_refuses_nonexistent_file() {
    let path = unique_path("nope");
    // intentionally do NOT create the file

    let out = Command::new(pqcd_bin())
        .args(["keystore", "verify"])
        .arg(&path)
        .output()
        .expect("run pqcd");

    assert!(!out.status.success(), "nonexistent file must exit non-zero");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("No such file") || stderr.contains("failed to read"),
        "stderr should report the missing file, got: {stderr}"
    );
}

#[test]
fn verify_unknown_keystore_subcommand_is_rejected() {
    // Defense against typo'd subcommands silently no-op'ing. Any verb
    // other than "verify" must surface usage.
    let out = Command::new(pqcd_bin())
        .args(["keystore", "verfy"]) // typo
        .output()
        .expect("run pqcd");

    assert!(
        !out.status.success(),
        "unknown subcommand must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Usage:"),
        "stderr should print usage hint, got: {stderr}"
    );
}
