// SPDX-License-Identifier: BUSL-1.1
//! Tests for `keystore_lifecycle`.
//!
//! Extracted from `keystore_lifecycle.rs` 2026-05-10. `use super::*;`
//! brings every private item from the parent module into scope.

//! SECURITY-FIX-PLAN.md §1 (Issue #1) — validator keystore migration.
//!
//! These tests pin the source-precedence contract of
//! `build_initial_keystore`:
//!
//!   1. The on-disk keystore (`devnet.keystore_path`) is
//!      authoritative when both it AND `validators[].commit_seed_hex`
//!      carry a seed for the same validator address.
//!   2. Disagreement between the two sources is a hard error
//!      (the binary refuses to start) — no silent overwrite, no
//!      silent precedence pick. The error message names the
//!      validator's `node_id` so an operator can grep their
//!      inventory for the offender.
//!   3. Agreement between the two sources is a no-op merge — the
//!      file's entry stays put; the in-config copy is redundant
//!      and skipped.
//!
//! Pure unit tests: a tempdir keystore.json + a constructed
//! `NodeConfig`. No network, no tokio runtime.
use super::*;
use crate::node::{
    ApiConfig, DevnetConfig, GenesisAccountConfig, NodeConfig, RateLimitConfig, SenderBudgetConfig,
    ValidatorConfig,
};
use pqc_crypto::{ml_dsa_public_key_from_seed, AlgId};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Std-only nanosecond-stamped tempdir under `env::temp_dir()`,
/// matching the pattern in `keystore.rs` and `chain_size_metric_tests`.
fn tempdir(label: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let path = std::env::temp_dir().join(format!(
        "pqcd-build-keystore-{label}-{}-{unique}-{n}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

/// Build a `ValidatorConfig` with `commit_seed_hex` populated and
/// `public_key_hex` derived from that seed (so the in-config
/// pk-cross-check inside `build_initial_keystore` passes whenever
/// the fall-through path is exercised).
fn validator_cfg(node_id: &str, address: [u8; 32], seed: [u8; 32]) -> ValidatorConfig {
    let pk = ml_dsa_public_key_from_seed(AlgId::MlDsa65, &seed).unwrap();
    ValidatorConfig {
        node_id: node_id.to_owned(),
        address_hex: hex::encode(address),
        sig_alg_id: AlgId::MlDsa65.as_u16(),
        public_key_hex: hex::encode(pk),
        archival_sk_hex: None,
        commit_seed_hex: Some(hex::encode(seed)),
    }
}

fn node_config_with(devnet: DevnetConfig) -> NodeConfig {
    NodeConfig {
        node_id: "test".into(),
        data_dir: PathBuf::from("/tmp/pqcd-build-initial-keystore-test"),
        chain_id_hex: String::new(),
        anchor_prev_hash_hex: "00".repeat(32),
        fee_params: pqc_tx::validate::FeeParams::default(),
        p2p_listen_addr: None,
        api_listen_addr: None,
        peers: Vec::new(),
        devnet,
        genesis_accounts: Vec::<GenesisAccountConfig>::new(),
        rate_limit: RateLimitConfig::default(),
        sender_budget: SenderBudgetConfig::default(),
        api: ApiConfig::default(),
        libp2p: None,
    }
}

/// Write a single-validator keystore.json that carries `seed` for
/// the validator at `address`. Returns the path.
fn write_keystore(dir: &std::path::Path, address: [u8; 32], seed: [u8; 32]) -> PathBuf {
    let path = dir.join("keystore.json");
    let body = serde_json::json!({
        "validators": [
            {
                "address_hex": hex::encode(address),
                "sig_alg_id": AlgId::MlDsa65.as_u16(),
                "commit_seed_hex": hex::encode(seed),
            }
        ]
    });
    fs::write(&path, serde_json::to_vec_pretty(&body).unwrap()).unwrap();
    path
}

/// node.json has the validator with seed = 0x11×32; keystore.json on
/// disk has the SAME validator address but seed = 0x22×32.
/// `build_initial_keystore` MUST refuse to start and the error MUST
/// name the validator's `node_id`.
#[test]
fn disagreement_between_node_json_and_keystore_file_bails() {
    let dir = tempdir("disagree");
    let address = [0xA1u8; 32];
    let file_seed = [0x22u8; 32];
    let path = write_keystore(&dir, address, file_seed);

    // node.json carries the SAME address but a DIFFERENT seed.
    // We use 0x11 in config so the fall-through pk cross-check
    // would have been the failure mode under the OLD code path
    // (config-only). Under the new code path the file-is-loaded-first
    // gate fires before that ever runs.
    let in_config_seed = [0x11u8; 32];
    let devnet = DevnetConfig {
        keystore_path: Some(path.clone()),
        validators: vec![validator_cfg("validator-rogue", address, in_config_seed)],
        ..DevnetConfig::default()
    };
    let cfg = node_config_with(devnet);

    let err = build_initial_keystore(&cfg, None)
        .expect_err("disagreeing seeds across node.json and keystore.json must bail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("validator-rogue"),
        "error must name the validator's node_id, got: {msg}"
    );
    assert!(
        msg.contains("disagrees"),
        "error must mention seed disagreement, got: {msg}"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// node.json has the validator with seed = 0x33×32; keystore.json on
/// disk has the same address with the SAME seed. `build_initial_keystore`
/// returns Ok with exactly one entry (file wins; in-config copy is
/// redundant and silently skipped).
#[test]
fn agreement_between_node_json_and_keystore_file_succeeds() {
    let dir = tempdir("agree");
    let address = [0xB2u8; 32];
    let seed = [0x33u8; 32];
    let path = write_keystore(&dir, address, seed);

    let devnet = DevnetConfig {
        keystore_path: Some(path.clone()),
        validators: vec![validator_cfg("validator-aligned", address, seed)],
        ..DevnetConfig::default()
    };
    let cfg = node_config_with(devnet);

    let ks = build_initial_keystore(&cfg, None).expect("agreeing seeds must build a keystore");
    assert_eq!(ks.len(), 1, "exactly one entry — file wins, config dedup'd");
    let entry = ks.get(&address).expect("address present");
    assert_eq!(
        entry.commit_seed, seed,
        "the file-loaded seed must be retained verbatim"
    );
    assert_eq!(entry.sig_alg_id, AlgId::MlDsa65);
    let _ = fs::remove_dir_all(&dir);
}
