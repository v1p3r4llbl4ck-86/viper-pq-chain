// SPDX-License-Identifier: BUSL-1.1
//! Integration tests for TASK-053: per-sender admission budget.
//!
//! These tests verify that:
//! 1. A sender that has filled their per-window budget gets their next submission
//!    rejected immediately (before signature verification) with an appropriate error.
//! 2. Rejected transactions (bad signature) do NOT consume sender budget — only
//!    successfully admitted transactions count against the window.
//! 3. Budget resets after the configured window expires.
//! 4. `max_txs_per_window == 0` disables the budget (unlimited admissions).

use std::{
    env, fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use pqc_crypto::{derive_address, ml_dsa_public_key_from_seed, ml_dsa_sign_with_seed, AlgId};
use pqc_tx::{codec::encode_tx, preimage::build_preimage, validate::FeeParams};
use pqc_types::{
    account::Address,
    keyset::allowed_tx,
    transaction::{MsgType, Transaction},
};
use pqcd::{
    devnet::start_from_config_path,
    node::{
        DevnetConfig, GenesisAccountConfig, GenesisKeyConfig, GenesisKeyStatus, NodeConfig,
        NodeRole, SenderBudgetConfig,
    },
};

// ── Sender keypair ─────────────────────────────────────────────────────────────
//
// Distinct seed from product_workflows.rs (0xAA) and rate_limit.rs (no seed).

const SENDER_SEED: [u8; 32] = [0xDD; 32];

fn sender_pk() -> Vec<u8> {
    ml_dsa_public_key_from_seed(AlgId::MlDsa65, &SENDER_SEED).expect("pk derivation must succeed")
}

fn sender_address() -> Address {
    let pk = sender_pk();
    // chain_id matches the empty chain_id used in txs and node config below.
    Address(derive_address(&[], AlgId::MlDsa65, &pk))
}

fn sender_genesis() -> GenesisAccountConfig {
    GenesisAccountConfig {
        address_hex: hex::encode(sender_address().0),
        balance: 10_000_000,
        nonce: 0,
        keys: vec![GenesisKeyConfig {
            alg_id: AlgId::MlDsa65.as_u16(),
            pk_hex: hex::encode(sender_pk()),
            key_version: 1,
            valid_from_height: 0,
            status: GenesisKeyStatus::Active,
            allowed_tx_types: allowed_tx::ALL,
        }],
    }
}

// ── Transaction builders ───────────────────────────────────────────────────────

/// Build a token-transfer transaction with a real ML-DSA-65 signature.
fn valid_tx(nonce: u64) -> Vec<u8> {
    let mut tx = Transaction {
        tx_version: 1,
        chain_id: vec![],
        msg_type: MsgType::TokenTransfer,
        sender: sender_address(),
        nonce,
        fee: 500,
        fee_tip: 0,
        gas_limit: 100_000,
        payload: vec![],
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![],
    };
    let preimage = build_preimage(&pqc_types::ForkDigest::viper_research_1(), &tx)
        .expect("preimage must build");
    tx.signature = ml_dsa_sign_with_seed(AlgId::MlDsa65, &SENDER_SEED, &preimage)
        .expect("signing must succeed");
    encode_tx(&tx).expect("encode must succeed")
}

/// Build a token-transfer transaction with a zeroed (invalid) signature.
///
/// The CBOR structure is valid and the sender is correctly set, so `decode_tx`
/// will succeed and the sender address will be extracted for budget checking.
/// However, the mempool's sig-verify step will reject it — so it must NOT
/// consume sender budget.
fn bad_sig_tx(nonce: u64) -> Vec<u8> {
    let tx = Transaction {
        tx_version: 1,
        chain_id: vec![],
        msg_type: MsgType::TokenTransfer,
        sender: sender_address(),
        nonce,
        fee: 500,
        fee_tip: 0,
        gas_limit: 100_000,
        payload: vec![],
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        // All-zero signature — valid CBOR but will fail sig verification.
        signature: vec![0u8; 512],
    };
    encode_tx(&tx).expect("encode must succeed")
}

// ── Test helpers ───────────────────────────────────────────────────────────────

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "pqcd-sbudget-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write_config(path: &Path, config: &NodeConfig) {
    fs::write(path, serde_json::to_vec_pretty(config).unwrap()).unwrap();
}

/// Minimal SingleNode config with per-sender budget set to `max_txs` per `window_secs`.
fn budget_node_config(data_dir: &Path, max_txs: u32, window_secs: u64) -> NodeConfig {
    NodeConfig {
        node_id: "budget-node".to_owned(),
        data_dir: data_dir.to_path_buf(),
        chain_id_hex: String::new(),
        anchor_prev_hash_hex: hex::encode([0x11u8; 32]),
        fee_params: FeeParams::default(),
        p2p_listen_addr: None,
        api_listen_addr: None,
        peers: Vec::new(),
        devnet: DevnetConfig {
            role: NodeRole::SingleNode,
            sync_interval_ms: 100,
            block_time_ms: 500,
            proposer_address_hex: None,
            quorum_threshold: None,
            validators: Vec::new(),
            snapshot_source: None,
            ..Default::default()
        },
        genesis_accounts: vec![sender_genesis()],
        rate_limit: Default::default(),
        libp2p: None,
        sender_budget: SenderBudgetConfig {
            max_txs_per_window: max_txs,
            window_secs,
        },
        api: Default::default(),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Once a sender reaches `max_txs_per_window` admissions, the next submission
/// is rejected with a budget-exhaustion error before signature verification runs.
#[tokio::test]
async fn sender_budget_blocks_excess_submissions() {
    let data_dir = TempDir::new("blocks");
    let config = budget_node_config(data_dir.path(), 1, 60);
    let config_path = data_dir.path().join("config.json");
    write_config(&config_path, &config);

    let handle = start_from_config_path(&config_path)
        .await
        .expect("node start failed");

    // First injection (nonce=0): must succeed and consume the one slot.
    handle
        .inject_tx(valid_tx(0))
        .await
        .expect("first inject must succeed — sender has budget");

    // Second injection (nonce=1): must fail with budget exhaustion.
    // The budget check fires before sig verify, so the nonce mismatch
    // (state nonce is still 0) is never reached.
    let err = handle
        .inject_tx(valid_tx(1))
        .await
        .expect_err("second inject must fail — budget exhausted");

    assert!(
        err.to_string().contains("budget"),
        "expected budget-exhaustion error, got: {err}"
    );

    handle.shutdown().await.expect("shutdown failed");
}

/// A transaction that fails signature verification does NOT consume sender
/// budget. Only successfully admitted transactions count against the window.
#[tokio::test]
async fn sender_budget_rejected_tx_does_not_consume() {
    let data_dir = TempDir::new("nocount");
    let config = budget_node_config(data_dir.path(), 1, 60);
    let config_path = data_dir.path().join("config.json");
    write_config(&config_path, &config);

    let handle = start_from_config_path(&config_path)
        .await
        .expect("node start failed");

    // Inject a bad-sig tx (nonce=0). It has a valid CBOR structure with the correct
    // sender address, so the budget is checked — but since it fails sig verify, it
    // must NOT be counted against the budget.
    let bad_err = handle
        .inject_tx(bad_sig_tx(0))
        .await
        .expect_err("bad-sig tx must be rejected");

    assert!(
        !bad_err.to_string().contains("budget"),
        "bad-sig rejection must not be a budget error: {bad_err}"
    );

    // The valid tx (nonce=0) must now succeed — budget was not consumed by the
    // failed attempt.
    handle
        .inject_tx(valid_tx(0))
        .await
        .expect("valid inject must succeed — budget was not consumed by rejected tx");

    handle.shutdown().await.expect("shutdown failed");
}

/// After the budget window expires, the sender can submit again without being
/// rate-limited.
#[tokio::test]
async fn sender_budget_window_reset_allows_reentry() {
    let data_dir = TempDir::new("reset");
    // 1-second window so the test does not take too long.
    let config = budget_node_config(data_dir.path(), 1, 1);
    let config_path = data_dir.path().join("config.json");
    write_config(&config_path, &config);

    let handle = start_from_config_path(&config_path)
        .await
        .expect("node start failed");

    // Consume the one slot.
    handle
        .inject_tx(valid_tx(0))
        .await
        .expect("first inject must succeed");

    // Confirm budget is now exhausted.
    let budget_err = handle
        .inject_tx(valid_tx(1))
        .await
        .expect_err("second inject must be budget-limited");
    assert!(
        budget_err.to_string().contains("budget"),
        "expected budget error before window reset: {budget_err}"
    );

    // Wait for the window to expire.
    tokio::time::sleep(Duration::from_millis(1_100)).await;

    // After the window reset, the budget check must pass. The tx itself (nonce=1)
    // will fail nonce validation because the node has committed no blocks and the
    // on-chain nonce is still 0 — but that is a *different* error, not a budget error.
    let post_reset_err = handle
        .inject_tx(valid_tx(1))
        .await
        .expect_err("nonce=1 must still fail after reset (state nonce is 0)");

    assert!(
        !post_reset_err.to_string().contains("budget"),
        "post-window-reset error must not be a budget error: {post_reset_err}"
    );

    handle.shutdown().await.expect("shutdown failed");
}

/// `max_txs_per_window == 0` disables the per-sender budget entirely.
/// Submissions are processed normally by the full admission pipeline.
#[tokio::test]
async fn sender_budget_disabled_allows_any_count() {
    let data_dir = TempDir::new("disabled");
    // max=0 disables per-sender budget.
    let config = budget_node_config(data_dir.path(), 0, 60);
    let config_path = data_dir.path().join("config.json");
    write_config(&config_path, &config);

    let handle = start_from_config_path(&config_path)
        .await
        .expect("node start failed");

    // First injection must succeed.
    handle
        .inject_tx(valid_tx(0))
        .await
        .expect("first inject must succeed with budget disabled");

    // Second injection (nonce=1) must fail for a non-budget reason (nonce mismatch
    // since state nonce is still 0 after no blocks). The budget check must NOT fire.
    let err = handle
        .inject_tx(valid_tx(1))
        .await
        .expect_err("nonce=1 must fail when state nonce is 0");

    assert!(
        !err.to_string().contains("budget"),
        "disabled budget must not produce a budget error: {err}"
    );

    handle.shutdown().await.expect("shutdown failed");
}
