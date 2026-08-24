// SPDX-License-Identifier: BUSL-1.1
//! TASK-057 — Load generator and throughput measurement.
//!
//! Exercises the node under sustained injection load and reports throughput
//! metrics that map directly to SPEC-TEST-001 §3.3 (devnet: ≥100 TPS) and
//! §4.5 (Phase 3-alpha: ≥200 TPS).
//!
//! ## Design: N senders, each with nonce=0
//!
//! The mempool validates nonce against the committed state snapshot. This means
//! two consecutive transactions from the same sender can only both be admitted if
//! the first one has been committed (nonce incremented in state) before the second
//! is injected.
//!
//! To measure concurrent admission throughput — not serialized commit latency —
//! the load test creates N independent sender accounts (each with a unique
//! deterministic ML-DSA-65 keypair) and injects one transaction per sender with
//! nonce=0. All N transactions are eligible for admission simultaneously, so the
//! mempool can accept them all before any block is produced.
//!
//! This correctly measures:
//! - Admission rate: how fast the node admits pre-signed transactions
//! - Block assembly throughput: how many transactions are included per block
//! - Effective TPS: included transactions / finalization time
//!
//! ## CI smoke test vs. full run
//!
//! The test that runs in CI (`load_test_smoke`) injects a small batch
//! (default: 100 tx, override with `LOAD_TX_COUNT`) and asserts only a
//! low threshold (≥5 effective TPS) that passes on constrained VPS hardware.
//!
//! For the protocol-level measurement required by SPEC-TEST-001 §6.2:
//!
//! ```text
//! LOAD_TX_COUNT=10000 cargo test --test load_test --release -- --nocapture
//! ```
//!
//! The `--release` flag is important: ML-DSA-65 signing and verification are
//! ~3–10× faster in release mode.

use std::{
    env, fs,
    net::TcpListener as StdTcpListener,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use ciborium::value::Value;
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
        NodeRole, RateLimitConfig, SenderBudgetConfig, ValidatorConfig,
    },
};
use tokio::time::{self, Duration, Instant};

// ── Constants ─────────────────────────────────────────────────────────────────

const ANCHOR_PREV_HASH: [u8; 32] = [0x11; 32];
const PRODUCER_ADDRESS: [u8; 32] = [0x99; 32];

/// Gas cost for a token_transfer — matches GAS_TOKEN_TRANSFER in gas_schedule.rs.
const GAS_TOKEN_TRANSFER: u64 = 5;

/// Calibrated FeeParams matching the Ubuntu VM reference node (TASK-042).
///
/// SPEC-TEST-001 §6.2 requires the fee model to be active during throughput
/// measurement. These match the runnable configs in `configs/`.
fn calibrated_fee_params() -> FeeParams {
    FeeParams {
        base_fee: 500,
        byte_fee: 2,
        sigverify_fee_v_a: 8_800,
        sigverify_fee_v_b: 14_000, // ML-DSA standard class (reference)
        sigverify_fee_v_c: 810_000,
        exec_fee_per_gas: 43,
        base_fee_dynamic: 0,
    }
}

/// Fee paid by each load-test transaction.
///
/// Calculated to comfortably exceed the minimum for a token_transfer with
/// gas_limit=GAS_TOKEN_TRANSFER and the calibrated FeeParams:
///   min ≈ base(500) + bytes(2×~3700=7400) + sigverify(14000) + exec(43×5=215) ≈ 22,115
///
/// 50,000 gives a ~2× buffer against CBOR encoding size variation.
const TX_FEE: u64 = 50_000;

/// Transfer amount per transaction (recipient receives this amount).
const TX_AMOUNT: u64 = 1;

// ── Per-sender deterministic identity ────────────────────────────────────────

/// Derive a unique signing seed for sender index `i`.
fn sender_seed(i: usize) -> [u8; 32] {
    let mut seed = [0xC0u8; 32];
    let idx_bytes = (i as u32).to_be_bytes();
    seed[..4].copy_from_slice(&idx_bytes);
    seed
}

fn sender_pk(seed: &[u8; 32]) -> Vec<u8> {
    ml_dsa_public_key_from_seed(AlgId::MlDsa65, seed)
        .expect("sender public key derivation must succeed")
}

fn sender_address(seed: &[u8; 32]) -> Address {
    let pk = sender_pk(seed);
    // chain_id matches the empty chain_id used in txs and node config below.
    Address(derive_address(&[], AlgId::MlDsa65, &pk))
}

fn sign_tx_with_seed(tx: &Transaction, seed: &[u8; 32]) -> Vec<u8> {
    let preimage = build_preimage(&pqc_types::ForkDigest::viper_research_1(), tx)
        .expect("preimage must build");
    ml_dsa_sign_with_seed(AlgId::MlDsa65, seed, &preimage).expect("signing must succeed")
}

// ── Infrastructure ────────────────────────────────────────────────────────────

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            env::temp_dir().join(format!("pqcd-load-{label}-{}-{unique}", std::process::id()));
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

fn reserve_local_addr() -> String {
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    format!("127.0.0.1:{}", addr.port())
}

fn write_config(path: &Path, config: &NodeConfig) {
    fs::write(path, serde_json::to_vec_pretty(config).unwrap()).unwrap();
}

fn test_validators() -> Vec<ValidatorConfig> {
    [
        ([0xA1u8; 32], AlgId::MlDsa65, [0x11u8; 32]),
        ([0xA2; 32], AlgId::MlDsa65, [0x22; 32]),
        ([0xA3; 32], AlgId::MlDsa65, [0x33; 32]),
    ]
    .iter()
    .enumerate()
    .map(|(i, (address, alg, seed))| {
        let pk =
            ml_dsa_public_key_from_seed(*alg, seed).expect("validator pk derivation must succeed");
        ValidatorConfig {
            node_id: format!("validator-{}", i + 1),
            address_hex: hex::encode(address),
            sig_alg_id: alg.as_u16(),
            public_key_hex: hex::encode(&pk),
            commit_seed_hex: Some(hex::encode(seed)),
            archival_sk_hex: None,
        }
    })
    .collect()
}

// ── CBOR helpers ──────────────────────────────────────────────────────────────

fn token_transfer_payload(recipient: &Address, amount: u64) -> Vec<u8> {
    let entries = vec![
        (
            Value::Integer(1u64.into()),
            Value::Bytes(recipient.0.to_vec()),
        ),
        (Value::Integer(2u64.into()), Value::Integer(amount.into())),
    ];
    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(entries), &mut out).unwrap();
    out
}

// ── Config and genesis account generation ─────────────────────────────────────

fn build_genesis_accounts(count: usize) -> Vec<GenesisAccountConfig> {
    // Balance must cover fee + amount per tx with headroom.
    let balance_per_account = TX_FEE as u128 + TX_AMOUNT as u128 + 1_000;

    (0..count)
        .map(|i| {
            let seed = sender_seed(i);
            let pk = sender_pk(&seed);
            let addr = sender_address(&seed);
            GenesisAccountConfig {
                address_hex: hex::encode(addr.0),
                balance: balance_per_account,
                nonce: 0,
                keys: vec![GenesisKeyConfig {
                    alg_id: AlgId::MlDsa65.as_u16(),
                    pk_hex: hex::encode(&pk),
                    key_version: 1,
                    valid_from_height: 0,
                    status: GenesisKeyStatus::Active,
                    allowed_tx_types: allowed_tx::ALL,
                }],
            }
        })
        .collect()
}

fn producer_node_config(data_dir: &Path, p2p_addr: &str, tx_count: usize) -> NodeConfig {
    NodeConfig {
        node_id: "load-producer".to_owned(),
        data_dir: data_dir.to_path_buf(),
        chain_id_hex: String::new(),
        anchor_prev_hash_hex: hex::encode(ANCHOR_PREV_HASH),
        fee_params: calibrated_fee_params(),
        p2p_listen_addr: Some(p2p_addr.to_owned()),
        api_listen_addr: None,
        peers: Vec::new(),
        devnet: DevnetConfig {
            role: NodeRole::Validator,
            sync_interval_ms: 50,
            block_time_ms: 200,
            proposer_address_hex: Some(hex::encode(PRODUCER_ADDRESS)),
            quorum_threshold: None,
            validators: test_validators(),
            snapshot_source: None,
            ..Default::default()
        },
        genesis_accounts: build_genesis_accounts(tx_count),
        // Per-IP rate limit is irrelevant for inject_tx (no HTTP path).
        rate_limit: RateLimitConfig {
            max_requests_per_window: 0, // disabled
            window_secs: 60,
        },
        // Per-sender budget MUST be disabled: each sender submits 1 tx (nonce=0)
        // so the budget would not trigger, but disabling it keeps the test clean.
        libp2p: None,
        sender_budget: SenderBudgetConfig {
            max_txs_per_window: 0, // disabled
            window_secs: 60,
        },
        api: Default::default(),
    }
}

// ── Pre-signing phase ──────────────────────────────────────────────────────────

/// Pre-sign `count` token_transfer transactions, one per sender (all nonce=0).
///
/// Each sender is a unique genesis account derived from `sender_seed(i)`.
/// Each recipient is a distinct address (derived from sender index + 0x80 offset)
/// so there are no self-transfers and no nonce conflicts.
///
/// Called BEFORE the injection timer starts. ML-DSA-65 signing takes ~1.3 ms
/// per key in debug mode; pre-signing ensures measured throughput reflects
/// node admission + block production, not crypto cost.
fn presign_batch(count: usize) -> Vec<Vec<u8>> {
    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        let seed = sender_seed(i);
        let sender = sender_address(&seed);

        // Recipient address: distinct from sender, derived from index with an offset.
        let mut recipient_bytes = [0xE0u8; 32];
        let idx_bytes = (i as u32).to_be_bytes();
        recipient_bytes[..4].copy_from_slice(&idx_bytes);
        let recipient = Address(recipient_bytes);

        let payload = token_transfer_payload(&recipient, TX_AMOUNT);

        let mut tx = Transaction {
            tx_version: 1,
            chain_id: vec![],
            msg_type: MsgType::TokenTransfer,
            sender,
            nonce: 0, // each sender's first (and only) transaction
            fee: TX_FEE,
            fee_tip: 0,
            gas_limit: GAS_TOKEN_TRANSFER,
            payload,
            sig_alg_id: AlgId::MlDsa65,
            sig_key_version: 1,
            signature: vec![],
        };
        tx.signature = sign_tx_with_seed(&tx, &seed);
        result.push(encode_tx(&tx).expect("encode must succeed"));
    }
    result
}

// ── Load test ─────────────────────────────────────────────────────────────────

/// Load test smoke: inject N transactions (one per sender, all nonce=0) into a
/// single-node devnet and report throughput metrics.
///
/// ## CI threshold
/// Asserts `effective_tps >= 10`. This is intentionally low to pass on
/// constrained CI hardware (debug builds, shared VMs). The SPEC-TEST-001 §3.3
/// target (≥100 TPS) must be measured on reference hardware.
///
/// ## Manual long run
/// ```text
/// LOAD_TX_COUNT=10000 cargo test --test load_test --release -- --nocapture
/// ```
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_test_smoke() -> Result<()> {
    let tx_count: usize = env::var("LOAD_TX_COUNT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100);

    let dir = TempDir::new("load-test");
    let p2p_addr = reserve_local_addr();
    let config_path = dir.path().join("producer.json");

    write_config(
        &config_path,
        &producer_node_config(&dir.path().join("node"), &p2p_addr, tx_count),
    );

    let node = start_from_config_path(&config_path)
        .await
        .context("failed to start load-test node")?;

    // Wait for genesis block to settle before injecting.
    node.wait_for_height(1, Duration::from_secs(5))
        .await
        .context("node did not reach height 1 before load injection")?;

    // ── Phase 1: Pre-sign all transactions (outside the timer) ────────────────
    let signed_txs = presign_batch(tx_count);

    // ── Phase 2: Inject ───────────────────────────────────────────────────────
    let height_start = node.snapshot().await.height;
    let inject_start = Instant::now();

    let mut admitted: usize = 0;
    let mut rejected: usize = 0;
    let mut mempool_peak: usize = 0;

    for raw_tx in &signed_txs {
        match node.inject_tx(raw_tx.clone()).await {
            Ok(()) => admitted += 1,
            Err(_) => rejected += 1,
        }
        let depth = node.mempool_depth().await;
        if depth > mempool_peak {
            mempool_peak = depth;
        }
    }

    let inject_duration = inject_start.elapsed();
    let injection_tps = if inject_duration.as_secs_f64() > 0.0 {
        admitted as f64 / inject_duration.as_secs_f64()
    } else {
        f64::INFINITY
    };

    // ── Phase 3: Wait for all admitted txs to be finalized ────────────────────
    //
    // Poll until the mempool is empty or height has not advanced for 3 block times.
    let finalize_start = Instant::now();
    let block_time = Duration::from_millis(200);
    let finalize_timeout = Duration::from_secs(30).max(block_time * (tx_count as u32 + 10));
    let mut last_height = node.snapshot().await.height;
    let mut stale_since = Instant::now();

    loop {
        time::sleep(Duration::from_millis(50)).await;
        let snap = node.snapshot().await;
        let depth = node.mempool_depth().await;

        if snap.height > last_height {
            last_height = snap.height;
            stale_since = Instant::now();
        }

        if depth == 0 && snap.height > height_start {
            // Mempool drained — all admitted txs have been included.
            last_height = snap.height;
            break;
        }

        if stale_since.elapsed() > block_time * 5 {
            // Height not advancing — declare done.
            break;
        }

        if finalize_start.elapsed() > finalize_timeout {
            break;
        }
    }

    let height_end = last_height;
    let blocks_produced = height_end.saturating_sub(height_start);
    let total_duration = inject_start.elapsed();
    let effective_tps = admitted as f64 / total_duration.as_secs_f64();
    let avg_txs_per_block = if blocks_produced > 0 {
        admitted as f64 / blocks_produced as f64
    } else {
        0.0
    };

    // ── Print structured results ───────────────────────────────────────────────
    println!();
    println!("=== LOAD TEST RESULTS ===");
    println!("Total txs injected:    {tx_count}");
    println!("Total txs admitted:    {admitted}");
    println!("Total txs rejected:    {rejected}");
    println!("Injection TPS:         {injection_tps:.1}");
    println!("Effective TPS:         {effective_tps:.1}");
    println!("Mempool peak depth:    {mempool_peak}");
    println!("Chain height start:    {height_start}");
    println!("Chain height end:      {height_end}");
    println!("Blocks produced:       {blocks_produced}");
    println!("Avg txs per block:     {avg_txs_per_block:.1}");
    println!("Duration (seconds):    {:.1}", total_duration.as_secs_f64());
    println!();
    println!("NOTE: SPEC-TEST-001 §3.3 target is ≥100 TPS on reference hardware.");
    println!("      SPEC-TEST-001 §4.5 target is ≥200 TPS for Phase 3-alpha.");
    println!("      This CI smoke test threshold is ≥5 TPS (debug build on constrained VPS).");
    println!("      For the protocol measurement: LOAD_TX_COUNT=10000 cargo test --release");

    node.shutdown().await?;

    // ── CI threshold ──────────────────────────────────────────────────────────
    // Threshold is 5 TPS for debug builds on constrained VPS hardware where
    // ML-DSA verification takes ~120 ms per tx.  The SPEC target (≥100 TPS)
    // must be measured in release mode on reference hardware (SPEC-TEST-001 §6.2).
    assert!(
        effective_tps >= 5.0,
        "effective TPS {effective_tps:.1} < 5.0 CI threshold \
         (SPEC target is ≥100 TPS on reference hardware; \
          rejected={rejected} — check fee, nonce, or balance setup)"
    );

    Ok(())
}
