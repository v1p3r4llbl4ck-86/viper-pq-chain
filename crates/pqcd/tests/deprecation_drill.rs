// SPDX-License-Identifier: BUSL-1.1
//! TASK-055 — Algorithm lifecycle deprecation drill.
//!
//! Exercises the full 4-step governance lifecycle (Active → Discouraged →
//! Deprecated → Banned) for ML-DSA-44 on a live single-node devnet.
//!
//! SPEC-TEST-001 §4.2 requires this drill to be demonstrated end-to-end before
//! Phase 3-alpha exit.
//!
//! ## What is verified at each stage
//!
//! | Stage                 | Tx with old-alg signing key | New key registration |
//! |-----------------------|-----------------------------|-----------------------|
//! | Active (baseline)     | Accepted (inject_tx Ok)     | Covered by unit tests |
//! | Discouraged           | Accepted (inject_tx Ok)     | Covered by unit tests |
//! | Deprecated            | Rejected (inject_tx Err)    | Covered by unit tests |
//! | Banned                | Rejected (inject_tx Err)    | Covered by unit tests |
//!
//! Key registration restrictions (new keys blocked for Discouraged and above)
//! are tested in `pqc-state::tests` unit tests — specifically
//! `key_add_rejects_discouraged_algorithm_registration`. This integration test
//! focuses on the governance lifecycle transitions and the mempool admission
//! behavior at each stage.
//!
//! ## Algorithm under deprecation
//!
//! ML-DSA-44 (alg_id 0x0001) — distinct from the ML-DSA-65 used by the
//! governance sender account (which remains unaffected throughout the drill).

use std::{
    env, fs,
    net::TcpListener as StdTcpListener,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use ciborium::value::Value;
use pqc_crypto::{
    derive_address, ml_dsa_public_key_from_seed, ml_dsa_sign_with_seed, AlgId, Lifecycle,
};
use pqc_tx::{codec::encode_tx, compute_tx_hash, preimage::build_preimage, validate::FeeParams};
use pqc_types::{
    account::Address,
    governance::GovernanceProposalType,
    keyset::allowed_tx,
    transaction::{MsgType, Transaction},
};
use pqcd::{
    devnet::{start_from_config_path, DevnetNodeHandle},
    node::{
        DevnetConfig, GenesisAccountConfig, GenesisKeyConfig, GenesisKeyStatus, NodeConfig,
        NodeRole, ValidatorConfig,
    },
};
use tokio::time::Duration;

// ── Test constants ─────────────────────────────────────────────────────────────

const ANCHOR_PREV_HASH: [u8; 32] = [0x11; 32];
const PRODUCER_ADDRESS: [u8; 32] = [0x99; 32];
const SENDER_BALANCE: u128 = 10_000_000;

/// Algorithm being deprecated through the full 4-step lifecycle.
const ALG_UNDER_DRILL: AlgId = AlgId::MlDsa44;

// ── Governance sender (ML-DSA-65) — submits governance proposals ───────────────
const GOV_SEED: [u8; 32] = [0xA0; 32];

fn gov_pk() -> Vec<u8> {
    ml_dsa_public_key_from_seed(AlgId::MlDsa65, &GOV_SEED).expect("gov pk")
}

fn gov_address() -> Address {
    let pk = gov_pk();
    // chain_id matches the empty chain_id used in txs and node config below.
    Address(derive_address(&[], AlgId::MlDsa65, &pk))
}

fn gov_sign(tx: &Transaction) -> Vec<u8> {
    let preimage =
        build_preimage(&pqc_types::ForkDigest::viper_research_1(), tx).expect("preimage");
    ml_dsa_sign_with_seed(AlgId::MlDsa65, &GOV_SEED, &preimage).expect("sign")
}

// ── ML-DSA-44 sender — signing key is the one being deprecated ────────────────
const DRILL_SEED: [u8; 32] = [0xB0; 32];

fn drill_pk() -> Vec<u8> {
    ml_dsa_public_key_from_seed(AlgId::MlDsa44, &DRILL_SEED).expect("drill pk")
}

fn drill_address() -> Address {
    let pk = drill_pk();
    // chain_id matches the empty chain_id used in txs and node config below.
    Address(derive_address(&[], AlgId::MlDsa44, &pk))
}

fn drill_sign(tx: &Transaction) -> Vec<u8> {
    let preimage =
        build_preimage(&pqc_types::ForkDigest::viper_research_1(), tx).expect("preimage");
    ml_dsa_sign_with_seed(AlgId::MlDsa44, &DRILL_SEED, &preimage).expect("sign")
}

// ── Test infrastructure ───────────────────────────────────────────────────────

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "pqcd-drill-{label}-{}-{unique}",
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

fn reserve_local_addr() -> String {
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    format!("127.0.0.1:{}", addr.port())
}

fn write_config(path: &Path, config: &NodeConfig) {
    fs::write(path, serde_json::to_vec_pretty(config).unwrap()).unwrap();
}

// ── Validator voter accounts — use commit_seed for ML-DSA-65 account signing ──
//
// Each validator also has a genesis account at their operator address.  They use
// their commit seed as the signing seed for governance vote transactions.
// (In production, the governance signing key would typically differ from the
// consensus key, but using the same seed is correct for tests.)
const VALIDATOR_DATA: [(&str, [u8; 32], [u8; 32]); 3] = [
    ("validator-1", [0xA1u8; 32], [0x11u8; 32]),
    ("validator-2", [0xA2u8; 32], [0x22u8; 32]),
    ("validator-3", [0xA3u8; 32], [0x33u8; 32]),
];

fn validator_configs() -> Vec<ValidatorConfig> {
    VALIDATOR_DATA
        .into_iter()
        .map(|(node_id, address, commit_seed)| {
            let pk =
                ml_dsa_public_key_from_seed(AlgId::MlDsa65, &commit_seed).expect("validator pk");
            ValidatorConfig {
                node_id: node_id.to_owned(),
                address_hex: hex::encode(address),
                sig_alg_id: AlgId::MlDsa65.as_u16(),
                public_key_hex: hex::encode(&pk),
                commit_seed_hex: Some(hex::encode(commit_seed)),
                archival_sk_hex: None,
            }
        })
        .collect()
}

/// Genesis accounts for validator operators so they can submit GovernanceVote txs.
fn validator_genesis_accounts() -> Vec<GenesisAccountConfig> {
    VALIDATOR_DATA
        .into_iter()
        .map(|(_node_id, address, commit_seed)| {
            let pk = ml_dsa_public_key_from_seed(AlgId::MlDsa65, &commit_seed)
                .expect("validator account pk");
            GenesisAccountConfig {
                address_hex: hex::encode(address),
                balance: SENDER_BALANCE,
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

async fn start_producer(data_dir: &Path) -> DevnetNodeHandle {
    let p2p_addr = reserve_local_addr();
    let mut genesis_accounts = vec![
        // Governance sender — ML-DSA-65, submits governance proposals.
        GenesisAccountConfig {
            address_hex: hex::encode(gov_address().0),
            balance: SENDER_BALANCE,
            nonce: 0,
            keys: vec![GenesisKeyConfig {
                alg_id: AlgId::MlDsa65.as_u16(),
                pk_hex: hex::encode(gov_pk()),
                key_version: 1,
                valid_from_height: 0,
                status: GenesisKeyStatus::Active,
                allowed_tx_types: allowed_tx::ALL,
            }],
        },
        // Drill sender — ML-DSA-44 signing key, deprecated through the drill.
        GenesisAccountConfig {
            address_hex: hex::encode(drill_address().0),
            balance: SENDER_BALANCE,
            nonce: 0,
            keys: vec![GenesisKeyConfig {
                alg_id: AlgId::MlDsa44.as_u16(),
                pk_hex: hex::encode(drill_pk()),
                key_version: 1,
                valid_from_height: 0,
                status: GenesisKeyStatus::Active,
                allowed_tx_types: allowed_tx::ALL,
            }],
        },
    ];
    // Validator accounts for governance voting (TASK-100).
    genesis_accounts.extend(validator_genesis_accounts());

    let cfg = NodeConfig {
        node_id: "producer".to_owned(),
        data_dir: data_dir.to_path_buf(),
        chain_id_hex: String::new(),
        anchor_prev_hash_hex: hex::encode(ANCHOR_PREV_HASH),
        fee_params: FeeParams::default(),
        p2p_listen_addr: Some(p2p_addr),
        api_listen_addr: None,
        peers: Vec::new(),
        devnet: DevnetConfig {
            role: NodeRole::Validator,
            sync_interval_ms: 50,
            // 10 ms block time target; debug-build ML-DSA crypto makes actual
            // block time ~1-2 s.  GOVERNANCE_VOTING_PERIOD=5 → ~5-10 s per step.
            block_time_ms: 10,
            proposer_address_hex: Some(hex::encode(PRODUCER_ADDRESS)),
            quorum_threshold: None,
            validators: validator_configs(),
            snapshot_source: None,
            ..Default::default()
        },
        genesis_accounts,
        rate_limit: Default::default(),
        libp2p: None,
        sender_budget: Default::default(),
        api: Default::default(),
    };
    let cfg_path = data_dir.join("producer.json");
    write_config(&cfg_path, &cfg);
    start_from_config_path(&cfg_path)
        .await
        .expect("producer start")
}

// ── CBOR helpers ──────────────────────────────────────────────────────────────

enum CborVal {
    Int(u64),
    Bytes(Vec<u8>),
}

fn cbor_map(pairs: Vec<(u64, CborVal)>) -> Vec<u8> {
    let entries: Vec<(Value, Value)> = pairs
        .into_iter()
        .map(|(k, v)| {
            let key = Value::Integer(k.into());
            let val = match v {
                CborVal::Int(i) => Value::Integer(i.into()),
                CborVal::Bytes(b) => Value::Bytes(b),
            };
            (key, val)
        })
        .collect();
    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(entries), &mut out).unwrap();
    out
}

/// Build a signed governance_proposal(registry_update) tx from the gov sender.
///
/// `lifecycle_code`: 1=Discouraged, 2=Deprecated, 3=Banned.
fn governance_tx(
    nonce: u64,
    alg_id: AlgId,
    lifecycle_code: u8,
    new_min_fee: Option<u64>,
) -> Vec<u8> {
    let mut pairs = vec![
        (
            1,
            CborVal::Int(GovernanceProposalType::RegistryUpdate.as_u8() as u64),
        ),
        (2, CborVal::Int(alg_id.as_u16() as u64)),
        (3, CborVal::Int(lifecycle_code as u64)),
        (6, CborVal::Bytes([0x00; 32].to_vec())), // rationale_hash
    ];
    if let Some(fee) = new_min_fee {
        pairs.push((4, CborVal::Int(fee)));
    }
    let payload = cbor_map(pairs);
    // Fee covers the heavy lane (2× multiplier) after AIMD floor (BASE_FEE_MIN=100):
    // effective_base_fee = 100 × 2 = 200. Use 1_000 for headroom.
    let mut tx = Transaction {
        tx_version: 1,
        chain_id: Vec::new(),
        msg_type: MsgType::GovernanceProposal,
        sender: gov_address(),
        nonce,
        fee: 1_000,
        fee_tip: 0,
        gas_limit: 100,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 10],
    };
    tx.signature = gov_sign(&tx);
    encode_tx(&tx).expect("encode governance tx")
}

/// Build a signed governance_proposal tx and return (encoded_bytes, proposal_id).
fn governance_tx_with_id(
    nonce: u64,
    alg_id: AlgId,
    lifecycle_code: u8,
    new_min_fee: Option<u64>,
) -> (Vec<u8>, [u8; 32]) {
    let tx_bytes = governance_tx(nonce, alg_id, lifecycle_code, new_min_fee);
    let proposal_id = compute_tx_hash(&tx_bytes);
    (tx_bytes, proposal_id)
}

/// Build a signed governance_vote tx for a validator.
///
/// `proposal_id_bytes` is the 32-byte hash of the governance proposal tx.
/// Nonces are tracked by the caller per-validator.
fn governance_vote_tx(
    validator_index: usize,
    nonce: u64,
    proposal_id_bytes: [u8; 32],
    yes: bool,
) -> Vec<u8> {
    let (_node_id, address, commit_seed) = VALIDATOR_DATA[validator_index];
    let voter_addr = Address(address);
    let vote_val = if yes { 1u64 } else { 0u64 };
    let payload = cbor_map(vec![
        (1, CborVal::Bytes(proposal_id_bytes.to_vec())),
        (2, CborVal::Int(vote_val)),
    ]);
    let mut tx = Transaction {
        tx_version: 1,
        chain_id: Vec::new(),
        msg_type: MsgType::GovernanceVote,
        sender: voter_addr,
        nonce,
        fee: 500,
        fee_tip: 0,
        gas_limit: 100,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 10],
    };
    let preimage =
        build_preimage(&pqc_types::ForkDigest::viper_research_1(), &tx).expect("preimage");
    tx.signature =
        ml_dsa_sign_with_seed(AlgId::MlDsa65, &commit_seed, &preimage).expect("sign vote tx");
    encode_tx(&tx).expect("encode governance vote tx")
}

/// Build a signed proof_anchor tx from the drill sender (signs with MlDsa44).
///
/// proof_anchor is used because it has no secondary state effects and the sender
/// doesn't need to match any existing account for the state operation to succeed.
fn drill_proof_anchor_tx(nonce: u64, fill: u8) -> Vec<u8> {
    let payload = cbor_map(vec![
        (1, CborVal::Int(0x0001)),                // claim_type = ownership
        (2, CborVal::Bytes([fill; 32].to_vec())), // asset_id_hash (unique per call)
        (3, CborVal::Bytes([fill.wrapping_add(1); 32].to_vec())), // proof_hash
    ]);
    // Fee covers standard lane after AIMD floor (BASE_FEE_MIN=100). Use 500 for headroom.
    let mut tx = Transaction {
        tx_version: 1,
        chain_id: Vec::new(),
        msg_type: MsgType::ProofAnchor,
        sender: drill_address(),
        nonce,
        fee: 500,
        fee_tip: 0,
        gas_limit: 100,
        payload,
        sig_alg_id: AlgId::MlDsa44,
        sig_key_version: 1,
        signature: vec![0u8; 10],
    };
    tx.signature = drill_sign(&tx);
    encode_tx(&tx).expect("encode drill tx")
}

/// Build a signed proof_anchor tx from the gov sender (ML-DSA-65 — unaffected).
fn gov_proof_anchor_tx(nonce: u64, fill: u8) -> Vec<u8> {
    let payload = cbor_map(vec![
        (1, CborVal::Int(0x0001)),
        (2, CborVal::Bytes([fill; 32].to_vec())),
        (3, CborVal::Bytes([fill.wrapping_add(0x80); 32].to_vec())),
    ]);
    // Fee covers standard lane after AIMD floor (BASE_FEE_MIN=100). Use 500 for headroom.
    let mut tx = Transaction {
        tx_version: 1,
        chain_id: Vec::new(),
        msg_type: MsgType::ProofAnchor,
        sender: gov_address(),
        nonce,
        fee: 500,
        fee_tip: 0,
        gas_limit: 100,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 10],
    };
    tx.signature = gov_sign(&tx);
    encode_tx(&tx).expect("encode gov anchor tx")
}

/// Wait until `producer.alg_lifecycle(alg)` returns `expected`.
///
/// Polls every 50 ms with a hard timeout. Used after submitting governance
/// proposals because a single `wait_for_height_advance(1)` can fire before
/// the tx is included in a block (race between block production and injection).
async fn wait_for_lifecycle(
    producer: &DevnetNodeHandle,
    alg: AlgId,
    expected: Lifecycle,
    label: &str,
) -> Result<()> {
    // With GOVERNANCE_VOTING_PERIOD=5 and debug-build block times of ~1-2 s,
    // the voting period completes in ~10-15 s per step.  Allow 60 s for headroom.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        if let Some(lc) = producer.alg_lifecycle(alg).await {
            if lc == expected {
                return Ok(());
            }
        }
        if std::time::Instant::now() >= deadline {
            let current = producer.alg_lifecycle(alg).await;
            bail!(
                "timeout waiting for {alg:?} lifecycle to become {expected:?} ({label}); \
                 current: {current:?}"
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// Wait for at least one block to commit (gives the mempool time to drain after injection).
async fn wait_for_block(producer: &DevnetNodeHandle, label: &str) -> Result<()> {
    producer
        .wait_for_height_advance(1, Duration::from_millis(3000))
        .await
        .with_context(|| format!("timeout waiting for block after: {label}"))?;
    Ok(())
}

// ── Drill test ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn algorithm_lifecycle_deprecation_drill() -> Result<()> {
    let dir = TempDir::new("drill");
    let producer = start_producer(dir.path()).await;

    producer
        .wait_for_height(1, Duration::from_secs(5))
        .await
        .context("genesis block not produced")?;

    // Nonce counters — tracked explicitly to avoid sequencing errors.
    let mut gov_nonce: u64 = 0;
    let mut drill_nonce: u64 = 0;
    // Nonces for each of the 3 validator voter accounts.
    let mut val_nonces: [u64; 3] = [0, 0, 0];

    // ─ Baseline: MlDsa44 is Active ────────────────────────────────────────────
    {
        let lc = producer
            .alg_lifecycle(ALG_UNDER_DRILL)
            .await
            .context("MlDsa44 not in registry")?;
        assert_eq!(lc, Lifecycle::Active, "baseline: MlDsa44 must start Active");

        // Tx signed with MlDsa44 must be admitted.
        producer
            .inject_tx(drill_proof_anchor_tx(drill_nonce, 0x10))
            .await
            .context("baseline: MlDsa44-signed tx must be admitted when Active")?;
        wait_for_block(&producer, "baseline drill_tx").await?;
        drill_nonce += 1;

        eprintln!("[DRILL] BASELINE Active:               tx accepted ✓");
    }

    // Helper: inject a governance proposal + 3 validator votes, then wait for
    // the lifecycle to change.  With GOVERNANCE_VOTING_PERIOD=1_000 and
    // block_time_ms=10, this takes ~10 s per step.
    //
    // We wait for at least 1 block after the proposal before injecting votes so
    // the proposal is guaranteed to be in state (ProposalNotFound otherwise).
    macro_rules! governance_step {
        ($label:expr, $lifecycle_code:expr, $expected_lc:expr, $fill:expr) => {{
            let (proposal_bytes, proposal_id) =
                governance_tx_with_id(gov_nonce, ALG_UNDER_DRILL, $lifecycle_code, None);
            producer
                .inject_tx(proposal_bytes)
                .await
                .context(concat!($label, ": governance proposal must be admitted"))?;
            gov_nonce += 1;

            // Wait for the proposal to be included in a block before voting.
            wait_for_block(&producer, concat!($label, " proposal inclusion")).await?;

            // All 3 validators vote yes — quorum = ceil(2/3 * 3) = 2 (3 yes > 2).
            for i in 0..3usize {
                producer
                    .inject_tx(governance_vote_tx(i, val_nonces[i], proposal_id, true))
                    .await
                    .with_context(|| {
                        format!("{}: validator {} vote must be admitted", $label, i)
                    })?;
                val_nonces[i] += 1;
            }

            wait_for_lifecycle(&producer, ALG_UNDER_DRILL, $expected_lc, $label).await?;
        }};
    }

    // ─ Step 1: Active → Discouraged ───────────────────────────────────────────
    {
        governance_step!(
            "step1",
            1, /* Discouraged */
            Lifecycle::Discouraged,
            0x11
        );
        eprintln!("[DRILL] STEP 1 Active→Discouraged:     lifecycle updated ✓");

        // Discouraged: existing MlDsa44 signing key still admits transactions.
        producer
            .inject_tx(drill_proof_anchor_tx(drill_nonce, 0x11))
            .await
            .context("Step 1: tx signed with discouraged MlDsa44 key must be admitted")?;
        wait_for_block(&producer, "step1 drill_tx").await?;
        drill_nonce += 1;

        eprintln!("[DRILL] STEP 1 Discouraged:            tx with old key accepted ✓");
        eprintln!(
            "[DRILL]        (new key_add rejection verified by unit tests in pqc-state::tests)"
        );
    }

    // ─ Step 2: Discouraged → Deprecated ──────────────────────────────────────
    {
        governance_step!(
            "step2",
            2, /* Deprecated */
            Lifecycle::Deprecated,
            0x12
        );
        eprintln!("[DRILL] STEP 2 Discouraged→Deprecated: lifecycle updated ✓");

        // Deprecated: tx signed with MlDsa44 is rejected at mempool (AlgorithmBanned).
        let err = producer
            .inject_tx(drill_proof_anchor_tx(drill_nonce, 0x12))
            .await
            .expect_err("Step 2: tx with deprecated MlDsa44 signing key must be rejected");
        // Check full error chain (anyhow wraps inner cause).
        let full_msg = format!("{err:?}").to_lowercase();
        assert!(
            full_msg.contains("algorithmbanned")
                || full_msg.contains("algorithm_banned")
                || full_msg.contains("banned"),
            "Step 2: expected algorithm-banned error anywhere in chain, got: {err:?}"
        );
        eprintln!("[DRILL] STEP 2 Deprecated:             tx with old key rejected at mempool ✓");
    }

    // ─ Step 3: Deprecated → Banned ────────────────────────────────────────────
    {
        governance_step!("step3", 3 /* Banned */, Lifecycle::Banned, 0x13);
        eprintln!("[DRILL] STEP 3 Deprecated→Banned:      lifecycle updated ✓");

        // Banned: tx with MlDsa44 signing key is still rejected.
        let err = producer
            .inject_tx(drill_proof_anchor_tx(drill_nonce, 0x13))
            .await
            .expect_err("Step 3: tx with banned MlDsa44 signing key must be rejected");
        let full_msg = format!("{err:?}").to_lowercase();
        assert!(
            full_msg.contains("algorithmbanned")
                || full_msg.contains("algorithm_banned")
                || full_msg.contains("banned"),
            "Step 3: expected algorithm-banned error anywhere in chain, got: {err:?}"
        );
        eprintln!("[DRILL] STEP 3 Banned:                 tx with old key rejected at mempool ✓");

        // ML-DSA-65 account (gov sender) is completely unaffected.
        producer
            .inject_tx(gov_proof_anchor_tx(gov_nonce, 0x20))
            .await
            .context("Step 3: ML-DSA-65 account must be unaffected by MlDsa44 ban")?;
        wait_for_block(&producer, "step3 unaffected account").await?;
        gov_nonce += 1;

        eprintln!(
            "[DRILL] STEP 3:                        unaffected ML-DSA-65 account still transacts ✓"
        );
    }

    // ─ Verify chain advanced (3 governance steps + votes) ────────────────────
    {
        let snap = producer.snapshot().await;
        // Each step: 1 proposal + 3 votes + GOVERNANCE_VOTING_PERIOD blocks for voting deadline.
        // With GOVERNANCE_VOTING_PERIOD = 5 and 3 steps, at least ~15 blocks needed.
        assert!(
            snap.height >= 15,
            "expected at least 15 blocks for full drill, got {}",
            snap.height
        );
        eprintln!("[DRILL] chain height after drill: {}", snap.height);
    }

    // ─ Summary ────────────────────────────────────────────────────────────────
    eprintln!("=== DEPRECATION DRILL SUMMARY (SPEC-TEST-001 §4.2) ===");
    eprintln!("BASELINE  Active:               tx accepted ✓");
    eprintln!(
        "STEP 1    Active→Discouraged:   lifecycle updated; tx accepted; key_add blocked (unit) ✓"
    );
    eprintln!("STEP 2    Discouraged→Deprecated: lifecycle updated; tx rejected at mempool ✓");
    eprintln!(
        "STEP 3    Deprecated→Banned:    lifecycle updated; tx rejected; unaffected algo OK ✓"
    );
    eprintln!("DRILL COMPLETE — all lifecycle stages exercised");

    // Suppress "unused variable" warnings from nonce trackers.
    let _ = (gov_nonce, drill_nonce, val_nonces);

    producer.shutdown().await.context("shutdown")?;
    Ok(())
}
