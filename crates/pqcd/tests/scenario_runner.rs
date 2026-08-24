// SPDX-License-Identifier: BUSL-1.1
//! Deterministic node scenario runner.
//!
//! Each scenario drives the node through a complete lifecycle segment — from
//! genesis through block production and "restart" — and asserts the recovery
//! contract at the system boundary (`bootstrap_from_config_path`).
//!
//! Scenarios, ordered from simplest to most adversarial:
//! 1. `happy_path_bootstrap_commit_restart` — tip hash / state root preserved across restart
//! 2. `full_replay_without_checkpoint_gives_same_tip_hash` — replay determinism
//! 3. `corrupted_checkpoint_falls_back_and_preserves_tip_hash` — soft error, graceful fallback
//! 4. `corrupted_tail_block_is_rejected` — hard error, fail-fast on block file corruption

use std::{
    env, fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use ciborium::value::Value;
use pqc_consensus::{
    AssemblyConfig, LocalProposer, LocalProposerConfig, RecoverySource, RocksDbChainStore,
};
use pqc_crypto::{sign::StubVerifier, AlgId};
use pqc_mempool::{admission::try_admit, Mempool};
use pqc_state::StateStore;
use pqc_tx::{codec::encode_tx, validate::FeeParams};
use pqc_types::{
    account::{Account, Address},
    block::{BlockHash, CommitSig},
    keyset::{allowed_tx, KeyEntry, KeySet, KeyStatus},
    transaction::{MsgType, Transaction},
};

use pqcd::node::{
    bootstrap_from_config_path, DevnetConfig, GenesisAccountConfig, GenesisKeyConfig,
    GenesisKeyStatus, NodeConfig,
};

// ── Filesystem helper ─────────────────────────────────────────────────────────

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "pqcd-scenario-{label}-{}-{unique}",
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

// ── Transaction / account fixtures ────────────────────────────────────────────

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

fn transfer_payload(recipient: &Address) -> Vec<u8> {
    cbor_map(vec![
        (1, CborVal::Bytes(recipient.0.to_vec())),
        (2, CborVal::Int(50)),
    ])
}

fn transfer_tx(sender: Address, nonce: u64, fill: u8) -> Transaction {
    Transaction {
        tx_version: 1,
        chain_id: vec![],
        msg_type: MsgType::TokenTransfer,
        sender,
        nonce,
        fee: 100,
        fee_tip: 0,
        gas_limit: 100_000,
        payload: transfer_payload(&Address([0x22; 32])),
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![fill; 3_309],
    }
}

fn signer_account(address: Address) -> Account {
    Account {
        address,
        balance: 100_000,
        nonce: 0,
        keys: KeySet(vec![KeyEntry {
            alg_id: AlgId::MlDsa65,
            pk_bytes: vec![0u8; 32].into(),
            key_version: 1,
            valid_from_height: 0,
            status: KeyStatus::Active,
            allowed_tx_types: allowed_tx::ALL,
        }]),
        policy_version: 0,
        policy_hash: None,
        verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
        auth_data: Vec::new(),
    }
}

fn admit(pool: &mut Mempool, store: &StateStore, tx: &Transaction) {
    let raw = encode_tx(tx).unwrap();
    try_admit(pool, raw, store, &StubVerifier, &FeeParams::default()).unwrap();
}

// ── Config fixture ────────────────────────────────────────────────────────────

fn write_config(config_path: &Path, data_dir: &Path, sender: &Address) {
    let config = NodeConfig {
        node_id: "scenario-node".to_owned(),
        data_dir: data_dir.to_path_buf(),
        // Empty chain_id matches the test transactions which also use Vec::new().
        chain_id_hex: String::new(),
        anchor_prev_hash_hex: hex::encode([0x11; 32]),
        fee_params: FeeParams::default(),
        p2p_listen_addr: None,
        api_listen_addr: None,
        peers: Vec::new(),
        devnet: DevnetConfig::default(),
        genesis_accounts: vec![GenesisAccountConfig {
            address_hex: hex::encode(sender.0),
            balance: 100_000,
            nonce: 0,
            keys: vec![GenesisKeyConfig {
                alg_id: AlgId::MlDsa65.as_u16(),
                pk_hex: hex::encode([0u8; 32]),
                key_version: 1,
                valid_from_height: 0,
                status: GenesisKeyStatus::Active,
                allowed_tx_types: allowed_tx::ALL,
            }],
        }],
        rate_limit: Default::default(),
        libp2p: None,
        sender_budget: Default::default(),
        api: Default::default(),
    };
    fs::write(config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
}

// ── Chain builder ─────────────────────────────────────────────────────────────

/// The live state recorded during chain production — used to assert equivalence
/// after a simulated restart.
struct LiveChainSnapshot {
    sender: Address,
    /// Tip hash as the proposer last committed it.
    tip_hash: BlockHash,
    /// State root from the last committed block.
    state_root: BlockHash,
    /// Block height after all blocks are committed.
    height: u64,
}

/// Produce `n_blocks` blocks on a fresh `RocksDbChainStore` in `data_dir`.
/// Each block contains one token transfer transaction.
/// A trusted checkpoint is written immediately after `checkpoint_after_height`
/// if `Some` is passed.
fn build_chain(
    data_dir: &Path,
    n_blocks: u64,
    checkpoint_after_height: Option<u64>,
) -> LiveChainSnapshot {
    let anchor = BlockHash([0x11; 32]);
    let sender = Address([0xA1; 32]);

    let mut state = StateStore::new();
    state.insert_account(signer_account(sender.clone()));

    let mut pool = Mempool::new();
    let mut proposer = LocalProposer::new(
        [0x99; 32],
        LocalProposerConfig {
            assembly: AssemblyConfig::default(),
            initial_prev_hash: anchor.clone(),
        },
    );
    let mut disk = RocksDbChainStore::open(data_dir.join("rocksdb"), anchor).unwrap();

    let mut last_state_root = BlockHash([0u8; 32]);

    for i in 0..n_blocks {
        let tx = transfer_tx(sender.clone(), i, (i + 1) as u8);
        admit(&mut pool, &state, &tx);

        let mut result = proposer
            .run_once(&mut state, &mut pool, 1_710_000_000 + i)
            .unwrap();

        // Attach a stub commit signature so the persisted block satisfies the
        // ADR-054 §Stage 6 strict-finality audit (`verify_quick_finality_invariants`)
        // run by `bootstrap_from_config_path`. The audit only checks
        // `commit_signatures.is_empty()`; signature validity itself is
        // verified by `validate_block_commit_quorum` when `append_block` is
        // given a non-`None` `CommitQuorumPolicy` — this fixture intentionally
        // passes `None` (single-node, no validator set) so the stub bytes are
        // never verified cryptographically.
        result.block.commit_signatures.push(CommitSig {
            validator_address: vec![0xAA; 32],
            sig_alg_id: AlgId::MlDsa65,
            round: 0,
            signature: vec![0xBB; 64],
        });

        last_state_root = result.state_root.clone();
        disk.append_block(&result, None).unwrap();

        if checkpoint_after_height == Some(result.new_height) {
            disk.write_trusted_checkpoint(&state).unwrap();
        }
    }

    LiveChainSnapshot {
        sender,
        tip_hash: proposer.tip_hash().clone(),
        state_root: last_state_root,
        height: state.block_height(),
    }
}

// ── Scenarios ─────────────────────────────────────────────────────────────────

/// Scenario 1: node produces 3 blocks, writes a checkpoint at height 2, then
/// "restarts". The recovered tip hash and state root must be byte-identical to
/// what the live node last observed. No information is lost across a clean stop.
#[test]
fn happy_path_bootstrap_commit_restart() {
    let dir = TempDir::new("happy-path");
    let data_dir = dir.path().join("data");
    let config_path = dir.path().join("node.json");

    let live = build_chain(&data_dir, 3, Some(2));
    write_config(&config_path, &data_dir, &live.sender);

    let report =
        bootstrap_from_config_path(&config_path).expect("bootstrap must succeed after clean stop");

    assert_eq!(report.chain_height, live.height);
    assert_eq!(
        report.tip_hash, live.tip_hash,
        "tip hash must be identical after restart"
    );
    assert_eq!(
        report.state_root, live.state_root,
        "state root must be identical after restart"
    );
    assert_eq!(report.recovery_source, RecoverySource::TrustedCheckpoint);
    assert_eq!(
        report.checkpoint.as_ref().map(|c| c.height),
        Some(2),
        "checkpoint height must be 2 (where it was written)"
    );
}

/// Scenario 2: restart without any checkpoint falls back to full replay.
/// Replay is deterministic: the replayed tip hash and state root must match
/// what the live proposer computed during original block production.
#[test]
fn full_replay_without_checkpoint_gives_same_tip_hash() {
    let dir = TempDir::new("full-replay");
    let data_dir = dir.path().join("data");
    let config_path = dir.path().join("node.json");

    let live = build_chain(&data_dir, 3, None);
    write_config(&config_path, &data_dir, &live.sender);

    let report =
        bootstrap_from_config_path(&config_path).expect("bootstrap must succeed via full replay");

    assert_eq!(report.chain_height, live.height);
    assert_eq!(report.recovery_source, RecoverySource::FullReplay);
    assert_eq!(
        report.tip_hash, live.tip_hash,
        "full replay must produce the same tip hash as live production"
    );
    assert_eq!(
        report.state_root, live.state_root,
        "full replay must produce the same state root as live production"
    );
    assert!(report.checkpoint.is_none());
}

/// Scenario 3: a corrupted checkpoint triggers graceful fallback to full replay.
/// Even via the longer recovery path, the final tip hash must still match —
/// the recovery contract is: correct state or error, never silently wrong state.
#[test]
fn corrupted_checkpoint_falls_back_and_preserves_tip_hash() {
    let dir = TempDir::new("corrupt-ckpt");
    let data_dir = dir.path().join("data");
    let config_path = dir.path().join("node.json");

    let live = build_chain(&data_dir, 3, Some(2));
    write_config(&config_path, &data_dir, &live.sender);

    // Corrupt the checkpoint via RocksDB (blocks/checkpoints are column families,
    // not flat files, after the DiskChainStore → RocksDbChainStore migration).
    {
        let anchor = BlockHash([0x11; 32]);
        let db = RocksDbChainStore::open(data_dir.join("rocksdb"), anchor).unwrap();
        db.corrupt_checkpoint(2, b"NOT-A-VALID-CBOR-CHECKPOINT");
    }

    let report = bootstrap_from_config_path(&config_path)
        .expect("bootstrap must succeed after checkpoint fallback");

    assert_eq!(report.chain_height, live.height);
    assert_eq!(report.recovery_source, RecoverySource::FullReplay);
    assert_eq!(
        report.tip_hash, live.tip_hash,
        "fallback replay tip hash must match live state"
    );
    assert_eq!(
        report.state_root, live.state_root,
        "fallback replay state root must match live state"
    );
    assert!(report.checkpoint.is_none());
}

/// Scenario 4: a corrupted committed block file is a hard error.
/// The node must not silently fall back or produce a state derived from
/// incomplete history. This distinguishes soft checkpoint errors (recoverable)
/// from committed-history corruption (unrecoverable without operator action).
#[test]
fn corrupted_tail_block_is_rejected() {
    let dir = TempDir::new("corrupt-tail");
    let data_dir = dir.path().join("data");
    let config_path = dir.path().join("node.json");

    let live = build_chain(&data_dir, 2, None);
    write_config(&config_path, &data_dir, &live.sender);

    // Corrupt the block at height 2 via RocksDB (blocks are a column family,
    // not flat files, after the DiskChainStore → RocksDbChainStore migration).
    {
        let anchor = BlockHash([0x11; 32]);
        let db = RocksDbChainStore::open(data_dir.join("rocksdb"), anchor).unwrap();
        assert!(
            db.export_block_bytes(2).unwrap().is_some(),
            "block must exist before corruption"
        );
        db.corrupt_block(2, b"CORRUPTED");
    }

    let result = bootstrap_from_config_path(&config_path);
    assert!(
        result.is_err(),
        "corrupted committed block must be a hard error, not a graceful fallback"
    );
}
