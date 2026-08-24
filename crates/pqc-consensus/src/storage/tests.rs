// SPDX-License-Identifier: BUSL-1.1
//! Unit tests for `DiskChainStore`.
//!
//! Extracted from `storage.rs` 2026-05-10. `use super::*;` brings
//! every private item from storage.rs into scope.

use std::{
    env, fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use ciborium::value::Value;
use pqc_crypto::{sign::StubVerifier, AlgId};
use pqc_mempool::{admission::try_admit, Mempool};
use pqc_state::StateStore;
use pqc_tx::{
    codec::{decode_tx, encode_tx},
    validate::FeeParams,
};
use pqc_types::{
    account::{Account, Address},
    block::BlockHash,
    keyset::{allowed_tx, KeyEntry, KeySet, KeyStatus},
    transaction::{MsgType, Transaction},
};

use crate::{
    engine::compute_block_hash, AssemblyConfig, ChainError, ChainStore, LocalProposer,
    LocalProposerConfig,
};

use super::{
    block_file_name, hash_index_file_name, read_cbor, record_into_stored_block,
    stored_block_into_record, write_cbor, DiskChainStore, HashIndexRecord, RecoverySource,
    StorageError, StoredBlockRecord, TipRecord, TrustedCheckpointMetadata,
    TrustedCheckpointMetadataRecord, TrustedCheckpointRecord, BLOCKS_DIR, CHECKPOINTS_DIR,
    CHECKPOINT_FILE, HASHES_DIR, STAGING_DIR, TIP_FILE,
};

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "pqc-disk-store-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn cbor_map(pairs: Vec<(u64, CborVal)>) -> Vec<u8> {
    let entries: Vec<(Value, Value)> = pairs
        .into_iter()
        .map(|(key, value)| {
            let key = Value::Integer(key.into());
            let value = match value {
                CborVal::Int(int) => Value::Integer(int.into()),
                CborVal::Bytes(bytes) => Value::Bytes(bytes),
            };
            (key, value)
        })
        .collect();

    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(entries), &mut out).unwrap();
    out
}

enum CborVal {
    Int(u64),
    Bytes(Vec<u8>),
}

fn signer_account(address: Address, balance: u128, nonce: u64, alg_id: AlgId) -> Account {
    Account {
        address,
        balance,
        nonce,
        keys: KeySet(vec![KeyEntry {
            alg_id,
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

fn transfer_payload(recipient: &Address, amount: u64) -> Vec<u8> {
    cbor_map(vec![
        (1, CborVal::Bytes(recipient.0.to_vec())),
        (2, CborVal::Int(amount)),
    ])
}

fn transfer_tx(
    sender: Address,
    recipient: Address,
    nonce: u64,
    fee: u64,
    fee_tip: u64,
    signature_fill: u8,
) -> Transaction {
    Transaction {
        tx_version: 1,
        chain_id: Vec::new(),
        msg_type: MsgType::TokenTransfer,
        sender,
        nonce,
        fee,
        fee_tip,
        gas_limit: 100_000,
        payload: transfer_payload(&recipient, 100),
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![signature_fill; 3_309],
    }
}

fn admit(pool: &mut Mempool, store: &StateStore, tx: &Transaction) {
    let raw = encode_tx(tx).expect("encode must succeed");
    let verifier = StubVerifier;
    try_admit(pool, raw, store, &verifier, &FeeParams::default()).expect("admission must succeed");
}

fn proposer() -> LocalProposer {
    LocalProposer::new(
        [0x99; 32],
        LocalProposerConfig {
            assembly: AssemblyConfig::default(),
            initial_prev_hash: BlockHash([0x11; 32]),
        },
    )
}

fn checkpoint_path(root: &Path) -> PathBuf {
    root.join(CHECKPOINTS_DIR).join(CHECKPOINT_FILE)
}

fn build_persisted_chain(root: &Path) -> (StateStore, StateStore, ChainStore, DiskChainStore) {
    let sender = Address([0xA1; 32]);
    let recipient = Address([0x11; 32]);

    let mut genesis_state = StateStore::new();
    genesis_state.insert_account(signer_account(sender.clone(), 10_000, 0, AlgId::MlDsa65));

    let mut live_state = genesis_state.clone();
    let mut pool = Mempool::new();
    let mut proposer = proposer();
    let mut memory_chain = ChainStore::new(BlockHash([0x11; 32]));
    let mut disk =
        DiskChainStore::open(root, BlockHash([0x11; 32])).expect("disk store open must succeed");

    let first = transfer_tx(sender.clone(), recipient.clone(), 0, 100, 0, 0x01);
    admit(&mut pool, &live_state, &first);
    let result_1 = proposer
        .run_once(&mut live_state, &mut pool, 1_710_000_000)
        .expect("first run_once must succeed");
    memory_chain
        .append_block(&result_1)
        .expect("memory append must succeed");
    disk.append_block(&result_1)
        .expect("disk append must succeed");

    let second = transfer_tx(sender, recipient, 1, 100, 0, 0x02);
    admit(&mut pool, &live_state, &second);
    let result_2 = proposer
        .run_once(&mut live_state, &mut pool, 1_710_000_001)
        .expect("second run_once must succeed");
    memory_chain
        .append_block(&result_2)
        .expect("memory append must succeed");
    disk.append_block(&result_2)
        .expect("disk append must succeed");

    (genesis_state, live_state, memory_chain, disk)
}

fn build_persisted_chain_with_checkpoint(
    root: &Path,
) -> (
    StateStore,
    StateStore,
    ChainStore,
    DiskChainStore,
    TrustedCheckpointMetadata,
) {
    let sender = Address([0xA1; 32]);
    let recipient = Address([0x11; 32]);

    let mut genesis_state = StateStore::new();
    genesis_state.insert_account(signer_account(sender.clone(), 10_000, 0, AlgId::MlDsa65));

    let mut live_state = genesis_state.clone();
    let mut pool = Mempool::new();
    let mut proposer = proposer();
    let mut memory_chain = ChainStore::new(BlockHash([0x11; 32]));
    let mut disk =
        DiskChainStore::open(root, BlockHash([0x11; 32])).expect("disk store open must succeed");

    let first = transfer_tx(sender.clone(), recipient.clone(), 0, 100, 0, 0x01);
    admit(&mut pool, &live_state, &first);
    let result_1 = proposer
        .run_once(&mut live_state, &mut pool, 1_710_000_000)
        .expect("first run_once must succeed");
    memory_chain
        .append_block(&result_1)
        .expect("memory append must succeed");
    disk.append_block(&result_1)
        .expect("disk append must succeed");
    let checkpoint = disk
        .write_trusted_checkpoint(&live_state)
        .expect("checkpoint write must succeed");

    let second = transfer_tx(sender, recipient, 1, 100, 0, 0x02);
    admit(&mut pool, &live_state, &second);
    let result_2 = proposer
        .run_once(&mut live_state, &mut pool, 1_710_000_001)
        .expect("second run_once must succeed");
    memory_chain
        .append_block(&result_2)
        .expect("memory append must succeed");
    disk.append_block(&result_2)
        .expect("disk append must succeed");

    (genesis_state, live_state, memory_chain, disk, checkpoint)
}

#[test]
fn restart_rebuilds_chain_and_recovery_matches_in_memory() {
    let dir = TestDir::new("restart");
    let (genesis_state, live_state, memory_chain, disk) = build_persisted_chain(dir.path());
    drop(disk);

    let reopened =
        DiskChainStore::open(dir.path(), BlockHash([0x11; 32])).expect("reopen must succeed");

    assert_eq!(
        reopened.chain().metadata_in_order(),
        memory_chain.metadata_in_order()
    );
    assert_eq!(reopened.tip_hash(), memory_chain.tip_hash());

    let recovered = reopened
        .recover_tip(
            &genesis_state,
            FeeParams::default(),
            Default::default(),
            vec![],
        )
        .expect("recovery must succeed");
    assert_eq!(recovered.height, live_state.block_height());
    assert_eq!(recovered.tip_hash, reopened.tip_hash().unwrap().clone());

    let sender = Address([0xA1; 32]);
    let recipient = Address([0x11; 32]);
    assert_eq!(
        recovered.state.get_account(&sender).unwrap().balance,
        live_state.get_account(&sender).unwrap().balance
    );
    assert_eq!(
        recovered.state.get_account(&recipient).unwrap().balance,
        live_state.get_account(&recipient).unwrap().balance
    );
}

#[test]
fn recover_tip_with_valid_checkpoint_replays_tail_and_matches_full_replay() {
    let dir = TestDir::new("checkpoint-valid");
    let (genesis_state, live_state, memory_chain, disk, checkpoint) =
        build_persisted_chain_with_checkpoint(dir.path());
    drop(disk);

    let reopened =
        DiskChainStore::open(dir.path(), BlockHash([0x11; 32])).expect("reopen must succeed");
    let full = reopened
        .recover_tip(
            &genesis_state,
            FeeParams::default(),
            Default::default(),
            vec![],
        )
        .expect("full replay must succeed");
    let checkpointed = reopened
        .recover_tip_with_checkpoint(
            &genesis_state,
            FeeParams::default(),
            Default::default(),
            vec![],
        )
        .expect("checkpoint recovery must succeed");

    assert_eq!(checkpointed.source, RecoverySource::TrustedCheckpoint);
    assert_eq!(checkpointed.checkpoint, Some(checkpoint.clone()));
    assert_eq!(checkpointed.replay.height, full.height);
    assert_eq!(checkpointed.replay.tip_hash, full.tip_hash);
    assert_eq!(checkpointed.replay.state_root, full.state_root);
    // A valid checkpoint at height 1 causes DiskChainStore::open to load only
    // the tail (blocks > checkpoint_height) into memory. The in-memory chain
    // therefore holds only block 2 (the post-checkpoint tail).
    let tail_metadata: Vec<_> = memory_chain
        .metadata_in_order()
        .into_iter()
        .filter(|m| m.height > checkpoint.height)
        .collect();
    assert_eq!(reopened.chain().metadata_in_order(), tail_metadata);

    let sender = Address([0xA1; 32]);
    let recipient = Address([0x11; 32]);
    assert_eq!(
        checkpointed
            .replay
            .state
            .get_account(&sender)
            .unwrap()
            .balance,
        live_state.get_account(&sender).unwrap().balance
    );
    assert_eq!(
        checkpointed
            .replay
            .state
            .get_account(&recipient)
            .unwrap()
            .balance,
        live_state.get_account(&recipient).unwrap().balance
    );
}

#[test]
fn recover_tip_with_checkpoint_falls_back_on_metadata_mismatch() {
    let dir = TestDir::new("checkpoint-meta");
    let (genesis_state, live_state, _, disk, _) = build_persisted_chain_with_checkpoint(dir.path());
    drop(disk);

    let checkpoint_file = checkpoint_path(dir.path());
    let mut record: TrustedCheckpointRecord = read_cbor(&checkpoint_file).unwrap();
    record.metadata.tip_hash = [0xAA; 32];
    write_cbor(&checkpoint_file, &record).unwrap();

    let reopened =
        DiskChainStore::open(dir.path(), BlockHash([0x11; 32])).expect("reopen must succeed");
    let checkpointed = reopened
        .recover_tip_with_checkpoint(
            &genesis_state,
            FeeParams::default(),
            Default::default(),
            vec![],
        )
        .expect("recovery must succeed");

    assert_eq!(checkpointed.source, RecoverySource::FullReplay);
    assert!(checkpointed.checkpoint.is_none());
    assert_eq!(checkpointed.replay.height, live_state.block_height());
    assert_eq!(
        checkpointed.replay.tip_hash,
        reopened.tip_hash().unwrap().clone()
    );
}

#[test]
fn recover_tip_with_checkpoint_falls_back_on_state_root_mismatch() {
    let dir = TestDir::new("checkpoint-state-root");
    let (genesis_state, live_state, _, disk, _) = build_persisted_chain_with_checkpoint(dir.path());
    drop(disk);

    let checkpoint_file = checkpoint_path(dir.path());
    let mut record: TrustedCheckpointRecord = read_cbor(&checkpoint_file).unwrap();
    record.state.accounts[0].balance += 1;
    write_cbor(&checkpoint_file, &record).unwrap();

    let reopened =
        DiskChainStore::open(dir.path(), BlockHash([0x11; 32])).expect("reopen must succeed");
    let checkpointed = reopened
        .recover_tip_with_checkpoint(
            &genesis_state,
            FeeParams::default(),
            Default::default(),
            vec![],
        )
        .expect("recovery must succeed");

    assert_eq!(checkpointed.source, RecoverySource::FullReplay);
    assert!(checkpointed.checkpoint.is_none());
    assert_eq!(checkpointed.replay.height, live_state.block_height());
    assert_eq!(
        checkpointed.replay.tip_hash,
        reopened.tip_hash().unwrap().clone()
    );
}

#[test]
fn recover_tip_with_checkpoint_falls_back_on_non_canonical_height() {
    let dir = TestDir::new("checkpoint-height");
    let (genesis_state, live_state, _, disk, _) = build_persisted_chain_with_checkpoint(dir.path());
    drop(disk);

    let checkpoint_file = checkpoint_path(dir.path());
    let mut record: TrustedCheckpointRecord = read_cbor(&checkpoint_file).unwrap();
    record.metadata = TrustedCheckpointMetadataRecord {
        height: 99,
        tip_hash: record.metadata.tip_hash,
        state_root: record.metadata.state_root,
    };
    record.state.block_height = 99;
    write_cbor(&checkpoint_file, &record).unwrap();

    let reopened =
        DiskChainStore::open(dir.path(), BlockHash([0x11; 32])).expect("reopen must succeed");
    let checkpointed = reopened
        .recover_tip_with_checkpoint(
            &genesis_state,
            FeeParams::default(),
            Default::default(),
            vec![],
        )
        .expect("recovery must succeed");

    assert_eq!(checkpointed.source, RecoverySource::FullReplay);
    assert!(checkpointed.checkpoint.is_none());
    assert_eq!(checkpointed.replay.height, live_state.block_height());
    assert_eq!(
        checkpointed.replay.tip_hash,
        reopened.tip_hash().unwrap().clone()
    );
}

#[test]
fn open_rejects_staging_residue() {
    let dir = TestDir::new("staging");
    fs::create_dir_all(dir.path().join(STAGING_DIR)).unwrap();
    fs::write(dir.path().join(STAGING_DIR).join("partial.tmp"), b"partial").unwrap();

    let err = DiskChainStore::open(dir.path(), BlockHash([0x11; 32])).unwrap_err();
    assert!(matches!(err, StorageError::IncompleteWriteDetected));
}

#[test]
fn open_rejects_wrong_parent_persisted() {
    let dir = TestDir::new("wrong-parent");
    let (_, _, _, disk) = build_persisted_chain(dir.path());
    drop(disk);

    let block_path = dir.path().join(BLOCKS_DIR).join(block_file_name(2));
    let record: StoredBlockRecord = read_cbor(&block_path).unwrap();
    let mut stored = record_into_stored_block(record, 2).unwrap();
    let old_hash = stored.metadata.block_hash.clone();

    stored.block.header.prev_hash = BlockHash([0xFF; 32]);
    stored.metadata.prev_hash = BlockHash([0xFF; 32]);
    stored.metadata.block_hash = compute_block_hash(&stored.block);
    let new_hash = stored.metadata.block_hash.clone();

    write_cbor(&block_path, &stored_block_into_record(&stored).unwrap()).unwrap();
    fs::remove_file(
        dir.path()
            .join(HASHES_DIR)
            .join(hash_index_file_name(&old_hash)),
    )
    .unwrap();
    write_cbor(
        &dir.path()
            .join(HASHES_DIR)
            .join(hash_index_file_name(&new_hash)),
        &HashIndexRecord { height: 2 },
    )
    .unwrap();
    write_cbor(
        &dir.path().join(TIP_FILE),
        &TipRecord {
            height: 2,
            block_hash: new_hash.0,
        },
    )
    .unwrap();

    let err = DiskChainStore::open(dir.path(), BlockHash([0x11; 32])).unwrap_err();
    assert!(matches!(
        err,
        StorageError::Chain(ChainError::ParentHashMismatch { .. })
    ));
}

#[test]
fn open_rejects_persisted_body_hash_mismatch() {
    let dir = TestDir::new("body-hash");
    let (_, _, _, disk) = build_persisted_chain(dir.path());
    drop(disk);

    let block_path = dir.path().join(BLOCKS_DIR).join(block_file_name(1));
    let mut record: StoredBlockRecord = read_cbor(&block_path).unwrap();
    let mut tx = decode_tx(&record.tx_bodies[0]).unwrap();
    tx.nonce = 99;
    record.tx_bodies[0] = encode_tx(&tx).unwrap();
    write_cbor(&block_path, &record).unwrap();

    let err = DiskChainStore::open(dir.path(), BlockHash([0x11; 32])).unwrap_err();
    assert!(matches!(
        err,
        StorageError::TxBodyHashMismatch {
            height: 1,
            tx_index: 0,
            ..
        }
    ));
}

#[test]
fn open_rejects_hash_index_mismatch() {
    let dir = TestDir::new("hash-index");
    let (_, _, chain, disk) = build_persisted_chain(dir.path());
    let tip_hash = chain.get_metadata_by_height(1).unwrap().block_hash.clone();
    drop(disk);

    let hash_path = dir
        .path()
        .join(HASHES_DIR)
        .join(hash_index_file_name(&tip_hash));
    write_cbor(&hash_path, &HashIndexRecord { height: 99 }).unwrap();

    let err = DiskChainStore::open(dir.path(), BlockHash([0x11; 32])).unwrap_err();
    assert!(matches!(
        err,
        StorageError::HashIndexMismatch {
            expected_height: 1,
            got_height: 99,
            ..
        }
    ));
}

#[test]
fn open_rejects_extra_block_file_beyond_tip() {
    let dir = TestDir::new("extra-block");
    let (_, _, _, disk) = build_persisted_chain(dir.path());
    drop(disk);

    let source = dir.path().join(BLOCKS_DIR).join(block_file_name(1));
    let extra = dir.path().join(BLOCKS_DIR).join(block_file_name(3));
    fs::copy(source, extra).unwrap();

    let err = DiskChainStore::open(dir.path(), BlockHash([0x11; 32])).unwrap_err();
    assert!(matches!(err, StorageError::UnexpectedBlockFile { .. }));
}

#[test]
fn checkpoint_does_not_mask_corrupted_tail_blocks() {
    let dir = TestDir::new("checkpoint-tail");
    let (_, _, _, disk, _) = build_persisted_chain_with_checkpoint(dir.path());
    drop(disk);

    let block_path = dir.path().join(BLOCKS_DIR).join(block_file_name(2));
    let mut record: StoredBlockRecord = read_cbor(&block_path).unwrap();
    let mut tx = decode_tx(&record.tx_bodies[0]).unwrap();
    tx.nonce = 99;
    record.tx_bodies[0] = encode_tx(&tx).unwrap();
    write_cbor(&block_path, &record).unwrap();

    let err = DiskChainStore::open(dir.path(), BlockHash([0x11; 32])).unwrap_err();
    assert!(matches!(
        err,
        StorageError::TxBodyHashMismatch {
            height: 2,
            tx_index: 0,
            ..
        }
    ));
}

// ── ADR-030 / TASK-101: STATE_FORMAT_VERSION fail-fast boot check ─────────

use super::{check_state_format_version, StateSnapshotRecord, STATE_FORMAT_VERSION};

/// Helper: write a minimal `TrustedCheckpointRecord` with the given `version`
/// to `<dir>/checkpoints/trusted-checkpoint.cbor`.
fn write_versioned_checkpoint(dir: &Path, version: u16) {
    let checkpoints_dir = dir.join(CHECKPOINTS_DIR);
    fs::create_dir_all(&checkpoints_dir).unwrap();

    let record = TrustedCheckpointRecord {
        version,
        metadata: TrustedCheckpointMetadataRecord {
            height: 0,
            tip_hash: [0u8; 32],
            state_root: [0u8; 32],
        },
        state: StateSnapshotRecord {
            block_height: 0,
            accounts: vec![],
            attestations: vec![],
            governance_receipts: vec![],
            alg_registry: vec![],
            validators: vec![],
            fee_market_base_fee: 0,
            fee_market_block_gas_limit: 0,
            fee_market_burn_rate_bps: 0,
            pending_proposals: vec![],
            pending_upgrades: vec![],
        },
    };
    write_cbor(&checkpoints_dir.join(CHECKPOINT_FILE), &record).unwrap();
}

#[test]
fn state_format_version_current_is_ok() {
    assert!(
        check_state_format_version(STATE_FORMAT_VERSION).is_ok(),
        "current STATE_FORMAT_VERSION must pass the check"
    );
}

#[test]
fn state_format_version_upgrade_required_on_older_disk() {
    // Simulate a disk checkpoint written by an older binary (version 0).
    let err = check_state_format_version(0).unwrap_err();
    assert!(
        matches!(
            err,
            StorageError::StateFormatUpgradeRequired {
                disk_version: 0,
                binary_version: v
            } if v == STATE_FORMAT_VERSION
        ),
        "expected StateFormatUpgradeRequired, got: {err}"
    );
}

#[test]
fn state_format_version_binary_too_old_on_newer_disk() {
    // Simulate a disk checkpoint written by a newer binary (version = current + 1).
    let newer = STATE_FORMAT_VERSION + 1;
    let err = check_state_format_version(newer).unwrap_err();
    assert!(
        matches!(
            err,
            StorageError::BinaryTooOld {
                disk_version: v,
                binary_version: bv
            } if v == newer && bv == STATE_FORMAT_VERSION
        ),
        "expected BinaryTooOld, got: {err}"
    );
}

#[test]
fn disk_store_open_rejects_old_checkpoint_version() {
    // Build a minimal store directory, write a checkpoint with version = 0.
    let dir = TestDir::new("sfv-old");
    let anchor = BlockHash([0xAAu8; 32]);

    // Write the minimal directory structure so DiskChainStore::open can proceed
    // far enough to read the checkpoint.  We only need the required directories.
    for sub in &[BLOCKS_DIR, HASHES_DIR, STAGING_DIR, CHECKPOINTS_DIR] {
        fs::create_dir_all(dir.path().join(sub)).unwrap();
    }
    // Write the tip file (empty chain) and the old-version checkpoint.
    write_cbor(
        &dir.path().join(TIP_FILE),
        &TipRecord {
            height: 0,
            block_hash: [0u8; 32],
        },
    )
    .unwrap();
    write_versioned_checkpoint(dir.path(), 0);

    let err = DiskChainStore::open(dir.path(), anchor).unwrap_err();
    assert!(
        matches!(err, StorageError::StateFormatUpgradeRequired { .. }),
        "open must fail with StateFormatUpgradeRequired for an old checkpoint; got: {err}"
    );
}

#[test]
fn disk_store_open_rejects_newer_checkpoint_version() {
    let dir = TestDir::new("sfv-new");
    let anchor = BlockHash([0xBBu8; 32]);

    for sub in &[BLOCKS_DIR, HASHES_DIR, STAGING_DIR, CHECKPOINTS_DIR] {
        fs::create_dir_all(dir.path().join(sub)).unwrap();
    }
    write_cbor(
        &dir.path().join(TIP_FILE),
        &TipRecord {
            height: 0,
            block_hash: [0u8; 32],
        },
    )
    .unwrap();
    write_versioned_checkpoint(dir.path(), STATE_FORMAT_VERSION + 1);

    let err = DiskChainStore::open(dir.path(), anchor).unwrap_err();
    assert!(
        matches!(err, StorageError::BinaryTooOld { .. }),
        "open must fail with BinaryTooOld for a newer checkpoint; got: {err}"
    );
}
