// SPDX-License-Identifier: BUSL-1.1
//! ADR-054 §Stage 4 — end-to-end reception-pipeline integration test.
//!
//! This test reproduces the 2026-04-25 follower-1 incident shape and
//! verifies that the new pipeline recovers cleanly:
//!
//! 1. Build a synthetic chain that has block H committed (variant A).
//! 2. Construct variant B of H with the same `prev_hash`/`state_root`/
//!    `tx_root` but a shifted timestamp — state-equivalent sibling.
//! 3. Construct child H+1 with `prev_hash = block_hash(B)` (pointing
//!    at the canonical variant the rest of the network has).
//! 4. The receiver has variant A as its local canonical at H.
//! 5. Use `classify_incoming_block` to drive the dispatch decisions:
//!    - H+1 first arrives → classified `OrphanFutureChild` (parent
//!      mismatch). The orchestration would buffer it in
//!      `BlockTreeCache` and dispatch a by-hash fetch for B.
//!    - B arrives → classified `SiblingAtTip { local: A }`.
//!    - State-equivalent → atomic swap via
//!      `replace_canonical_at_height`. Local tip is now B.
//!    - H+1 re-classifies as `LinkAtTip`. Append succeeds.
//!
//! The test covers the storage-side state transitions (RocksDB
//! WriteBatch + siblings CF + tip update). It does NOT exercise the
//! libp2p plumbing — that path is unit-tested in pqcd via the
//! `handle_inbound_block_fetch_by_hash_response` flow and would
//! require a real two-node test harness.

use std::{
    env, fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use pqc_consensus::{
    block_tree_cache::BlockTreeCache, chain::StoredBlock, classify_incoming_block,
    compute_block_hash, BlockReceptionClass, RocksDbChainStore,
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

struct TempDir(PathBuf);
impl TempDir {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "adr054-reception-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn signer_account(addr: Address, balance: u128) -> Account {
    Account {
        address: addr,
        balance,
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

fn transfer_tx(sender: Address, recipient: Address, nonce: u64) -> Transaction {
    let mut payload = Vec::new();
    ciborium::into_writer(
        &ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Integer(1u64.into()),
                ciborium::value::Value::Bytes(recipient.0.to_vec()),
            ),
            (
                ciborium::value::Value::Integer(2u64.into()),
                ciborium::value::Value::Integer(100u64.into()),
            ),
        ]),
        &mut payload,
    )
    .unwrap();
    Transaction {
        tx_version: 1,
        chain_id: Vec::new(),
        msg_type: MsgType::TokenTransfer,
        sender,
        nonce,
        fee: 100,
        fee_tip: 0,
        gas_limit: 100_000,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0xAB; 3_309],
    }
}

fn admit_tx(pool: &mut Mempool, store: &StateStore, tx: &Transaction) {
    let raw = encode_tx(tx).unwrap();
    try_admit(pool, raw, store, &StubVerifier, &FeeParams::default()).unwrap();
}

fn make_proposer() -> pqc_consensus::LocalProposer {
    pqc_consensus::LocalProposer::new(
        [0x99; 32],
        pqc_consensus::LocalProposerConfig {
            assembly: pqc_consensus::AssemblyConfig::default(),
            initial_prev_hash: BlockHash([0x11; 32]),
        },
    )
}

/// Append one synthetic block at height 1 with a stub commit signature.
fn build_chain_with_block_h1(dir: &TempDir) -> (RocksDbChainStore, StoredBlock) {
    let mut store = RocksDbChainStore::open_no_wal(&dir.0, BlockHash([0x11; 32])).unwrap();
    let sender = Address([0xA1; 32]);
    let recipient = Address([0x22; 32]);
    let mut state = StateStore::new();
    state.insert_account(signer_account(sender.clone(), 10_000));
    let mut pool = Mempool::new();
    let mut proposer = make_proposer();
    admit_tx(&mut pool, &state, &transfer_tx(sender, recipient, 0));
    let mut result = proposer
        .run_once(&mut state, &mut pool, 1_710_000_000)
        .unwrap();
    // Stub commit signature so the on-startup audit doesn't refuse it.
    result.block.commit_signatures.push(CommitSig {
        validator_address: vec![0u8; 32],
        sig_alg_id: AlgId::MlDsa65,
        round: 0,
        signature: vec![0u8; 8],
    });
    store.append_block_trusted(&result).unwrap();
    let stored = store.read_stored_block_at_height(1).unwrap().unwrap();
    (store, stored)
}

/// Re-derive a state-equivalent sibling with a shifted timestamp.
fn shift_timestamp_sibling(stored: &StoredBlock, delta_ns: u64) -> StoredBlock {
    let mut block = stored.block.clone();
    block.header.timestamp = block.header.timestamp.saturating_add(delta_ns);
    let block_hash = compute_block_hash(&block);
    let mut metadata = stored.metadata.clone();
    metadata.timestamp = block.header.timestamp;
    metadata.block_hash = block_hash;
    StoredBlock {
        block,
        metadata,
        included_transactions: stored.included_transactions.clone(),
    }
}

/// Construct a synthetic child H+1 whose `prev_hash` points to a
/// specific variant of the parent. The body is meaningless — we only
/// exercise the classifier + storage layer here.
fn make_orphan_child(parent_hash: BlockHash, height: u64) -> StoredBlock {
    use pqc_types::block::{empty_extension_root, Block, BlockHeader, HEADER_VERSION_V1};
    let header = BlockHeader {
        header_version: HEADER_VERSION_V1,
        height,
        prev_hash: parent_hash,
        state_root: BlockHash([0xAA; 32]),
        tx_root: BlockHash([0xBB; 32]),
        timestamp: 1_710_000_005,
        proposer: vec![0u8; 32],
        extension_root: empty_extension_root(),
    };
    let block = Block {
        header,
        tx_hashes: Vec::new(),
        commit_signatures: vec![CommitSig {
            validator_address: vec![0u8; 32],
            sig_alg_id: AlgId::MlDsa65,
            round: 0,
            signature: vec![0u8; 8],
        }],
    };
    let block_hash = compute_block_hash(&block);
    let metadata = pqc_consensus::BlockMetadata {
        block_hash,
        height,
        prev_hash: block.header.prev_hash.clone(),
        state_root: block.header.state_root.clone(),
        tx_root: block.header.tx_root.clone(),
        timestamp: block.header.timestamp,
        bytes_used: 0,
        included_count: 0,
        deferred_count: 0,
        skipped_count: 0,
        vc_budget_consumed: 0,
    };
    StoredBlock {
        block,
        metadata,
        included_transactions: Vec::new(),
    }
}

/// End-to-end scenario: receiver has variant A at H=1; canonical
/// network has variant B at H=1 + child H=2 pointing at B. The
/// receiver must classify, sibling-swap, and link the child cleanly.
#[test]
fn reproduces_2026_04_25_follower_divergence_and_recovers() {
    let dir = TempDir::new("incident-repro");
    let (mut store, variant_a) = build_chain_with_block_h1(&dir);
    assert_eq!(store.tip_hash(), Some(&variant_a.metadata.block_hash));

    // Canonical sibling B at H=1 — same body, +2 s timestamp.
    let variant_b = shift_timestamp_sibling(&variant_a, 2_000_000_000);
    assert_ne!(variant_a.metadata.block_hash, variant_b.metadata.block_hash);
    // Child H=2 with prev_hash pointing at canonical B.
    let child = make_orphan_child(variant_b.metadata.block_hash.clone(), 2);

    // ── Step 1: H+1 arrives first. Classifier sees prev_hash != local
    // tip (which is A); orphan path. ───────────────────────────────────
    let local_height = store.height();
    let local_tip_meta = store
        .chain()
        .tip_hash()
        .and_then(|h| store.chain().get_metadata_by_hash(h))
        .cloned();
    let class = classify_incoming_block(&child, local_height, local_tip_meta.as_ref(), |h| {
        if h == 2 {
            None
        } else {
            store.chain().get_metadata_by_height(h).cloned()
        }
    })
    .unwrap();
    assert_eq!(class, BlockReceptionClass::OrphanFutureChild);

    // Buffer the orphan in the cache (in production this happens at
    // the same call site that receives the OrphanFutureChild
    // classification).
    let mut cache = BlockTreeCache::new(64, std::time::Duration::from_secs(60));
    cache.insert(child.clone());

    // ── Step 2: B arrives (response to a by-hash fetch the receiver
    // would have dispatched on the orphan classification above). ────
    let local_height = store.height();
    let local_tip_meta = store
        .chain()
        .tip_hash()
        .and_then(|h| store.chain().get_metadata_by_hash(h))
        .cloned();
    let class_b = classify_incoming_block(&variant_b, local_height, local_tip_meta.as_ref(), |h| {
        store.chain().get_metadata_by_height(h).cloned()
    })
    .unwrap();
    match class_b {
        BlockReceptionClass::SiblingAtTip { local } => {
            assert_eq!(local.block_hash, variant_a.metadata.block_hash);
        }
        other => panic!("expected SiblingAtTip, got {other:?}"),
    }

    // State-equivalence holds → swap is permitted. Drive the storage
    // primitive directly (the pqcd dispatcher does the same call).
    let displaced = store
        .replace_canonical_at_height(variant_b.clone(), None)
        .expect("sibling swap must succeed");
    assert_eq!(displaced.metadata.block_hash, variant_a.metadata.block_hash);
    assert_eq!(store.tip_hash(), Some(&variant_b.metadata.block_hash));

    // ── Step 3: drain orphan cache children of the just-imported
    // parent. The single child re-classifies as LinkAtTip. ─────────
    let drained: Vec<_> = cache
        .children_of(&variant_b.metadata.block_hash)
        .into_iter()
        .cloned()
        .collect();
    assert_eq!(drained.len(), 1);
    let resumed = &drained[0];
    let local_height = store.height();
    let local_tip_meta = store
        .chain()
        .tip_hash()
        .and_then(|h| store.chain().get_metadata_by_hash(h))
        .cloned();
    let class_child =
        classify_incoming_block(resumed, local_height, local_tip_meta.as_ref(), |h| {
            store.chain().get_metadata_by_height(h).cloned()
        })
        .unwrap();
    assert_eq!(class_child, BlockReceptionClass::LinkAtTip);

    // The replaced variant A is still discoverable via the siblings CF
    // for forensic audits — closes ADR-054 §Stage 4 archival contract.
    let archived = store
        .read_sibling_by_hash(&variant_a.metadata.block_hash)
        .unwrap()
        .expect("displaced variant A archived to siblings CF");
    assert_eq!(archived.metadata.block_hash, variant_a.metadata.block_hash);

    // The on-startup audit accepts the post-recovery chain (every
    // block has at least one commit signature).
    store.verify_quick_finality_invariants().unwrap();
}

/// Negative scenario: a state-divergent sibling arriving at the tip
/// MUST be rejected by `replace_canonical_at_height` without mutating
/// the store. (The dispatch layer in pqcd then submits equivocation
/// evidence; this test only validates the storage-side guard.)
#[test]
fn state_divergent_sibling_rejected_atomically_at_storage_layer() {
    use pqc_consensus::{ChainError, StorageError};
    let dir = TempDir::new("divergent-rejected");
    let (mut store, variant_a) = build_chain_with_block_h1(&dir);
    let original_tip = variant_a.metadata.block_hash.clone();

    // Synthesize a divergent variant — different state_root.
    let mut block = variant_a.block.clone();
    block.header.state_root = BlockHash([0xCC; 32]);
    block.header.timestamp += 2_000_000_000;
    let new_hash = compute_block_hash(&block);
    let mut metadata = variant_a.metadata.clone();
    metadata.state_root = BlockHash([0xCC; 32]);
    metadata.timestamp = block.header.timestamp;
    metadata.block_hash = new_hash;
    let divergent = StoredBlock {
        block,
        metadata,
        included_transactions: variant_a.included_transactions.clone(),
    };

    let err = store
        .replace_canonical_at_height(divergent, None)
        .unwrap_err();
    match err {
        StorageError::Chain(ChainError::SiblingStateDivergence { field, .. }) => {
            assert_eq!(field, "state_root");
        }
        other => panic!("expected state_root divergence, got {other:?}"),
    }
    // Tip unchanged.
    assert_eq!(store.tip_hash(), Some(&original_tip));
}
