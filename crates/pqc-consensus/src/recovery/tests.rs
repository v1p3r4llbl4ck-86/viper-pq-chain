// SPDX-License-Identifier: BUSL-1.1
//! Tests for `recovery`.
//!
//! Extracted from `recovery.rs` 2026-05-10. `use super::*;`
//! brings every private item from the parent module into scope.

use pqc_crypto::AlgId;
use pqc_crypto::Lifecycle;
use pqc_mempool::Mempool;
use pqc_state::StateStore;
use pqc_tx::validate::FeeParams;
use pqc_types::{account::Address, block::BlockHash};

use crate::test_support::{
    admit, attestation_create_tx, cbor_map, signer_account, transfer_tx, CborVal,
};
use crate::{AssemblyConfig, ChainStore, LocalProposer, LocalProposerConfig};

use super::{recover_tip, replay_blocks_from_genesis, verify_chain_consistency, ReplayError};

fn proposer() -> LocalProposer {
    LocalProposer::new(
        [0x99; 32],
        LocalProposerConfig {
            assembly: AssemblyConfig::default(),
            initial_prev_hash: BlockHash([0x11; 32]),
        },
    )
}

fn build_chain() -> (StateStore, ChainStore, StateStore) {
    let sender = Address([0xA1; 32]);
    let recipient = Address([0x11; 32]);

    let mut genesis_state = StateStore::new();
    genesis_state.insert_account(signer_account(sender.clone(), 10_000, 0, AlgId::MlDsa65));

    let mut live_state = genesis_state.clone();
    let mut pool = Mempool::new();
    let mut proposer = proposer();
    let mut chain = ChainStore::new(BlockHash([0x11; 32]));

    let first = transfer_tx(
        sender.clone(),
        recipient.clone(),
        0,
        100,
        0,
        0x01,
        AlgId::MlDsa65,
    );
    admit(&mut pool, &live_state, &first);
    let result_1 = proposer
        .run_once(&mut live_state, &mut pool, 1_710_000_000)
        .expect("first run_once must succeed");
    chain
        .append_block(&result_1)
        .expect("first append must succeed");

    let second = transfer_tx(sender, recipient, 1, 100, 0, 0x02, AlgId::MlDsa65);
    admit(&mut pool, &live_state, &second);
    let result_2 = proposer
        .run_once(&mut live_state, &mut pool, 1_710_000_001)
        .expect("second run_once must succeed");
    chain
        .append_block(&result_2)
        .expect("second append must succeed");

    (genesis_state, chain, live_state)
}

fn governance_registry_update_tx(
    sender: Address,
    nonce: u64,
    signature_fill: u8,
) -> pqc_types::transaction::Transaction {
    let payload = cbor_map(vec![
        (1, CborVal::Int(1)),
        (2, CborVal::Int(AlgId::MlDsa65.as_u16() as u64)),
        (3, CborVal::Int(1)),
        (4, CborVal::Int(500)),
        (6, CborVal::Bytes(vec![0xAB; 32])),
        (100, CborVal::Int(1)),
        (101, CborVal::Int(1)),
        (102, CborVal::Int(1)),
    ]);

    pqc_types::transaction::Transaction {
        tx_version: 1,
        chain_id: Vec::new(),
        msg_type: pqc_types::transaction::MsgType::GovernanceProposal,
        sender,
        nonce,
        fee: 500,
        fee_tip: 0,
        gas_limit: 100_000,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![signature_fill; 3_309],
    }
}

#[test]
fn replay_from_genesis_reconstructs_same_tip_and_state_root() {
    let (genesis_state, chain, live_state) = build_chain();

    let replay = recover_tip(
        &chain,
        &genesis_state,
        FeeParams::default(),
        Default::default(),
        vec![],
    )
    .expect("recovery must succeed");

    assert_eq!(replay.height, live_state.block_height());
    assert_eq!(replay.tip_hash, chain.tip_hash().unwrap().clone());
    assert_eq!(replay.state_root, chain.tip().unwrap().metadata.state_root);

    let sender = Address([0xA1; 32]);
    let recipient = Address([0x11; 32]);
    assert_eq!(
        replay.state.get_account(&sender).unwrap().balance,
        live_state.get_account(&sender).unwrap().balance
    );
    assert_eq!(
        replay.state.get_account(&recipient).unwrap().balance,
        live_state.get_account(&recipient).unwrap().balance
    );
}

#[test]
fn replay_same_sequence_twice_is_identical() {
    let (genesis_state, chain, _) = build_chain();

    let replay_a = recover_tip(
        &chain,
        &genesis_state,
        FeeParams::default(),
        Default::default(),
        vec![],
    )
    .expect("first recovery must succeed");
    let replay_b = recover_tip(
        &chain,
        &genesis_state,
        FeeParams::default(),
        Default::default(),
        vec![],
    )
    .expect("second recovery must succeed");

    assert_eq!(replay_a.height, replay_b.height);
    assert_eq!(replay_a.tip_hash, replay_b.tip_hash);
    assert_eq!(replay_a.state_root, replay_b.state_root);

    let sender = Address([0xA1; 32]);
    assert_eq!(
        replay_a.state.get_account(&sender).unwrap().balance,
        replay_b.state.get_account(&sender).unwrap().balance
    );
}

#[test]
fn replay_rejects_corrupted_block_body() {
    let (genesis_state, chain, _) = build_chain();
    let mut blocks: Vec<_> = chain.blocks_in_order().into_iter().cloned().collect();
    blocks[0].included_transactions[0].nonce = 99;

    let err = replay_blocks_from_genesis(
        &genesis_state,
        chain.anchor_prev_hash(),
        &blocks,
        FeeParams::default(),
        Default::default(),
        vec![],
    )
    .unwrap_err();

    assert!(matches!(
        err,
        ReplayError::TxHashMismatch {
            height: 1,
            tx_index: 0,
            ..
        }
    ));
}

#[test]
fn replay_rejects_gap_in_height_sequence() {
    let (genesis_state, chain, _) = build_chain();
    let mut blocks: Vec<_> = chain.blocks_in_order().into_iter().cloned().collect();
    blocks[1].block.header.height = 3;
    blocks[1].metadata.height = 3;

    let err = replay_blocks_from_genesis(
        &genesis_state,
        chain.anchor_prev_hash(),
        &blocks,
        FeeParams::default(),
        Default::default(),
        vec![],
    )
    .unwrap_err();

    assert!(matches!(
        err,
        ReplayError::HeightGap {
            expected: 2,
            got: 3
        }
    ));
}

#[test]
fn replay_reconstructs_attestation_state_from_history() {
    let sender = Address([0xA1; 32]);
    let subject = [0x77; 32];

    let mut genesis_state = StateStore::new();
    genesis_state.insert_account(signer_account(sender.clone(), 10_000, 0, AlgId::MlDsa65));

    let mut live_state = genesis_state.clone();
    let mut pool = Mempool::new();
    let mut proposer = proposer();
    let mut chain = ChainStore::new(BlockHash([0x11; 32]));

    let tx = attestation_create_tx(sender.clone(), 0, 100, 0x01, subject, 0x0002);
    admit(&mut pool, &live_state, &tx);
    let result = proposer
        .run_once(&mut live_state, &mut pool, 1_710_000_000)
        .expect("run_once must succeed");
    chain.append_block(&result).expect("append must succeed");

    let replay = recover_tip(
        &chain,
        &genesis_state,
        FeeParams::default(),
        Default::default(),
        vec![],
    )
    .expect("recovery must succeed");

    let expected_id = result.included[0].clone();
    let attestation = replay
        .state
        .get_attestation(&pqc_types::attestation::AttestationId(expected_id.0))
        .expect("replayed state must contain attestation");

    assert_eq!(attestation.subject, subject);
    assert_eq!(attestation.anchor_height, 1);
    assert_eq!(replay.state_root, chain.tip().unwrap().metadata.state_root);
    assert_eq!(replay.tip_hash, chain.tip_hash().unwrap().clone());
}

#[test]
fn replay_reconstructs_governance_registry_update_and_receipt() {
    // TASK-100: GovernanceProposal now registers a PendingProposal in Voting
    // status instead of executing immediately.  The registry is NOT modified
    // at proposal-inclusion time; it is only modified after the voting period
    // closes and `process_governance_tallies` finds quorum.
    //
    // This test verifies that after replay:
    // - the proposal is present as a pending proposal in Voting status
    // - the registry was NOT changed (no immediate execution)
    // - the state root derived from replay matches the live-assembled root
    let sender = Address([0xA1; 32]);

    let mut genesis_state = StateStore::new();
    genesis_state.insert_account(signer_account(sender.clone(), 10_000, 0, AlgId::MlDsa65));

    let mut live_state = genesis_state.clone();
    let mut pool = Mempool::new();
    let mut proposer = proposer();
    let mut chain = ChainStore::new(BlockHash([0x11; 32]));

    let tx = governance_registry_update_tx(sender.clone(), 0, 0x33);
    admit(&mut pool, &live_state, &tx);
    let result = proposer
        .run_once(&mut live_state, &mut pool, 1_710_000_000)
        .expect("run_once must succeed");
    chain.append_block(&result).expect("append must succeed");

    let replay = recover_tip(
        &chain,
        &genesis_state,
        FeeParams::default(),
        Default::default(),
        vec![],
    )
    .expect("recovery must succeed");

    // Registry must NOT be updated — the proposal is still in Voting status.
    let entry = replay
        .state
        .alg_entry(AlgId::MlDsa65)
        .expect("registry entry must exist");
    assert_eq!(
        entry.lifecycle,
        Lifecycle::Active,
        "lifecycle must remain Active — proposal is in Voting, not yet executed"
    );

    // A pending proposal must exist in Voting status.
    let proposals = replay.state.pending_proposals_in_order();
    assert_eq!(
        proposals.len(),
        1,
        "one pending proposal must exist after replay"
    );
    assert_eq!(
        proposals[0].status,
        pqc_types::governance::ProposalStatus::Voting,
        "proposal must be in Voting status"
    );
    assert_eq!(proposals[0].proposer, sender);

    // State root derived from replay must match the live-assembled root.
    assert_eq!(replay.state_root, chain.tip().unwrap().metadata.state_root);
    assert_eq!(replay.tip_hash, chain.tip_hash().unwrap().clone());
}

#[test]
fn verify_chain_consistency_accepts_valid_active_chain() {
    let (_, chain, _) = build_chain();
    verify_chain_consistency(&chain).expect("valid chain must verify");
}
