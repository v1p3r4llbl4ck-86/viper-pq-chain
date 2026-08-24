// SPDX-License-Identifier: BUSL-1.1
//! Token-transfer pin tests — extracted from `tests.rs` 2026-05-10.
//!
//! Exercises the full validate → apply path for token_transfer plus
//! the related attestation_create / attestation_revoke flows that
//! shared this section in the original layout. `use super::*;`
//! pulls in every helper, type, constant from the sibling
//! `tests.rs` (now the parent module) — same recursive-glob pattern
//! used across other splits in the workspace.

use super::*;

// ── token_transfer tests ──────────────────────────────────────────────────────

#[test]
fn attestation_create_records_active_attestation_and_advances_nonce() {
    let attester_addr = Address([0xDD; 32]);
    let subject = [0x11; 32];
    let content_hash = [0x22; 32];
    let schema_id = [0x33; 32];
    let metadata_hash = [0x44; 32];

    let payload = attestation_payload(
        subject,
        0x0002,
        content_hash,
        schema_id,
        Some(metadata_hash),
        Some(25),
    );

    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::AttestationCreate,
        sender: attester_addr.clone(),
        nonce: 0,
        fee: 500,
        fee_tip: 0,
        gas_limit: GAS_ATTESTATION_CREATE,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let mut store = StateStore::new();
    let mut attester = creator_account(attester_addr.clone(), 0);
    attester.balance = 10_000;
    store.insert_account(attester);

    let sender = store.get_account(&attester_addr).unwrap().clone();
    let raw = encode_tx(&tx).unwrap();
    let verifier = StubVerifier;
    let ctx = ValidationContext {
        chain_id: CHAIN_ID,
        fork_digest: &TEST_FORK_DIGEST,
        current_height: CURRENT_HEIGHT,
        sender_account: Some(&sender),
        fee_params: FeeParams::default(),
        verifier: &verifier,
        alg_lifecycle: &active_lifecycle,
        alg_min_fee: &zero_min_fee,
    };

    validate_tx(&tx, &raw, &ctx).expect("validation must pass");
    let result = apply_tx(
        &mut store,
        &tx,
        ExecutionContext {
            tx_bytes_len: raw.len(),
            fee_params: FeeParams {
                base_fee: 100,
                ..FeeParams::default()
            },
        },
    )
    .expect("apply must succeed");

    assert_eq!(result.status, ExecutionStatus::Applied);
    assert_eq!(result.gas_used, GAS_ATTESTATION_CREATE);
    assert_eq!(result.fee_charged, 100);
    assert_eq!(result.fee_refund, 400);

    let attestation_id = AttestationId(compute_tx_hash(&raw));
    let attestation = store
        .get_attestation(&attestation_id)
        .expect("attestation must exist after apply");

    assert_eq!(attestation.attester, attester_addr);
    assert_eq!(attestation.subject, subject);
    assert_eq!(attestation.attestation_type, 0x0002);
    assert_eq!(attestation.content_hash, content_hash);
    assert_eq!(attestation.schema_id, schema_id);
    assert_eq!(attestation.metadata_hash, Some(metadata_hash));
    assert_eq!(attestation.anchor_height, 1);
    assert_eq!(attestation.expires_at_height, Some(25));
    assert_eq!(attestation.status, AttestationStatus::Active);
    assert!(attestation.revocation.is_none());

    let attester_after = store.get_account(&attester_addr).unwrap();
    assert_eq!(attester_after.balance, 9_900);
    assert_eq!(attester_after.nonce, 1);
}

#[test]
fn attestation_create_rejects_expiry_at_or_before_anchor_height() {
    let attester_addr = Address([0xDD; 32]);
    let payload = attestation_payload([0x11; 32], 0x0002, [0x22; 32], [0x33; 32], None, Some(1));

    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::AttestationCreate,
        sender: attester_addr.clone(),
        nonce: 0,
        fee: 0,
        fee_tip: 0,
        gas_limit: GAS_ATTESTATION_CREATE,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let mut store = StateStore::new();
    store.insert_account(creator_account(attester_addr, 0));

    let err = apply_tx(&mut store, &tx, exec_ctx(&tx)).unwrap_err();
    assert!(
        matches!(err, crate::error::ApplyError::InvalidExpiry),
        "got: {err}"
    );
}

#[test]
fn key_add_registers_pending_key_and_charges_fee() {
    let sender_addr = Address([0xAA; 32]);
    let payload = key_add_payload(AlgId::MlDsa44, vec![0x11; 1_312], 2, 2, allowed_tx::ALL);

    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::KeyAdd,
        sender: sender_addr.clone(),
        nonce: 0,
        fee: 500,
        fee_tip: 0,
        gas_limit: GAS_KEY_ADD,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let mut store = StateStore::new();
    let mut sender = creator_account(sender_addr.clone(), 0);
    sender.balance = 10_000;
    store.insert_account(sender);

    let signer = store.get_account(&sender_addr).unwrap().clone();
    let raw = encode_tx(&tx).unwrap();
    let verifier = StubVerifier;
    let ctx = ValidationContext {
        chain_id: CHAIN_ID,
        fork_digest: &TEST_FORK_DIGEST,
        current_height: CURRENT_HEIGHT,
        sender_account: Some(&signer),
        fee_params: FeeParams::default(),
        verifier: &verifier,
        alg_lifecycle: &active_lifecycle,
        alg_min_fee: &zero_min_fee,
    };

    validate_tx(&tx, &raw, &ctx).expect("validation must pass");
    let result = apply_tx(
        &mut store,
        &tx,
        ExecutionContext {
            tx_bytes_len: raw.len(),
            fee_params: FeeParams {
                base_fee: 100,
                ..FeeParams::default()
            },
        },
    )
    .expect("apply must succeed");

    assert_eq!(result.status, ExecutionStatus::Applied);
    assert_eq!(result.gas_used, GAS_KEY_ADD);
    assert_eq!(result.fee_charged, 100);
    assert_eq!(result.fee_refund, 400);

    let sender_after = store.get_account(&sender_addr).unwrap();
    assert_eq!(sender_after.nonce, 1);
    assert_eq!(sender_after.balance, 9_900);
    assert_eq!(sender_after.keys.0.len(), 2);
    assert_eq!(sender_after.keys.0[1].alg_id, AlgId::MlDsa44);
    assert_eq!(sender_after.keys.0[1].key_version, 2);
    assert_eq!(sender_after.keys.0[1].status, KeyStatus::Pending);
    assert_eq!(sender_after.keys.0[1].valid_from_height, 2);
}

#[test]
fn key_add_rejects_duplicate_key_version() {
    let sender_addr = Address([0xAA; 32]);
    let payload = key_add_payload(AlgId::MlDsa44, vec![0x11; 1_312], 1, 1, allowed_tx::ALL);

    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::KeyAdd,
        sender: sender_addr.clone(),
        nonce: 0,
        fee: 0,
        fee_tip: 0,
        gas_limit: GAS_KEY_ADD,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let mut store = StateStore::new();
    store.insert_account(creator_account(sender_addr, 0));

    let err = apply_tx(&mut store, &tx, exec_ctx(&tx)).unwrap_err();
    assert!(
        matches!(err, crate::error::ApplyError::KeyVersionConflict),
        "got: {err}"
    );
}

#[test]
fn key_add_rejects_invalid_slh_permissions() {
    let sender_addr = Address([0xAA; 32]);
    let payload = key_add_payload(AlgId::SlhDsaSha2128s, vec![0x11; 32], 2, 1, allowed_tx::ALL);

    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::KeyAdd,
        sender: sender_addr.clone(),
        nonce: 0,
        fee: 0,
        fee_tip: 0,
        gas_limit: GAS_KEY_ADD,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let mut store = StateStore::new();
    store.insert_account(creator_account(sender_addr, 0));

    let err = apply_tx(&mut store, &tx, exec_ctx(&tx)).unwrap_err();
    assert!(
        matches!(err, crate::error::ApplyError::InvalidKeyPermissions),
        "got: {err}"
    );
}

#[test]
fn key_add_rejects_discouraged_algorithm_registration() {
    let sender_addr = Address([0xAA; 32]);
    let payload = key_add_payload(AlgId::MlDsa44, vec![0x11; 1_312], 2, 1, allowed_tx::ALL);

    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::KeyAdd,
        sender: sender_addr.clone(),
        nonce: 0,
        fee: 0,
        fee_tip: 0,
        gas_limit: GAS_KEY_ADD,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let mut store = StateStore::new();
    store.insert_account(creator_account(sender_addr, 0));
    store.alg_entry_mut(AlgId::MlDsa44).unwrap().lifecycle = Lifecycle::Discouraged;

    let err = apply_tx(&mut store, &tx, exec_ctx(&tx)).unwrap_err();
    assert!(
        matches!(err, crate::error::ApplyError::UnsupportedAlgorithm),
        "got: {err}"
    );
}

#[test]
fn key_rotate_atomically_revokes_old_key_and_adds_new_active_key() {
    let sender_addr = Address([0xAA; 32]);
    let payload = key_rotate_payload(AlgId::MlDsa44, vec![0x22; 1_312], 2, 0, allowed_tx::ALL, 1);

    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::KeyRotate,
        sender: sender_addr.clone(),
        nonce: 0,
        fee: 100,
        fee_tip: 0,
        gas_limit: GAS_KEY_ROTATE,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let mut store = StateStore::new();
    let mut sender = creator_account(sender_addr.clone(), 0);
    sender.balance = 10_000;
    store.insert_account(sender);

    let result = apply_tx(&mut store, &tx, exec_ctx(&tx)).expect("rotation must succeed");
    assert_eq!(result.status, ExecutionStatus::Applied);

    let keys = &store.get_account(&sender_addr).unwrap().keys.0;
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0].status, KeyStatus::Revoked);
    assert_eq!(keys[1].status, KeyStatus::Active);
    assert_eq!(keys[1].key_version, 2);
    assert_eq!(keys[1].alg_id, AlgId::MlDsa44);
}

#[test]
fn key_rotate_rejects_pending_replacement_if_it_would_leave_zero_active_keys() {
    let sender_addr = Address([0xAA; 32]);
    let payload = key_rotate_payload(AlgId::MlDsa44, vec![0x22; 1_312], 2, 2, allowed_tx::ALL, 1);

    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::KeyRotate,
        sender: sender_addr.clone(),
        nonce: 0,
        fee: 0,
        fee_tip: 0,
        gas_limit: GAS_KEY_ROTATE,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let mut store = StateStore::new();
    store.insert_account(creator_account(sender_addr, 0));

    let err = apply_tx(&mut store, &tx, exec_ctx(&tx)).unwrap_err();
    assert!(
        matches!(err, crate::error::ApplyError::InsufficientActiveKeys),
        "got: {err}"
    );
}

#[test]
fn key_revoke_revokes_non_signing_key_when_another_active_key_exists() {
    let sender_addr = Address([0xAA; 32]);
    let payload = key_revoke_payload(2);

    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::KeyRevoke,
        sender: sender_addr.clone(),
        nonce: 0,
        fee: 0,
        fee_tip: 0,
        gas_limit: GAS_KEY_REVOKE,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let mut store = StateStore::new();
    let mut sender = creator_account(sender_addr.clone(), 0);
    sender.keys.0.push(active_key(2));
    store.insert_account(sender);

    let result = apply_tx(&mut store, &tx, exec_ctx(&tx)).expect("revoke must succeed");
    assert_eq!(result.status, ExecutionStatus::Applied);

    let keys = &store.get_account(&sender_addr).unwrap().keys.0;
    assert_eq!(keys[0].status, KeyStatus::Active);
    assert_eq!(keys[1].status, KeyStatus::Revoked);
}

#[test]
fn key_revoke_rejects_signer_is_target() {
    let sender_addr = Address([0xAA; 32]);
    let payload = key_revoke_payload(1);

    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::KeyRevoke,
        sender: sender_addr.clone(),
        nonce: 0,
        fee: 0,
        fee_tip: 0,
        gas_limit: GAS_KEY_REVOKE,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let mut store = StateStore::new();
    let mut sender = creator_account(sender_addr.clone(), 0);
    sender.keys.0.push(active_key(2));
    store.insert_account(sender);

    let err = apply_tx(&mut store, &tx, exec_ctx(&tx)).unwrap_err();
    assert!(
        matches!(err, crate::error::ApplyError::SignerIsTarget),
        "got: {err}"
    );
}

#[test]
fn governance_registry_update_discourages_algorithm_and_records_receipt() {
    // TASK-100: GovernanceProposal now creates a PendingProposal in Voting
    // status.  The registry is updated only after the voting period closes
    // and process_governance_tallies finds quorum.
    let sender_addr = Address([0xAA; 32]);
    let payload = governance_registry_update_payload(AlgId::MlDsa65, Some(1), Some(500), 0x6A);

    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::GovernanceProposal,
        sender: sender_addr.clone(),
        nonce: 0,
        fee: 500,
        fee_tip: 0,
        gas_limit: GAS_GOVERNANCE_PROPOSAL,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let mut store = StateStore::new();
    let mut sender = creator_account(sender_addr.clone(), 0);
    sender.balance = 10_000;
    store.insert_account(sender.clone());

    let signer = store.get_account(&sender_addr).unwrap().clone();
    let raw = encode_tx(&tx).unwrap();
    let verifier = StubVerifier;
    let ctx = ValidationContext {
        chain_id: CHAIN_ID,
        fork_digest: &TEST_FORK_DIGEST,
        current_height: CURRENT_HEIGHT,
        sender_account: Some(&signer),
        fee_params: FeeParams::default(),
        verifier: &verifier,
        alg_lifecycle: &active_lifecycle,
        alg_min_fee: &zero_min_fee,
    };

    validate_tx(&tx, &raw, &ctx).expect("governance tx validation must pass");
    let result = apply_tx(&mut store, &tx, exec_ctx(&tx)).expect("apply must succeed");
    assert_eq!(result.status, ExecutionStatus::Applied);

    // Registry must NOT be updated yet — proposal is in Voting status.
    let entry = store.alg_entry(AlgId::MlDsa65).unwrap();
    assert_eq!(
        entry.lifecycle,
        Lifecycle::Active,
        "registry must not change at proposal time"
    );

    // A pending proposal must exist in Voting status.
    let proposals = store.pending_proposals_in_order();
    assert_eq!(proposals.len(), 1, "one pending proposal must exist");
    assert_eq!(proposals[0].status, ProposalStatus::Voting);

    // Register a validator and cast a yes vote to produce quorum.
    let val_addr = Address([0xBBu8; 32]);
    store.insert_account(creator_account(val_addr.clone(), 0));
    store.insert_validator(pqc_types::validator::ValidatorRecord {
        operator: val_addr.clone(),
        node_id: "val-1".into(),
        consensus_alg_id: AlgId::MlDsa65,
        consensus_pk: vec![0xCCu8; 1952],
        self_bond: 0,
        status: pqc_types::validator::ValidatorStatus::Active,
        registered_height: 0,
        tombstoned: false,
    });

    let proposal_id = store.pending_proposals_in_order()[0].proposal_id.0;
    let vote_payload = make_governance_vote_payload(proposal_id, true);
    let vote_tx = make_gov_tx(val_addr.clone(), 0, MsgType::GovernanceVote, vote_payload);
    apply_governance_vote(&mut store, &vote_tx).expect("validator vote must succeed");

    // Tally at height past the deadline (quorum = 1 validator, 1 yes vote → passes).
    let deadline = store.pending_proposals_in_order()[0].voting_deadline;
    process_governance_tallies(&mut store, deadline + 1);

    // Now the registry must be updated.
    let entry = store.alg_entry(AlgId::MlDsa65).unwrap();
    assert_eq!(
        entry.lifecycle,
        Lifecycle::Discouraged,
        "lifecycle must be Discouraged after tally"
    );
    assert_eq!(entry.min_fee, 500, "min_fee must be updated after tally");

    // A receipt must exist.
    let receipt = store
        .get_governance_receipt(&pqc_types::transaction::TxHash(proposal_id))
        .expect("receipt must be recorded after tally");
    assert_eq!(
        receipt.proposal_type,
        GovernanceProposalType::RegistryUpdate
    );
    assert_eq!(receipt.target_alg_id, AlgId::MlDsa65);
    assert_eq!(receipt.lifecycle_before, Lifecycle::Active);
    assert_eq!(receipt.lifecycle_after, Lifecycle::Discouraged);
    assert_eq!(receipt.min_fee_before, 0);
    assert_eq!(receipt.min_fee_after, 500);
}

#[test]
fn discouraged_registry_min_fee_is_enforced_on_followup_transfer() {
    // TASK-100: governance now needs voting + tally before taking effect.
    // We run the full flow (proposal → vote → tally) to get the registry updated,
    // then verify that the min_fee is enforced on a subsequent transfer.
    let sender_addr = Address([0xAA; 32]);
    let governance_payload =
        governance_registry_update_payload(AlgId::MlDsa65, Some(1), Some(500), 0x6B);
    let governance_tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::GovernanceProposal,
        sender: sender_addr.clone(),
        nonce: 0,
        fee: 500,
        fee_tip: 0,
        gas_limit: GAS_GOVERNANCE_PROPOSAL,
        payload: governance_payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let mut store = StateStore::new();
    let mut sender = creator_account(sender_addr.clone(), 0);
    sender.balance = 10_000;
    store.insert_account(sender);

    // Submit the proposal.
    apply_tx(&mut store, &governance_tx, exec_ctx(&governance_tx)).expect("governance apply");

    // Add a validator and vote yes to reach quorum (1 validator = quorum of 1).
    let val_addr = Address([0xCCu8; 32]);
    store.insert_account(creator_account(val_addr.clone(), 0));
    store.insert_validator(pqc_types::validator::ValidatorRecord {
        operator: val_addr.clone(),
        node_id: "val-disc".into(),
        consensus_alg_id: AlgId::MlDsa65,
        consensus_pk: vec![0xDDu8; 1952],
        self_bond: 0,
        status: pqc_types::validator::ValidatorStatus::Active,
        registered_height: 0,
        tombstoned: false,
    });
    let proposal_id = store.pending_proposals_in_order()[0].proposal_id.0;
    let vote_payload = make_governance_vote_payload(proposal_id, true);
    let vote_tx = make_gov_tx(val_addr.clone(), 0, MsgType::GovernanceVote, vote_payload);
    apply_governance_vote(&mut store, &vote_tx).expect("validator vote must succeed");

    // Tally to execute the proposal.
    let deadline = store.pending_proposals_in_order()[0].voting_deadline;
    process_governance_tallies(&mut store, deadline + 1);

    // Verify the registry is now updated.
    assert_eq!(
        store.alg_entry(AlgId::MlDsa65).unwrap().min_fee,
        500,
        "min_fee must be 500 after tally"
    );

    let transfer = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::TokenTransfer,
        sender: sender_addr.clone(),
        nonce: 1,
        fee: 100,
        fee_tip: 0,
        gas_limit: GAS_TOKEN_TRANSFER,
        payload: transfer_payload(&Address([0xBB; 32]), 50),
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let signer = store.get_account(&sender_addr).unwrap().clone();
    let raw = encode_tx(&transfer).unwrap();
    let verifier = StubVerifier;
    let ctx = ValidationContext {
        chain_id: CHAIN_ID,
        fork_digest: &TEST_FORK_DIGEST,
        current_height: CURRENT_HEIGHT,
        sender_account: Some(&signer),
        fee_params: FeeParams {
            sigverify_fee_v_b: 50,
            ..FeeParams::default()
        },
        verifier: &verifier,
        alg_lifecycle: &|alg_id| store.alg_entry(alg_id).map(|entry| entry.lifecycle),
        alg_min_fee: &|alg_id| store.alg_min_fee(alg_id),
    };

    let err = validate_tx(&transfer, &raw, &ctx).unwrap_err();
    assert!(
        matches!(
            err,
            pqc_tx::TxError::FeeInsufficient {
                paid: 100,
                required: 500,
                sigverify: 500,
                ..
            }
        ),
        "got: {err}"
    );
}

#[test]
fn governance_registry_update_rejects_invalid_transition() {
    // TASK-100: With multi-step governance, the lifecycle transition validity is
    // checked during tally (execute_registry_update), not at proposal submission
    // time. An Active→Banned proposal is accepted as a pending proposal but its
    // effect is silently skipped during tally (invalid forward-only transition).
    // The registry must remain unchanged.
    let sender_addr = Address([0xAA; 32]);
    let payload = governance_registry_update_payload(AlgId::MlDsa65, Some(3), Some(500), 0x6C);

    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::GovernanceProposal,
        sender: sender_addr.clone(),
        nonce: 0,
        fee: 0,
        fee_tip: 0,
        gas_limit: GAS_GOVERNANCE_PROPOSAL,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let mut store = StateStore::new();
    let mut sender = creator_account(sender_addr.clone(), 0);
    sender.balance = 10_000;
    store.insert_account(sender);

    // Proposal submission now succeeds (validation deferred to tally).
    apply_tx(&mut store, &tx, exec_ctx(&tx)).expect("proposal submission must succeed");
    assert_eq!(store.pending_proposals_in_order().len(), 1);

    // Add validator and vote yes.
    let val_addr = Address([0xEEu8; 32]);
    store.insert_account(creator_account(val_addr.clone(), 0));
    store.insert_validator(pqc_types::validator::ValidatorRecord {
        operator: val_addr.clone(),
        node_id: "val-inv".into(),
        consensus_alg_id: AlgId::MlDsa65,
        consensus_pk: vec![0xFFu8; 1952],
        self_bond: 0,
        status: pqc_types::validator::ValidatorStatus::Active,
        registered_height: 0,
        tombstoned: false,
    });
    let proposal_id = store.pending_proposals_in_order()[0].proposal_id.0;
    let vote_payload = make_governance_vote_payload(proposal_id, true);
    let vote_tx = make_gov_tx(val_addr.clone(), 0, MsgType::GovernanceVote, vote_payload);
    apply_governance_vote(&mut store, &vote_tx).expect("vote must succeed");

    let deadline = store.pending_proposals_in_order()[0].voting_deadline;
    process_governance_tallies(&mut store, deadline + 1);

    // Registry must NOT have changed — invalid transition was silently skipped.
    let entry = store.alg_entry(AlgId::MlDsa65).unwrap();
    assert_eq!(
        entry.lifecycle,
        Lifecycle::Active,
        "lifecycle must remain Active when invalid transition is silently skipped"
    );
    assert_eq!(entry.min_fee, 0, "min_fee must remain unchanged");
}

#[test]
fn token_transfer_debits_sender_and_credits_existing_recipient() {
    let sender_addr = Address([0xAA; 32]);
    let recipient_addr = Address([0xBB; 32]);

    let payload = transfer_payload(&recipient_addr, 500);

    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::TokenTransfer,
        sender: sender_addr.clone(),
        nonce: 0,
        fee: 100,
        fee_tip: 0,
        gas_limit: 100_000,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let mut store = StateStore::new();

    // Sender with enough balance
    let mut sender = creator_account(sender_addr.clone(), 0);
    sender.balance = 10_000;
    store.insert_account(sender);

    // Recipient already exists with 200 tokens
    let mut recipient = creator_account(recipient_addr.clone(), 0);
    recipient.balance = 200;
    store.insert_account(recipient);

    let result = apply_tx(
        &mut store,
        &tx,
        ExecutionContext {
            tx_bytes_len: encode_tx(&tx).unwrap().len(),
            fee_params: FeeParams {
                base_fee: 100,
                ..FeeParams::default()
            },
        },
    )
    .expect("apply must succeed");
    assert_eq!(result.fee_charged, 100);
    assert_eq!(result.fee_refund, 0);

    let sender_after = store.get_account(&sender_addr).unwrap();
    // 10_000 - 500 (amount) - 100 (fee) = 9_400
    assert_eq!(sender_after.balance, 9_400);
    assert_eq!(sender_after.nonce, 1, "nonce must increment");

    let recipient_after = store.get_account(&recipient_addr).unwrap();
    assert_eq!(recipient_after.balance, 700); // 200 + 500
}

#[test]
fn token_transfer_creates_recipient_implicitly() {
    let sender_addr = Address([0xAA; 32]);
    let new_recipient = Address([0xEE; 32]);

    let payload = transfer_payload(&new_recipient, 300);

    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::TokenTransfer,
        sender: sender_addr.clone(),
        nonce: 0,
        fee: 0,
        fee_tip: 0,
        gas_limit: 100_000,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let mut store = StateStore::new();
    let mut sender = creator_account(sender_addr.clone(), 0);
    sender.balance = 5_000;
    store.insert_account(sender);

    assert!(
        store.get_account(&new_recipient).is_none(),
        "recipient must not exist before transfer"
    );

    let result = apply_tx(&mut store, &tx, exec_ctx(&tx)).expect("apply must succeed");
    assert_eq!(result.status, ExecutionStatus::Applied);

    let created = store
        .get_account(&new_recipient)
        .expect("recipient must be created implicitly");
    assert_eq!(created.balance, 300);
    assert_eq!(created.nonce, 0);
    assert!(
        created.keys.0.is_empty(),
        "implicitly created account must have empty KeySet"
    );
}

#[test]
fn token_transfer_rejects_self_transfer() {
    let addr = Address([0xAA; 32]);
    let payload = transfer_payload(&addr, 100);

    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::TokenTransfer,
        sender: addr.clone(),
        nonce: 0,
        fee: 0,
        fee_tip: 0,
        gas_limit: 100_000,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let mut store = StateStore::new();
    let mut account = creator_account(addr.clone(), 0);
    account.balance = 1_000;
    store.insert_account(account);

    let err = apply_tx(&mut store, &tx, exec_ctx(&tx)).unwrap_err();
    assert!(
        matches!(err, crate::error::ApplyError::SelfTransfer),
        "got: {err}"
    );
}

#[test]
fn token_transfer_rejects_insufficient_funds() {
    let sender_addr = Address([0xAA; 32]);
    let recipient_addr = Address([0xBB; 32]);
    let payload = transfer_payload(&recipient_addr, 5_000);

    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::TokenTransfer,
        sender: sender_addr.clone(),
        nonce: 0,
        fee: 0,
        fee_tip: 0,
        gas_limit: 100_000,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let mut store = StateStore::new();
    let mut sender = creator_account(sender_addr.clone(), 0);
    sender.balance = 100; // less than 5_000
    store.insert_account(sender);

    let err = apply_tx(&mut store, &tx, exec_ctx(&tx)).unwrap_err();
    assert!(
        matches!(err, crate::error::ApplyError::InsufficientFunds),
        "got: {err}"
    );
}

#[test]
fn token_transfer_refunds_overdeclared_fee() {
    let sender_addr = Address([0xAA; 32]);
    let recipient_addr = Address([0xBB; 32]);

    let payload = transfer_payload(&recipient_addr, 500);

    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::TokenTransfer,
        sender: sender_addr.clone(),
        nonce: 0,
        fee: 500,
        fee_tip: 0,
        gas_limit: GAS_TOKEN_TRANSFER + 1,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let mut store = StateStore::new();
    let mut sender = creator_account(sender_addr.clone(), 0);
    sender.balance = 10_000;
    store.insert_account(sender);

    let result = apply_tx(
        &mut store,
        &tx,
        ExecutionContext {
            tx_bytes_len: encode_tx(&tx).unwrap().len(),
            fee_params: FeeParams {
                base_fee: 100,
                ..FeeParams::default()
            },
        },
    )
    .expect("apply must succeed");

    assert_eq!(result.status, ExecutionStatus::Applied);
    assert_eq!(result.fee_charged, 100);
    assert_eq!(result.fee_refund, 400);

    let sender_after = store.get_account(&sender_addr).unwrap();
    assert_eq!(sender_after.balance, 9_400);
    assert_eq!(sender_after.nonce, 1);
}

#[test]
fn token_transfer_succeeds_at_exact_required_gas_limit() {
    let sender_addr = Address([0xAA; 32]);
    let recipient_addr = Address([0xBB; 32]);

    let payload = transfer_payload(&recipient_addr, 500);

    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::TokenTransfer,
        sender: sender_addr.clone(),
        nonce: 0,
        fee: 100,
        fee_tip: 0,
        gas_limit: GAS_TOKEN_TRANSFER,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let mut store = StateStore::new();
    let mut sender = creator_account(sender_addr.clone(), 0);
    sender.balance = 10_000;
    store.insert_account(sender);

    let result = apply_tx(
        &mut store,
        &tx,
        ExecutionContext {
            tx_bytes_len: encode_tx(&tx).unwrap().len(),
            fee_params: FeeParams {
                base_fee: 100,
                ..FeeParams::default()
            },
        },
    )
    .expect("apply must succeed at the exact scheduled gas threshold");

    assert_eq!(result.status, ExecutionStatus::Applied);
    assert_eq!(result.gas_used, GAS_TOKEN_TRANSFER);
    assert_eq!(result.fee_charged, 100);
    assert_eq!(result.fee_refund, 0);

    let sender_after = store.get_account(&sender_addr).unwrap();
    assert_eq!(sender_after.balance, 9_400);
    assert_eq!(sender_after.nonce, 1);

    let recipient_after = store.get_account(&recipient_addr).unwrap();
    assert_eq!(recipient_after.balance, 500);
}

// Amounts that do not fit in u64 (CBOR major type 0) must round-trip through
// the 16-byte big-endian bstr form. Regression for crates/pqcd/src/main.rs:604
// where `Integer::try_from(i128)` panicked for amounts ≥ 2^64.
#[test]
fn token_transfer_accepts_u128_amount_as_bstr() {
    let sender_addr = Address([0xAA; 32]);
    let recipient_addr = Address([0xBB; 32]);

    let big_amount: u128 = (u64::MAX as u128) + 1;
    let payload = {
        let map = Value::Map(vec![
            (
                Value::Integer(1u64.into()),
                Value::Bytes(recipient_addr.0.to_vec()),
            ),
            (
                Value::Integer(2u64.into()),
                Value::Bytes(big_amount.to_be_bytes().to_vec()),
            ),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&map, &mut buf).unwrap();
        buf
    };

    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::TokenTransfer,
        sender: sender_addr.clone(),
        nonce: 0,
        fee: 100,
        fee_tip: 0,
        gas_limit: 100_000,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let mut store = StateStore::new();
    let mut sender = creator_account(sender_addr.clone(), 0);
    sender.balance = u128::MAX;
    store.insert_account(sender);

    let result = apply_tx(
        &mut store,
        &tx,
        ExecutionContext {
            tx_bytes_len: encode_tx(&tx).unwrap().len(),
            fee_params: FeeParams {
                base_fee: 100,
                ..FeeParams::default()
            },
        },
    )
    .expect("u128 transfer must apply without panic");
    assert_eq!(result.status, ExecutionStatus::Applied);

    let sender_after = store.get_account(&sender_addr).unwrap();
    assert_eq!(sender_after.balance, u128::MAX - big_amount - 100);

    let recipient_after = store.get_account(&recipient_addr).unwrap();
    assert_eq!(recipient_after.balance, big_amount);
}

#[test]
fn token_transfer_rejects_wrong_length_amount_bstr() {
    let sender_addr = Address([0xAA; 32]);
    let recipient_addr = Address([0xBB; 32]);

    let payload = {
        let map = Value::Map(vec![
            (
                Value::Integer(1u64.into()),
                Value::Bytes(recipient_addr.0.to_vec()),
            ),
            (Value::Integer(2u64.into()), Value::Bytes(vec![0xFFu8; 8])),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&map, &mut buf).unwrap();
        buf
    };

    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::TokenTransfer,
        sender: sender_addr.clone(),
        nonce: 0,
        fee: 100,
        fee_tip: 0,
        gas_limit: 100_000,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let mut store = StateStore::new();
    let mut sender = creator_account(sender_addr.clone(), 0);
    sender.balance = 10_000;
    store.insert_account(sender);

    let err = apply_tx(
        &mut store,
        &tx,
        ExecutionContext {
            tx_bytes_len: encode_tx(&tx).unwrap().len(),
            fee_params: FeeParams {
                base_fee: 100,
                ..FeeParams::default()
            },
        },
    )
    .expect_err("malformed amount bstr must be rejected");
    assert!(
        matches!(err, crate::error::ApplyError::PayloadDecode(_)),
        "got: {err}"
    );
}

#[test]
fn out_of_gas_charges_full_fee_and_discards_payload_changes_below_required_limit() {
    let sender_addr = Address([0xAA; 32]);
    let recipient_addr = Address([0xBB; 32]);

    let payload = transfer_payload(&recipient_addr, 500);

    let tx = Transaction {
        tx_version: 1,
        chain_id: CHAIN_ID.to_vec(),
        msg_type: MsgType::TokenTransfer,
        sender: sender_addr.clone(),
        nonce: 0,
        fee: 300,
        fee_tip: 7,
        gas_limit: GAS_TOKEN_TRANSFER - 1,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };

    let mut store = StateStore::new();
    let mut sender = creator_account(sender_addr.clone(), 0);
    sender.balance = 10_000;
    store.insert_account(sender);

    let result = apply_tx(
        &mut store,
        &tx,
        ExecutionContext {
            tx_bytes_len: encode_tx(&tx).unwrap().len(),
            fee_params: FeeParams {
                base_fee: 100,
                ..FeeParams::default()
            },
        },
    )
    .expect("out-of-gas transaction should still be included");

    assert_eq!(result.status, ExecutionStatus::RevertedOutOfGas);
    assert_eq!(result.gas_used, tx.gas_limit);
    assert_eq!(result.fee_charged, tx.fee);
    assert_eq!(result.fee_refund, 0);

    let sender_after = store.get_account(&sender_addr).unwrap();
    assert_eq!(sender_after.balance, 10_000 - 300 - 7);
    assert_eq!(sender_after.nonce, 1);
    assert!(
        store.get_account(&recipient_addr).is_none(),
        "payload state changes must be discarded"
    );
}
