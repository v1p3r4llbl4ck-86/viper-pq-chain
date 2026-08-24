// SPDX-License-Identifier: BUSL-1.1
//! Pin tests for `apply/governance.rs`.
//!
//! Extracted from `governance.rs` 2026-05-10. `use super::*;` brings
//! every private item from the parent module into scope.

use super::*;
use ciborium::value::Value as CborValue;
use pqc_crypto::{AlgId, Lifecycle};
use pqc_types::{
    account::{Account, Address},
    governance::{
        AddAlgorithmProposal, GovernanceProposalType, PendingProposal, ProposalEffect,
        ProposalStatus,
    },
    keyset::{allowed_tx, KeyEntry, KeySet, KeyStatus},
    transaction::{MsgType, Transaction, TxHash},
    validator::{ValidatorRecord, ValidatorStatus},
};

// ── Helpers ───────────────────────────────────────────────────────────────

/// Encode a CBOR map from `(int_key, value)` pairs.  Mirrors the helper in
/// `tests.rs` but locally scoped so this module stays self-contained.
fn encode_cbor_map(pairs: Vec<(i128, CborValue)>) -> Vec<u8> {
    let entries: Vec<(CborValue, CborValue)> = pairs
        .into_iter()
        .map(|(k, v)| (CborValue::Integer(k.try_into().unwrap()), v))
        .collect();
    let mut out = Vec::new();
    ciborium::into_writer(&CborValue::Map(entries), &mut out).unwrap();
    out
}

fn cbor_int(n: i128) -> CborValue {
    CborValue::Integer(n.try_into().unwrap())
}

fn cbor_bytes(b: Vec<u8>) -> CborValue {
    CborValue::Bytes(b)
}

fn cbor_text(s: &str) -> CborValue {
    CborValue::Text(s.into())
}

fn make_account(addr: Address) -> Account {
    Account {
        address: addr,
        balance: 1_000_000,
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

fn insert_active_validator(store: &mut StateStore, tag: u8) -> Address {
    let addr = Address([tag; 32]);
    store.insert_account(make_account(addr.clone()));
    store.insert_validator(ValidatorRecord {
        operator: addr.clone(),
        node_id: format!("val-{tag}"),
        consensus_alg_id: AlgId::MlDsa65,
        consensus_pk: vec![tag; 1952],
        self_bond: 0,
        status: ValidatorStatus::Active,
        registered_height: 0,
        tombstoned: false,
    });
    addr
}

/// Build a `Transaction` for a governance proposal with the given payload.
/// Sender nonce starts at 0; signature is a 0-byte stub.  The test path
/// calls `apply_governance_proposal` directly, bypassing signature checks.
fn make_proposal_tx(sender: Address, payload: Vec<u8>) -> Transaction {
    Transaction {
        tx_version: 1,
        chain_id: Vec::new(),
        nonce: 0,
        sender,
        msg_type: MsgType::GovernanceProposal,
        payload,
        gas_limit: 1_000_000,
        fee: 0,
        fee_tip: 0,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![],
    }
}

fn make_vote_tx(sender: Address, proposal_id: [u8; 32], yes: bool) -> Transaction {
    let payload = encode_cbor_map(vec![
        (1, cbor_bytes(proposal_id.to_vec())),
        (2, cbor_int(if yes { 1 } else { 0 })),
    ]);
    Transaction {
        tx_version: 1,
        chain_id: Vec::new(),
        nonce: 0,
        sender,
        msg_type: MsgType::GovernanceVote,
        payload,
        gas_limit: 1_000_000,
        fee: 0,
        fee_tip: 0,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![],
    }
}

/// Build a `RegistryUpdate` payload.  `target_lifecycle` is the raw u8
/// the apply path expects (1=Discouraged, 2=Deprecated, 3=Banned).
fn registry_update_payload(
    alg_id: u16,
    target_lifecycle: Option<u8>,
    new_min_fee: Option<u64>,
    rationale_byte: u8,
) -> Vec<u8> {
    let mut pairs: Vec<(i128, CborValue)> = vec![
        (
            1,
            cbor_int(GovernanceProposalType::RegistryUpdate.as_u8() as i128),
        ),
        (2, cbor_int(alg_id as i128)),
        (6, cbor_bytes(vec![rationale_byte; 32])),
    ];
    if let Some(lc) = target_lifecycle {
        pairs.push((3, cbor_int(lc as i128)));
    }
    if let Some(fee) = new_min_fee {
        pairs.push((4, cbor_int(fee as i128)));
    }
    encode_cbor_map(pairs)
}

/// Build an `AddAlgorithm` payload.  Defaults to a sane envelope so each
/// test only needs to override the field it is exercising.
#[allow(clippy::too_many_arguments)]
fn add_algorithm_payload(
    alg_id: u16,
    spec_ref: &str,
    pk_size: u32,
    sig_size: u32,
    sig_class: Option<u8>,
    initial_lifecycle_raw: u8,
    rationale_byte: u8,
) -> Vec<u8> {
    let mut pairs: Vec<(i128, CborValue)> = vec![
        (
            1,
            cbor_int(GovernanceProposalType::AddAlgorithm.as_u8() as i128),
        ),
        (2, cbor_int(alg_id as i128)),
        (6, cbor_bytes(vec![rationale_byte; 32])),
        (11, cbor_text(spec_ref)),
        (12, cbor_int(pk_size as i128)),
        (13, cbor_int(sig_size as i128)),
        (15, cbor_int(initial_lifecycle_raw as i128)),
    ];
    if let Some(sc) = sig_class {
        pairs.push((14, cbor_int(sc as i128)));
    }
    encode_cbor_map(pairs)
}

fn add_slashing_verifier_payload(
    evidence_type: u8,
    spec_ref: &str,
    slash_fraction_bps: u16,
    jail_duration: Option<u64>,
    tombstone: bool,
    lifecycle_raw: u8,
    rationale_byte: u8,
) -> Vec<u8> {
    let mut pairs: Vec<(i128, CborValue)> = vec![
        (
            1,
            cbor_int(GovernanceProposalType::AddSlashingVerifier.as_u8() as i128),
        ),
        (6, cbor_bytes(vec![rationale_byte; 32])),
        (30, cbor_int(evidence_type as i128)),
        (31, cbor_text(spec_ref)),
        (32, cbor_int(slash_fraction_bps as i128)),
        (34, cbor_int(if tombstone { 1 } else { 0 })),
        (35, cbor_int(lifecycle_raw as i128)),
    ];
    if let Some(jd) = jail_duration {
        pairs.push((33, cbor_int(jd as i128)));
    }
    encode_cbor_map(pairs)
}

/// Drop a passing-quorum proposal directly into the store as Voting and
/// return its id.  Skips the apply path (which would also work) so each
/// effect test runs with a tightly-controlled `effect`.  Used when the
/// goal is to PIN the tally-execution behaviour, not the encoding path.
fn seed_voting_proposal(
    store: &mut StateStore,
    effect: ProposalEffect,
    proposer: Address,
) -> TxHash {
    let id_bytes = [0xEEu8; 32];
    let id = TxHash(id_bytes);
    let proposal_type = match &effect {
        ProposalEffect::RegistryUpdate { .. } => GovernanceProposalType::RegistryUpdate,
        ProposalEffect::BurnRateUpdate { .. } => GovernanceProposalType::BurnRateUpdate,
        ProposalEffect::FeeParamUpdate { .. } => GovernanceProposalType::FeeParamUpdate,
        ProposalEffect::SoftwareUpgrade { .. } => GovernanceProposalType::SoftwareUpgrade,
        ProposalEffect::AddAlgorithm(_) => GovernanceProposalType::AddAlgorithm,
        ProposalEffect::AddSlashingVerifier(_) => GovernanceProposalType::AddSlashingVerifier,
        ProposalEffect::AddHash(_) => GovernanceProposalType::AddHash,
        ProposalEffect::AddAuthTemplate(_) => GovernanceProposalType::AddAuthTemplate,
    };
    let prop = PendingProposal {
        proposal_id: id.clone(),
        proposal_type,
        proposer,
        voting_deadline: 0,
        execute_after: 0,
        effect,
        votes: std::collections::HashMap::new(),
        status: ProposalStatus::Voting,
        rationale_hash: [0u8; 32],
    };
    store.insert_pending_proposal(prop);
    id
}

// ── Lifecycle transition tests (RegistryUpdate) ──────────────────────────

/// Active → Discouraged is the canonical first transition.  PIN the fact
/// that lifecycle changes only after tally executes (not at proposal
/// time).
#[test]
fn registry_update_active_to_discouraged_executes_on_tally() {
    // Arrange
    let mut store = StateStore::new();
    let proposer = Address([0x01; 32]);
    store.insert_account(make_account(proposer.clone()));
    let _v1 = insert_active_validator(&mut store, 0xA1);

    let payload = registry_update_payload(AlgId::MlDsa65.as_u16(), Some(1), None, 0xA1);
    let tx = make_proposal_tx(proposer.clone(), payload);

    // Act
    apply_governance_proposal(&mut store, &tx).expect("proposal must register");
    let id = store.pending_proposals_in_order()[0].proposal_id.0;
    let vote_tx = make_vote_tx(Address([0xA1; 32]), id, true);
    apply_governance_vote(&mut store, &vote_tx).expect("vote must succeed");
    let deadline = store.pending_proposals_in_order()[0].voting_deadline;
    process_governance_tallies(&mut store, deadline + 1);

    // Assert — Active → Discouraged is the only valid first step.
    let entry = store.alg_entry(AlgId::MlDsa65).unwrap();
    assert_eq!(entry.lifecycle, Lifecycle::Discouraged);
    let proposal = store.pending_proposals_in_order()[0];
    assert_eq!(proposal.status, ProposalStatus::Executed);
}

/// Discouraged → Deprecated is the canonical second transition.
#[test]
fn registry_update_discouraged_to_deprecated_succeeds() {
    let mut store = StateStore::new();
    // Pre-stage: walk the registry entry to Discouraged.
    let entry = store.alg_entry_mut(AlgId::MlDsa65).unwrap();
    entry.lifecycle = Lifecycle::Discouraged;
    store.commit_alg_entry_mutation(AlgId::MlDsa65);

    let proposer = Address([0x02; 32]);
    store.insert_account(make_account(proposer.clone()));
    let _v1 = insert_active_validator(&mut store, 0xB1);

    let effect = ProposalEffect::RegistryUpdate {
        alg_id: AlgId::MlDsa65,
        target_lifecycle: Some(Lifecycle::Deprecated),
        new_min_fee: None,
    };
    let id = seed_voting_proposal(&mut store, effect, proposer);
    // Cast yes vote to clear quorum (1 active validator → quorum = 1).
    let vote_tx = make_vote_tx(Address([0xB1; 32]), id.0, true);
    apply_governance_vote(&mut store, &vote_tx).expect("vote");

    process_governance_tallies(&mut store, 1);

    let entry = store.alg_entry(AlgId::MlDsa65).unwrap();
    assert_eq!(entry.lifecycle, Lifecycle::Deprecated);
}

/// Deprecated → Banned is the canonical third (terminal) transition.
#[test]
fn registry_update_deprecated_to_banned_succeeds() {
    let mut store = StateStore::new();
    let entry = store.alg_entry_mut(AlgId::MlDsa65).unwrap();
    entry.lifecycle = Lifecycle::Deprecated;
    store.commit_alg_entry_mutation(AlgId::MlDsa65);

    let proposer = Address([0x03; 32]);
    store.insert_account(make_account(proposer.clone()));
    let _v1 = insert_active_validator(&mut store, 0xC1);

    let effect = ProposalEffect::RegistryUpdate {
        alg_id: AlgId::MlDsa65,
        target_lifecycle: Some(Lifecycle::Banned),
        new_min_fee: None,
    };
    let id = seed_voting_proposal(&mut store, effect, proposer);
    let vote_tx = make_vote_tx(Address([0xC1; 32]), id.0, true);
    apply_governance_vote(&mut store, &vote_tx).expect("vote");
    process_governance_tallies(&mut store, 1);

    let entry = store.alg_entry(AlgId::MlDsa65).unwrap();
    assert_eq!(entry.lifecycle, Lifecycle::Banned);
}

/// Active → Banned skips Discouraged/Deprecated and MUST be rejected.
/// PIN the tally-time invariant: invalid transitions yield
/// `ExecutionFailed`, not panic, and leave the registry untouched.
#[test]
fn registry_update_invalid_skip_to_banned_marked_execution_failed() {
    let mut store = StateStore::new();
    let proposer = Address([0x04; 32]);
    store.insert_account(make_account(proposer.clone()));
    let _v1 = insert_active_validator(&mut store, 0xD1);

    let effect = ProposalEffect::RegistryUpdate {
        alg_id: AlgId::MlDsa65,
        target_lifecycle: Some(Lifecycle::Banned), // Active → Banned, illegal
        new_min_fee: None,
    };
    let id = seed_voting_proposal(&mut store, effect, proposer);
    let vote_tx = make_vote_tx(Address([0xD1; 32]), id.0, true);
    apply_governance_vote(&mut store, &vote_tx).expect("vote");
    process_governance_tallies(&mut store, 1);

    let entry = store.alg_entry(AlgId::MlDsa65).unwrap();
    assert_eq!(
        entry.lifecycle,
        Lifecycle::Active,
        "registry MUST be unchanged on invalid transition"
    );
    let proposal = store.pending_proposals_in_order()[0];
    assert_eq!(
        proposal.status,
        ProposalStatus::ExecutionFailed,
        "invalid transition MUST mark ExecutionFailed, not panic"
    );
}

/// Banned → Active is a backward transition; it MUST be rejected.
#[test]
fn registry_update_banned_to_active_rejected() {
    let mut store = StateStore::new();
    let entry = store.alg_entry_mut(AlgId::MlDsa65).unwrap();
    entry.lifecycle = Lifecycle::Banned;
    store.commit_alg_entry_mutation(AlgId::MlDsa65);

    let proposer = Address([0x05; 32]);
    store.insert_account(make_account(proposer.clone()));
    let _v1 = insert_active_validator(&mut store, 0xE1);

    let effect = ProposalEffect::RegistryUpdate {
        alg_id: AlgId::MlDsa65,
        target_lifecycle: Some(Lifecycle::Active),
        new_min_fee: None,
    };
    let id = seed_voting_proposal(&mut store, effect, proposer);
    let vote_tx = make_vote_tx(Address([0xE1; 32]), id.0, true);
    apply_governance_vote(&mut store, &vote_tx).expect("vote");
    process_governance_tallies(&mut store, 1);

    let entry = store.alg_entry(AlgId::MlDsa65).unwrap();
    assert_eq!(
        entry.lifecycle,
        Lifecycle::Banned,
        "Banned MUST be terminal"
    );
    let proposal = store.pending_proposals_in_order()[0];
    assert_eq!(proposal.status, ProposalStatus::ExecutionFailed);
}

// ── AddAlgorithm tests ───────────────────────────────────────────────────

/// AddAlgorithm with a known-to-binary id (0x0023 SlhDsaShake128s removed
/// from registry then re-added) MUST insert a fresh AlgEntry.  PIN the
/// post-tally state: registry contains the new entry with Active
/// lifecycle.
#[test]
fn add_algorithm_inserts_known_alg_id_after_tally() {
    // Phase-1 registry already contains all known AlgIds.  Drop one so
    // the AddAlgorithm path has a duplicate-free target.
    // We do this by rebuilding the store from a snapshot without that entry.
    let keep: Vec<_> = pqc_crypto::registry::phase1_registry()
        .into_iter()
        .filter(|e| e.alg_id != AlgId::SlhDsaShake128s)
        .collect();
    let mut store = StateStore::from_snapshot_full_with_proofs(
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        keep,
        0,
        Vec::new(),
    );
    let proposer = Address([0x06; 32]);
    store.insert_account(make_account(proposer.clone()));
    let _v1 = insert_active_validator(&mut store, 0xF1);

    let payload = add_algorithm_payload(
        AlgId::SlhDsaShake128s.as_u16(),
        "FIPS 205",
        32,
        7_856,
        Some(3), // SigClass::Premium
        0,       // initial Active
        0xAA,
    );
    let tx = make_proposal_tx(proposer.clone(), payload);
    apply_governance_proposal(&mut store, &tx).expect("proposal must register");

    let id = store.pending_proposals_in_order()[0].proposal_id.0;
    let vote_tx = make_vote_tx(Address([0xF1; 32]), id, true);
    apply_governance_vote(&mut store, &vote_tx).expect("vote");
    let deadline = store.pending_proposals_in_order()[0].voting_deadline;
    process_governance_tallies(&mut store, deadline + 1);

    // PIN: registry contains the freshly added entry.
    let added = store.alg_entry(AlgId::SlhDsaShake128s).unwrap();
    assert_eq!(added.lifecycle, Lifecycle::Active);
    assert_eq!(added.pk_size, 32);
    assert_eq!(added.sig_size, 7_856);
    let proposal = store.pending_proposals_in_order()[0];
    assert_eq!(proposal.status, ProposalStatus::Executed);
}

/// AddAlgorithm with an alg_id already registered MUST be rejected at
/// tally time as ExecutionFailed (decode-time check is duplicate-free).
#[test]
fn add_algorithm_duplicate_alg_id_marked_execution_failed() {
    let mut store = StateStore::new();
    let proposer = Address([0x07; 32]);
    store.insert_account(make_account(proposer.clone()));
    let _v1 = insert_active_validator(&mut store, 0xF2);

    // Seed proposal directly so we bypass the encode-time check (which
    // would not catch duplicates — that's a tally-time check).
    let dup = AddAlgorithmProposal {
        alg_id: AlgId::MlDsa65.as_u16(), // already in phase1_registry
        spec_ref: "FIPS 204".into(),
        pk_size: 1_952,
        sig_size: 3_309,
        sig_class: Some(2),
        min_fee: 0,
        benchmark_verify_per_sec: 0,
        initial_lifecycle: Lifecycle::Active,
    };
    let id = seed_voting_proposal(&mut store, ProposalEffect::AddAlgorithm(dup), proposer);
    let vote_tx = make_vote_tx(Address([0xF2; 32]), id.0, true);
    apply_governance_vote(&mut store, &vote_tx).expect("vote");
    process_governance_tallies(&mut store, 1);

    let proposal = store.pending_proposals_in_order()[0];
    assert_eq!(proposal.status, ProposalStatus::ExecutionFailed);
}

/// AddAlgorithm with an alg_id in the reserved range 0x0000..=0x000F MUST
/// be rejected at decode time with `ReservedAlgIdRange`.
#[test]
fn add_algorithm_reserved_alg_id_rejected_at_decode() {
    let mut store = StateStore::new();
    let proposer = Address([0x08; 32]);
    store.insert_account(make_account(proposer.clone()));

    let payload = add_algorithm_payload(0x0005, "spec", 100, 200, Some(2), 0, 0xAB);
    let tx = make_proposal_tx(proposer, payload);
    let err =
        apply_governance_proposal(&mut store, &tx).expect_err("reserved alg_id MUST be rejected");
    assert!(matches!(err, ApplyError::ReservedAlgIdRange(0x0005)));
}

/// AddAlgorithm with pk_size or sig_size of 0 MUST be rejected at decode time.
#[test]
fn add_algorithm_zero_size_rejected_at_decode() {
    let mut store = StateStore::new();
    let proposer = Address([0x09; 32]);
    store.insert_account(make_account(proposer.clone()));

    let payload = add_algorithm_payload(0x0042, "spec", 0, 200, Some(2), 0, 0xAC);
    let tx = make_proposal_tx(proposer, payload);
    let err = apply_governance_proposal(&mut store, &tx).expect_err("zero size MUST be rejected");
    assert!(matches!(err, ApplyError::InvalidSize));
}

/// AddAlgorithm referencing an alg_id NOT recognized by the binary
/// (e.g. 0x0042) MUST tally to ExecutionFailed — the metadata is rejected
/// at insert-time because the AlgEntry constructor needs a typed AlgId.
#[test]
fn add_algorithm_unknown_to_binary_marks_execution_failed() {
    let mut store = StateStore::new();
    let proposer = Address([0x0A; 32]);
    store.insert_account(make_account(proposer.clone()));
    let _v1 = insert_active_validator(&mut store, 0xF4);

    let unknown = AddAlgorithmProposal {
        alg_id: 0x0042, // not in AlgId::from_u16
        spec_ref: "future spec".into(),
        pk_size: 100,
        sig_size: 200,
        sig_class: Some(2),
        min_fee: 0,
        benchmark_verify_per_sec: 0,
        initial_lifecycle: Lifecycle::Active,
    };
    let id = seed_voting_proposal(&mut store, ProposalEffect::AddAlgorithm(unknown), proposer);
    let vote_tx = make_vote_tx(Address([0xF4; 32]), id.0, true);
    apply_governance_vote(&mut store, &vote_tx).expect("vote");
    process_governance_tallies(&mut store, 1);

    let proposal = store.pending_proposals_in_order()[0];
    assert_eq!(
        proposal.status,
        ProposalStatus::ExecutionFailed,
        "unknown alg_id at apply-time MUST mark ExecutionFailed (deferred to SoftwareUpgrade)"
    );
}

// ── AddSlashingVerifier tests (ADR-050) ──────────────────────────────────

/// A governance-added evidence type in the 0x10..=0xFF range MUST be
/// inserted on tally and read back via `slashing_verifier_entry`.  PIN
/// that the inserted record is byte-faithful to the proposal payload.
#[test]
fn add_slashing_verifier_inserts_governance_range_entry() {
    let mut store = StateStore::new();
    let proposer = Address([0x0B; 32]);
    store.insert_account(make_account(proposer.clone()));
    let _v1 = insert_active_validator(&mut store, 0xF5);

    let payload = add_slashing_verifier_payload(
        0x10,
        "ADR-050 §3 (data-withholding)",
        300,
        Some(1_000),
        false,
        0,
        0xAD,
    );
    let tx = make_proposal_tx(proposer.clone(), payload);
    apply_governance_proposal(&mut store, &tx).expect("proposal must register");

    let id = store.pending_proposals_in_order()[0].proposal_id.0;
    let vote_tx = make_vote_tx(Address([0xF5; 32]), id, true);
    apply_governance_vote(&mut store, &vote_tx).expect("vote");
    let deadline = store.pending_proposals_in_order()[0].voting_deadline;
    process_governance_tallies(&mut store, deadline + 1);

    let entry = store.slashing_verifier_entry(0x10).expect("entry inserted");
    assert_eq!(entry.evidence_type, 0x10);
    assert_eq!(entry.slash_fraction_bps, 300);
    assert_eq!(entry.jail_duration_blocks, 1_000);
    assert!(!entry.tombstone);
    assert_eq!(entry.lifecycle, Lifecycle::Active);
}

/// AddSlashingVerifier targeting a reserved evidence type (0x01) MUST be
/// rejected at decode time with `ReservedSlashingEvidenceType`.
#[test]
fn add_slashing_verifier_reserved_evidence_type_rejected_at_decode() {
    let mut store = StateStore::new();
    let proposer = Address([0x0C; 32]);
    store.insert_account(make_account(proposer.clone()));

    let payload = add_slashing_verifier_payload(
        0x01, // core, reserved
        "spec", 500, None, true, 0, 0xAE,
    );
    let tx = make_proposal_tx(proposer, payload);
    let err = apply_governance_proposal(&mut store, &tx)
        .expect_err("reserved evidence_type MUST be rejected");
    assert!(matches!(
        err,
        ApplyError::ReservedSlashingEvidenceType(0x01)
    ));
}

/// AddSlashingVerifier with a fraction > 10_000 bps MUST be rejected at
/// decode time with `InvalidSlashingFraction`.
#[test]
fn add_slashing_verifier_fraction_out_of_range_rejected_at_decode() {
    let mut store = StateStore::new();
    let proposer = Address([0x0D; 32]);
    store.insert_account(make_account(proposer.clone()));

    let payload = add_slashing_verifier_payload(
        0x11, "spec", 10_001, // > 100% — illegal
        None, false, 0, 0xAF,
    );
    let tx = make_proposal_tx(proposer, payload);
    let err = apply_governance_proposal(&mut store, &tx).expect_err("fraction MUST be capped");
    assert!(matches!(err, ApplyError::InvalidSlashingFraction));
}

// ── Payload decoding edge cases ──────────────────────────────────────────

/// An empty payload MUST be rejected with `PayloadDecode`.
#[test]
fn empty_payload_rejected() {
    let mut store = StateStore::new();
    let proposer = Address([0x10; 32]);
    store.insert_account(make_account(proposer.clone()));
    let tx = make_proposal_tx(proposer, Vec::new());
    let err = apply_governance_proposal(&mut store, &tx).expect_err("empty MUST fail");
    assert!(matches!(err, ApplyError::PayloadDecode(_)));
}

/// A truncated CBOR payload (first byte only) MUST be rejected.
#[test]
fn truncated_payload_rejected() {
    let mut store = StateStore::new();
    let proposer = Address([0x11; 32]);
    store.insert_account(make_account(proposer.clone()));
    let tx = make_proposal_tx(proposer, vec![0xA5]); // CBOR map header, no body
    let err = apply_governance_proposal(&mut store, &tx).expect_err("truncated MUST fail");
    assert!(matches!(err, ApplyError::PayloadDecode(_)));
}

/// A payload with an unknown integer key MUST be rejected.
#[test]
fn unknown_payload_key_rejected() {
    let mut store = StateStore::new();
    let proposer = Address([0x12; 32]);
    store.insert_account(make_account(proposer.clone()));

    // Use key 999 — outside the documented [1..=16, 30..=35, 100..=102] set.
    let payload = encode_cbor_map(vec![
        (
            1,
            cbor_int(GovernanceProposalType::RegistryUpdate.as_u8() as i128),
        ),
        (2, cbor_int(AlgId::MlDsa65.as_u16() as i128)),
        (3, cbor_int(1)),
        (6, cbor_bytes(vec![0x12; 32])),
        (999, cbor_int(0)),
    ]);
    let tx = make_proposal_tx(proposer, payload);
    let err = apply_governance_proposal(&mut store, &tx).expect_err("unknown key MUST fail");
    assert!(matches!(err, ApplyError::PayloadDecode(_)));
}

/// A RegistryUpdate payload with neither lifecycle nor min_fee MUST be
/// rejected with `GovernanceNoEffect`.
#[test]
fn registry_update_no_effect_rejected() {
    let mut store = StateStore::new();
    let proposer = Address([0x13; 32]);
    store.insert_account(make_account(proposer.clone()));

    let payload = registry_update_payload(AlgId::MlDsa65.as_u16(), None, None, 0xB0);
    let tx = make_proposal_tx(proposer, payload);
    let err = apply_governance_proposal(&mut store, &tx).expect_err("no-op MUST fail");
    assert!(matches!(err, ApplyError::GovernanceNoEffect));
}

// ── Proposal-id uniqueness ───────────────────────────────────────────────

/// Submitting the byte-identical proposal twice MUST fail the second
/// time with `DuplicateProposal`.  PIN the deduplication-by-tx-hash
/// behaviour so concurrent identical proposals collide deterministically.
#[test]
fn duplicate_proposal_id_rejected() {
    let mut store = StateStore::new();
    let proposer = Address([0x14; 32]);
    store.insert_account(make_account(proposer.clone()));

    let payload = registry_update_payload(AlgId::MlDsa65.as_u16(), Some(1), None, 0xB1);
    let tx = make_proposal_tx(proposer, payload);
    apply_governance_proposal(&mut store, &tx).expect("first MUST succeed");
    let err = apply_governance_proposal(&mut store, &tx).expect_err("second MUST fail");
    assert!(matches!(err, ApplyError::DuplicateProposal));
}

// ── Pending → active timing (voting_deadline) ────────────────────────────

/// A proposal landed at height H has `voting_deadline = H + GOVERNANCE_VOTING_PERIOD`.
/// Tally MUST NOT execute before `voting_deadline + 1`.  PIN the off-by-one
/// so callers can rely on `process_governance_tallies(deadline)` being a no-op.
#[test]
fn tally_before_deadline_is_noop() {
    let mut store = StateStore::new();
    // Move to a non-zero block height so deadline arithmetic is non-trivial.
    for _ in 0..10 {
        store.advance_height();
    }
    let h_at_proposal = store.block_height();

    let proposer = Address([0x15; 32]);
    store.insert_account(make_account(proposer.clone()));
    let _v1 = insert_active_validator(&mut store, 0xC0);

    let payload = registry_update_payload(AlgId::MlDsa65.as_u16(), Some(1), None, 0xB2);
    let tx = make_proposal_tx(proposer.clone(), payload);
    apply_governance_proposal(&mut store, &tx).expect("proposal");

    let (id, voting_deadline) = {
        let proposal = store.pending_proposals_in_order()[0];
        assert_eq!(
            proposal.voting_deadline,
            h_at_proposal + GOVERNANCE_VOTING_PERIOD,
            "voting_deadline MUST equal block_height + GOVERNANCE_VOTING_PERIOD"
        );
        (proposal.proposal_id.0, proposal.voting_deadline)
    };
    let vote_tx = make_vote_tx(Address([0xC0; 32]), id, true);
    apply_governance_vote(&mut store, &vote_tx).expect("vote");

    // PIN: tally at exactly the deadline does NOT execute (filter is strict
    // less-than).
    process_governance_tallies(&mut store, voting_deadline);
    assert_eq!(
        store.pending_proposals_in_order()[0].status,
        ProposalStatus::Voting
    );

    // PIN: tally at deadline + 1 DOES execute.
    process_governance_tallies(&mut store, voting_deadline + 1);
    assert_eq!(
        store.pending_proposals_in_order()[0].status,
        ProposalStatus::Executed
    );
}

// ── Vote validation ──────────────────────────────────────────────────────

/// A vote past the `voting_deadline` MUST be rejected.
#[test]
fn vote_past_deadline_rejected() {
    let mut store = StateStore::new();
    let proposer = Address([0x16; 32]);
    store.insert_account(make_account(proposer.clone()));
    let val = insert_active_validator(&mut store, 0xD2);

    let payload = registry_update_payload(AlgId::MlDsa65.as_u16(), Some(1), None, 0xB3);
    let tx = make_proposal_tx(proposer, payload);
    apply_governance_proposal(&mut store, &tx).expect("proposal");

    let proposal = store.pending_proposals_in_order()[0];
    let deadline = proposal.voting_deadline;
    let id = proposal.proposal_id.0;

    // Advance height past the deadline.
    for _ in 0..(deadline + 2) {
        store.advance_height();
    }

    let vote_tx = make_vote_tx(val, id, true);
    let err = apply_governance_vote(&mut store, &vote_tx).expect_err("late vote MUST fail");
    assert!(matches!(err, ApplyError::VotingPeriodClosed));
}

/// A vote from an address that is not a registered Active validator MUST
/// be rejected with `NotAnActiveValidatorForVote`.
#[test]
fn vote_from_non_validator_rejected() {
    let mut store = StateStore::new();
    let proposer = Address([0x17; 32]);
    store.insert_account(make_account(proposer.clone()));
    let _v = insert_active_validator(&mut store, 0xD3);

    // Non-validator tries to vote.
    let outsider = Address([0x99; 32]);
    store.insert_account(make_account(outsider.clone()));

    let payload = registry_update_payload(AlgId::MlDsa65.as_u16(), Some(1), None, 0xB4);
    let tx = make_proposal_tx(proposer, payload);
    apply_governance_proposal(&mut store, &tx).expect("proposal");

    let id = store.pending_proposals_in_order()[0].proposal_id.0;
    let vote_tx = make_vote_tx(outsider, id, true);
    let err = apply_governance_vote(&mut store, &vote_tx).expect_err("non-validator MUST fail");
    assert!(matches!(err, ApplyError::NotAnActiveValidatorForVote));
}

/// A second vote by the same validator on the same proposal MUST fail
/// with `AlreadyVoted` — no vote-update semantic.
#[test]
fn duplicate_vote_rejected() {
    let mut store = StateStore::new();
    let proposer = Address([0x18; 32]);
    store.insert_account(make_account(proposer.clone()));
    let val = insert_active_validator(&mut store, 0xD4);

    let payload = registry_update_payload(AlgId::MlDsa65.as_u16(), Some(1), None, 0xB5);
    let tx = make_proposal_tx(proposer, payload);
    apply_governance_proposal(&mut store, &tx).expect("proposal");
    let id = store.pending_proposals_in_order()[0].proposal_id.0;

    let vote_tx = make_vote_tx(val.clone(), id, true);
    apply_governance_vote(&mut store, &vote_tx).expect("first vote");
    let err = apply_governance_vote(&mut store, &vote_tx).expect_err("second MUST fail");
    assert!(matches!(err, ApplyError::AlreadyVoted));
}

// ── quorum_required formula ──────────────────────────────────────────────

/// PIN the quorum formula `ceil(2N/3)` for a representative spread.  These
/// values are the contract for the tally path; a regression here
/// silently changes proposal outcomes.
#[test]
fn quorum_required_matches_spec_formula() {
    // n = 0 → 1 (degenerate but safe-by-construction)
    assert_eq!(quorum_required(0), 1);
    // n = 1 → 1, n = 2 → 2, n = 3 → 2, n = 4 → 3
    assert_eq!(quorum_required(1), 1);
    assert_eq!(quorum_required(2), 2);
    assert_eq!(quorum_required(3), 2);
    assert_eq!(quorum_required(4), 3);
    // n = 24 → 16 (matches SPEC-VAL-001 §5 reference table modulo +1).
    assert_eq!(quorum_required(24), 16);
    // n = 100 → 67
    assert_eq!(quorum_required(100), 67);
}

// ── check_pending_upgrades — version mismatch + timestamp activation ─────

/// `check_pending_upgrades` at the activation timestamp with a
/// matching version MUST succeed and clear the pending entry.
#[test]
fn pending_upgrade_version_match_clears_entry() {
    let mut store = StateStore::new();
    let id = TxHash([0x42; 32]);
    store.insert_pending_upgrade(pqc_types::governance::PendingUpgrade {
        proposal_id: id.clone(),
        activate_at_timestamp_ns: 100,
        expected_version: 7,
    });
    check_pending_upgrades(&mut store, 100, 7).expect("matching version MUST pass");
    assert!(
        store.pending_upgrades_in_order().is_empty(),
        "matching upgrade MUST be removed"
    );
}

/// `check_pending_upgrades` past the activation timestamp with a
/// mismatched version MUST return `SoftwareUpgradeVersionMismatch`
/// and leave the pending entry in place so the next block also halts.
#[test]
fn pending_upgrade_version_mismatch_returns_error() {
    let mut store = StateStore::new();
    let id = TxHash([0x43; 32]);
    store.insert_pending_upgrade(pqc_types::governance::PendingUpgrade {
        proposal_id: id.clone(),
        activate_at_timestamp_ns: 200,
        expected_version: 9,
    });
    let err = check_pending_upgrades(&mut store, 200, 8).expect_err("mismatched version MUST fail");
    assert!(matches!(
        err,
        ApplyError::SoftwareUpgradeVersionMismatch {
            activate_at_timestamp_ns: 200,
            expected_version: 9,
            actual_version: 8,
        }
    ));
    assert_eq!(
        store.pending_upgrades_in_order().len(),
        1,
        "pending upgrade MUST remain — next block will halt again"
    );
}

/// ADR-053 §T2.3: a block landing AFTER the scheduled timestamp
/// activates the upgrade (timestamp-based activation allows
/// catching up when block times stretch under load). A block
/// BEFORE the timestamp leaves the upgrade pending.
#[test]
fn pending_upgrade_activates_when_block_timestamp_exceeds_scheduled() {
    let mut store = StateStore::new();
    let id = TxHash([0x44; 32]);
    store.insert_pending_upgrade(pqc_types::governance::PendingUpgrade {
        proposal_id: id.clone(),
        activate_at_timestamp_ns: 1_000,
        expected_version: 5,
    });

    // Block timestamp BEFORE scheduled activation — upgrade stays pending.
    check_pending_upgrades(&mut store, 500, 5).expect("early block must not fail");
    assert_eq!(
        store.pending_upgrades_in_order().len(),
        1,
        "upgrade MUST remain pending before activation timestamp"
    );

    // Block timestamp well past scheduled activation (network hiccup
    // delayed catch-up) — upgrade activates and clears.
    check_pending_upgrades(&mut store, 5_000, 5).expect("catch-up block must pass");
    assert!(
        store.pending_upgrades_in_order().is_empty(),
        "upgrade MUST clear once block timestamp reaches activation"
    );
}
