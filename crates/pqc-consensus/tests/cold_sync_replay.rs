// SPDX-License-Identifier: BUSL-1.1
//! Cold-sync replay-from-genesis CI harness — Policy P-COMPAT-001 §2(d).
//!
//! ## Why this test exists
//!
//! This is the standing CI invariant required by ADR-052 P-COMPAT-001 rule 2(d)
//! ("a cold-sync integration test that replays from genesis ... and asserts
//! byte-identical `state_root` continuity at every height"). It exists to
//! prevent another rc1-class divergence on the order of the 2026-04-24
//! `viper-devnet-2` incident: a binary built against a new state-root topology
//! was deployed against an older on-disk store, recomputed `state_root` under
//! a different Merkle layout, and the producer halted block production for
//! ~3 minutes while the rolling upgrade was rolled back.
//!
//! ## What this test does
//!
//! 1. Builds a synthetic chain in memory using the *real* `LocalProposer`,
//!    `assemble_block`, `apply_tx`, and `state_root()` code paths — no mocks.
//! 2. After every block it captures `state_root()` and compares it against
//!    a hard-coded vector below. The hex strings are pinned to the values
//!    produced by the current codebase.
//! 3. Replays the captured blocks against a fresh genesis state via
//!    `replay_blocks_from_genesis` and asserts the per-height `state_root`
//!    matches the same pinned vector.
//!
//! ## How to interpret a failure
//!
//! If this test fails, *something changed in the consensus-relevant state
//! encoding or root derivation*. That is exactly what P-COMPAT-001 §2(d) is
//! designed to catch. Three legitimate reactions:
//!
//! - **Intentional change with an ADR + activation height**: update the
//!   pinned `EXPECTED_STATE_ROOTS` in this file in the same commit. The diff
//!   is the human-readable record of which roots changed and how.
//! - **Unintentional change**: investigate. The leaf domain string, sort
//!   order, or hash algorithm probably regressed. Treat as a launch-blocker.
//! - **Refactor that intends to be byte-identical**: do not touch the
//!   pinned values; the failure proves your refactor changed semantics.
//!
//! ## Discipline rules — read before editing
//!
//! - DO NOT mark this test `#[ignore]`. The whole purpose is the always-on
//!   CI guard; a skipped guard is no guard.
//! - DO NOT gate it behind a feature flag. Same reason.
//! - DO NOT mock the state machine. The real `StateStore` is the only thing
//!   whose root we actually care about.
//! - DO NOT introduce `SystemTime::now()`, `rand::thread_rng()`, or any
//!   environment-dependent input. Determinism across machines is a
//!   correctness property, not a nice-to-have.
//!
//! ## Spec references
//!
//! - DECISIONS.md ADR-052 (P-COMPAT-001) — §2(d) cold-sync invariant
//! - DECISIONS.md ADR-053 — state evolution roadmap
//! - SPEC-FEE-002 — fee-market state contributing to the root
//! - PQC-STATE-ROOT-V2 — root derivation algorithm

use ciborium::value::Value;
use pqc_consensus::{
    replay_blocks_from_genesis, AssemblyConfig, ChainStore, LocalProposer, LocalProposerConfig,
};
use pqc_crypto::{sign::StubVerifier, AlgId};
use pqc_mempool::{admission::try_admit, Mempool};
use pqc_state::StateStore;
use pqc_tx::{codec::encode_tx, validate::FeeParams};
use pqc_types::{
    account::{Account, Address},
    block::BlockHash,
    keyset::{allowed_tx, KeyEntry, KeySet, KeyStatus},
    transaction::{MsgType, Transaction},
};

// ── Pinned expected state-root vector ────────────────────────────────────────
//
// One entry per produced block, height-ordered (height 1 first). These hex
// strings are produced by the CURRENT codebase. To regenerate after an
// intentional consensus-affecting change:
//
//   1. Run this test once and observe the `state_root mismatch` failure
//      output, which prints the actual hex.
//   2. Replace the pinned strings below with the actual values.
//   3. Run this test again; it MUST pass.
//   4. Land the diff in the same commit as the change that produced it,
//      with an ADR documenting why the roots moved.
//
// The fixture is intentionally small (2 blocks of mixed-msg-type tx). The
// value here is the *format-pin* — proving the leaf-domain strings, sort
// order, and hash function are stable — not a load-test.
const EXPECTED_STATE_ROOTS: &[&str] = &[
    // height 1 — block with two transfer txs (sender_a -> recipient, sender_b -> recipient)
    // Updated for ADR-053 §T3.5 unified smart-account model (TASK-196) — every
    // account now carries `verifier_template_id` + `auth_data` and those bytes
    // fold into the account leaf hash via PQC-ACCOUNT-LEAF-V1. Updates layered
    // on top of TASK-195's binary Merkle state tree (leaves tagged
    // "VIPER-STATE-LEAF-V1" / branches "VIPER-STATE-BRANCH-V1").
    "a3cb2eaf85ffc6b2ef70f78f7f7bf27b3eb013febf7b7d361cd07d14627d0e79",
    // height 2 — block with attestation_create (by sender_a) + transfer (by sender_b)
    "e71535698a33f07c2fc39126b807f260c4c28d68f813a18b2b1fd593865a3c75",
];

// ── Inline tx/account helpers (deliberately self-contained) ──────────────────
//
// `pqc_consensus::test_support` is `pub(crate)`. Rather than promote it for
// this one harness, we keep the integration test self-contained: it cannot
// regress on internal helper changes, and the helpers below are short
// enough to read at a glance — exactly what you want when triaging a CI
// red on this test in a hurry.

enum CborVal {
    Int(u64),
    Bytes(Vec<u8>),
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
    ciborium::into_writer(&Value::Map(entries), &mut out).expect("cbor encode must succeed");
    out
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

fn transfer_tx(
    sender: Address,
    recipient: Address,
    nonce: u64,
    fee: u64,
    signature_fill: u8,
) -> Transaction {
    let payload = cbor_map(vec![
        (1, CborVal::Bytes(recipient.0.to_vec())),
        (2, CborVal::Int(100)),
    ]);
    Transaction {
        tx_version: 1,
        chain_id: Vec::new(),
        msg_type: MsgType::TokenTransfer,
        sender,
        nonce,
        fee,
        fee_tip: 0,
        gas_limit: 100_000,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![signature_fill; 3_309],
    }
}

fn attestation_create_tx(
    sender: Address,
    nonce: u64,
    fee: u64,
    signature_fill: u8,
    subject: [u8; 32],
    attestation_type: u16,
) -> Transaction {
    let payload = cbor_map(vec![
        (1, CborVal::Bytes(subject.to_vec())),
        (2, CborVal::Int(attestation_type as u64)),
        (3, CborVal::Bytes([0x22; 32].to_vec())),
        (4, CborVal::Bytes([0x33; 32].to_vec())),
    ]);
    Transaction {
        tx_version: 1,
        chain_id: Vec::new(),
        msg_type: MsgType::AttestationCreate,
        sender,
        nonce,
        fee,
        fee_tip: 0,
        gas_limit: 100_000,
        payload,
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

// ── Synthetic chain construction ─────────────────────────────────────────────

/// Build the deterministic 2-block fixture chain.
///
/// Returns `(genesis_state, chain_store, expected_roots_per_height)` so the
/// harness can replay the chain from genesis and cross-check both against
/// the chain-recorded headers and against the pinned vector at the top of
/// this file.
///
/// The fixture covers two distinct `MsgType` variants (TokenTransfer and
/// AttestationCreate) so a regression to either the account-leaf path or
/// the attestation-leaf path is caught. Every other state-root contributor
/// (algorithm registry, hash registry, fee market, storage fund, slashing
/// registry) is exercised at the genesis layer because `StateStore::new`
/// seeds them.
fn build_fixture_chain() -> (StateStore, ChainStore, Vec<BlockHash>) {
    let sender_a = Address([0xA1; 32]);
    let sender_b = Address([0xB2; 32]);
    let recipient = Address([0x11; 32]);
    let attestation_subject = [0x77u8; 32];

    let mut genesis_state = StateStore::new();
    genesis_state.insert_account(signer_account(
        sender_a.clone(),
        1_000_000,
        0,
        AlgId::MlDsa65,
    ));
    genesis_state.insert_account(signer_account(
        sender_b.clone(),
        1_000_000,
        0,
        AlgId::MlDsa65,
    ));

    let mut live_state = genesis_state.clone();
    let mut pool = Mempool::new();
    let mut proposer = LocalProposer::new(
        [0x99; 32],
        LocalProposerConfig {
            assembly: AssemblyConfig::default(),
            initial_prev_hash: BlockHash([0x11; 32]),
        },
    );
    let mut chain = ChainStore::new(BlockHash([0x11; 32]));
    let mut roots = Vec::new();

    // ── Block 1: two transfers from distinct senders ─────────────────────────
    // Why two senders: forces the account-leaf sort order to be exercised
    // (one address < the other), which would silently pass with one tx.
    let tx_a = transfer_tx(sender_a.clone(), recipient.clone(), 0, 100, 0x01);
    let tx_b = transfer_tx(sender_b.clone(), recipient.clone(), 0, 100, 0x02);
    admit(&mut pool, &live_state, &tx_a);
    admit(&mut pool, &live_state, &tx_b);
    let result_1 = proposer
        .run_once(&mut live_state, &mut pool, 1_710_000_000)
        .expect("block 1 assembly must succeed");
    chain
        .append_block(&result_1)
        .expect("append 1 must succeed");
    roots.push(result_1.state_root.clone());

    // ── Block 2: one attestation + one transfer ──────────────────────────────
    // Why mixed: exercises a non-account leaf group and ensures the leaf
    // sort key for `AttestationId` is reached.
    let tx_att = attestation_create_tx(sender_a.clone(), 1, 100, 0x03, attestation_subject, 0x0002);
    let tx_c = transfer_tx(sender_b, recipient, 1, 100, 0x04);
    admit(&mut pool, &live_state, &tx_att);
    admit(&mut pool, &live_state, &tx_c);
    let result_2 = proposer
        .run_once(&mut live_state, &mut pool, 1_710_000_001)
        .expect("block 2 assembly must succeed");
    chain
        .append_block(&result_2)
        .expect("append 2 must succeed");
    roots.push(result_2.state_root.clone());

    (genesis_state, chain, roots)
}

// ── The harness test ────────────────────────────────────────────────────────

/// Cold-sync replay test enforcing P-COMPAT-001 §2(d).
///
/// Three independent assertions run together:
///
/// 1. **Live-assembled vs. pinned** — every block the proposer produces
///    must hash to a pinned `EXPECTED_STATE_ROOTS` value. Catches a change
///    to the on-mutation root computation path.
/// 2. **Replay vs. live** — replaying the captured blocks from a fresh
///    genesis state through `replay_blocks_from_genesis` must reproduce
///    the same per-height roots. Catches replay/live divergence, which
///    is the exact 2026-04-24 incident shape.
/// 3. **Tip continuity** — the final replayed `state_root` must equal the
///    chain's tip header `state_root`. Belt-and-braces: the previous two
///    checks already imply this, but this assertion is what an operator
///    actually runs at `replay_from_disk` time, so we verify the
///    operator-facing invariant directly.
#[test]
fn cold_sync_replay_from_genesis_matches_committed_roots() {
    let (genesis_state, chain, live_roots) = build_fixture_chain();

    // ── Assertion 1: live roots match the pinned vector ──────────────────────
    // Debug aid (only printed when running with --nocapture): list the actual
    // roots so an operator regenerating the pin can copy them straight from
    // the test output.
    for (i, r) in live_roots.iter().enumerate() {
        eprintln!(
            "[cold-sync] height {} live root = {}",
            i + 1,
            hex::encode(r.0)
        );
    }
    assert_eq!(
        live_roots.len(),
        EXPECTED_STATE_ROOTS.len(),
        "fixture produced {} blocks but EXPECTED_STATE_ROOTS has {} entries — \
         update the pinned vector to match the fixture",
        live_roots.len(),
        EXPECTED_STATE_ROOTS.len(),
    );
    for (i, (actual, expected_hex)) in live_roots.iter().zip(EXPECTED_STATE_ROOTS).enumerate() {
        let actual_hex = hex::encode(actual.0);
        assert_eq!(
            actual_hex,
            *expected_hex,
            "live state_root at height {} diverges from pinned value.\n\
             expected: {}\n\
             actual:   {}\n\
             If this divergence is intentional (you landed an ADR + activation \
             height per P-COMPAT-001 §2(b)/(c)), update EXPECTED_STATE_ROOTS in \
             this file in the same commit. If unintentional, your change \
             altered consensus-relevant state encoding — treat as a \
             launch-blocker per P-COMPAT-001 §2(d).",
            i + 1,
            expected_hex,
            actual_hex,
        );
    }

    // ── Assertion 2: replay-from-genesis reproduces the same per-height roots
    let blocks: Vec<_> = chain.blocks_in_order().into_iter().cloned().collect();
    let replay = replay_blocks_from_genesis(
        &genesis_state,
        chain.anchor_prev_hash(),
        &blocks,
        FeeParams::default(),
        Default::default(),
        Vec::new(),
    )
    .expect("cold-sync replay from genesis must succeed");

    // After a successful replay, the per-height roots are implicitly
    // verified by `replay_blocks_from_state` itself (it errors with
    // `StateRootMismatch` on the first divergence). The next assertion
    // pins the final tip-root for an extra layer of safety.
    let expected_tip_hex = EXPECTED_STATE_ROOTS
        .last()
        .expect("EXPECTED_STATE_ROOTS must be non-empty");
    let replay_tip_hex = hex::encode(replay.state_root.0);
    assert_eq!(
        replay_tip_hex, *expected_tip_hex,
        "replayed tip state_root does not match the pinned tip value.\n\
         expected: {expected_tip_hex}\n\
         actual:   {replay_tip_hex}\n\
         This means replay diverged from live assembly — exactly the \
         2026-04-24 rc1 failure shape. Investigate immediately.",
    );

    // ── Assertion 3: replayed tip matches the chain-recorded tip header ──────
    let chain_tip_root = chain
        .tip()
        .expect("chain must have a tip after appending blocks")
        .metadata
        .state_root
        .clone();
    assert_eq!(
        replay.state_root, chain_tip_root,
        "replayed state_root does not match the tip header — \
         the chain store and the replay would disagree on the live root \
         (this is the operator-facing invariant)."
    );
    assert_eq!(
        replay.height,
        live_roots.len() as u64,
        "replay produced {} heights, fixture produced {}",
        replay.height,
        live_roots.len()
    );
}
