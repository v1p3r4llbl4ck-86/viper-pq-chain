// SPDX-License-Identifier: BUSL-1.1
//! Tests for `p2p`.
//!
//! Extracted from `p2p.rs` 2026-05-10. `use super::*;`
//! brings every private item from the parent module into scope.

use super::*;
use pqc_p2p::Keypair;

fn fresh_peer() -> PeerId {
    PeerId::from(Keypair::generate_ed25519().public())
}

#[test]
fn empty_allow_list_admits_everything() {
    let allow: HashSet<PeerId> = HashSet::new();
    // Opt-in semantics per ADR-041 addendum: the allow-list is
    // empty on devnet-2 pre-M2 and the check must not fire.
    assert!(is_tx_admitted(&Some(fresh_peer()), &allow));
    assert!(is_tx_admitted(&None, &allow));
}

#[test]
fn populated_allow_list_rejects_outsider_peer_id() {
    let mut allow = HashSet::new();
    allow.insert(fresh_peer());
    let outsider = fresh_peer();
    assert!(!is_tx_admitted(&Some(outsider), &allow));
}

#[test]
fn populated_allow_list_rejects_anonymous_source() {
    let mut allow = HashSet::new();
    allow.insert(fresh_peer());
    assert!(
        !is_tx_admitted(&None, &allow),
        "anonymous (source=None) Transaction must be rejected when \
         the binding check is active — gossipsub Signed authenticity \
         is load-bearing here (SPEC-P2P-002 §4.4)"
    );
}

#[test]
fn populated_allow_list_admits_listed_peer() {
    let insider = fresh_peer();
    let mut allow = HashSet::new();
    allow.insert(insider);
    assert!(is_tx_admitted(&Some(insider), &allow));
}

// ── Stage A.1 — salt seam on `derive_keypair` ─────────────────────
// Regression guards for the `libp2p_seed_salt_hex` rotation seam
// scoped in the private design notes.
// The on-chain `ValidatorPeerId` bindings on viper-pq-1 were computed
// with the legacy (no-salt) path, so the `None` branch MUST stay
// byte-stable; the `Some(_)` branch MUST diverge so the rotation
// mechanism actually rotates.

#[test]
fn deterministic_peer_id_is_stable_across_calls_legacy_path() {
    let a = deterministic_peer_id("validator-1", None);
    let b = deterministic_peer_id("validator-1", None);
    assert_eq!(
        a, b,
        "legacy (no-salt) derivation MUST be deterministic — viper-pq-1's \
         on-chain ValidatorPeerId bindings depend on this",
    );
}

#[test]
fn deterministic_peer_id_is_stable_across_calls_salted_path() {
    let salt = [0x11u8; 32];
    let a = deterministic_peer_id("validator-1", Some(&salt));
    let b = deterministic_peer_id("validator-1", Some(&salt));
    assert_eq!(
        a, b,
        "salted derivation MUST be deterministic given the same salt"
    );
}

#[test]
fn salt_seam_changes_peer_id() {
    let legacy = deterministic_peer_id("validator-1", None);
    let salted = deterministic_peer_id("validator-1", Some(&[0x11u8; 32]));
    assert_ne!(
        legacy, salted,
        "adding a salt MUST change the derived PeerId — otherwise the \
         rotation mechanism is a no-op",
    );
}

#[test]
fn different_salts_give_different_peer_ids() {
    let s1 = deterministic_peer_id("validator-1", Some(&[0x11u8; 32]));
    let s2 = deterministic_peer_id("validator-1", Some(&[0x22u8; 32]));
    assert_ne!(
        s1, s2,
        "each salt rotation MUST produce a fresh PeerId so quarterly \
         rotations don't accidentally re-collide",
    );
}

#[test]
fn different_node_ids_give_different_peer_ids_under_same_salt() {
    let salt = [0x11u8; 32];
    let v1 = deterministic_peer_id("validator-1", Some(&salt));
    let v2 = deterministic_peer_id("validator-2", Some(&salt));
    assert_ne!(
        v1, v2,
        "salt does not collapse the node_id dimension — two validators \
         sharing a salt (which they would not, but defensively) still \
         derive distinct PeerIds",
    );
}

// ── Stage A.2 — known-input pin tests ─────────────────────────────
// Byte-stability regression guards. If any of these strings change,
// either (a) the derivation algorithm has drifted (breaks viper-pq-1
// peer admission), or (b) someone re-pinned intentionally and these
// constants need updating along with a SoftwareUpgrade activation
// height. Either way the failure must be visible in code review.

/// viper-pq-1's `validator-1` PeerId in the operator-supplied
/// `libp2p.validator_peer_ids` allow-list. Captured 2026-05-11 from
/// `target/release/pqcd peer-id validator-1` after Stage A.1 landed
/// (commit `0df4ff39`). DO NOT change this constant unless every
/// operator's node.json is migrated in lockstep — the chain's peer
/// admission depends on byte-stable derivation here.
const VALIDATOR_1_LEGACY_PEER_ID: &str = "12D3KooWM4udo5S4t4v1WWQ31gFPoAC9pXubQGaCbncW17KCv5nk";

#[test]
fn legacy_peer_id_for_validator_1_is_pinned() {
    let pid = deterministic_peer_id("validator-1", None);
    assert_eq!(
        pid.to_string(),
        VALIDATOR_1_LEGACY_PEER_ID,
        "viper-pq-1 allow-list pin drift — see comment on \
         VALIDATOR_1_LEGACY_PEER_ID",
    );
}

#[test]
fn salted_peer_id_for_validator_1_pins_to_known_value_aa() {
    // (node_id="validator-1", salt=[0xAA; 32]) → known PeerId.
    // Captured 2026-05-11 from a release-build smoke run of
    // `pqcd peer-id validator-1 --salt aa..aa`.
    let pid = deterministic_peer_id("validator-1", Some(&[0xAAu8; 32]));
    assert_eq!(
        pid.to_string(),
        "12D3KooWPJpRvvFERHPR1sJ1z1B2YR3PJHDFRKMDhc73Xs6PzJjE",
        "salted derivation drift — two binaries that disagree on this \
         value cannot interop because peer admission resolves the \
         operator-rotated PeerId to a different multihash",
    );
}

#[test]
fn salted_peer_id_for_validator_1_pins_to_known_value_11() {
    // Independent pin with a different salt, to catch the case where
    // the salt input is silently ignored (would make both pins coincide
    // with the legacy one).
    let pid = deterministic_peer_id("validator-1", Some(&[0x11u8; 32]));
    assert_eq!(
        pid.to_string(),
        "12D3KooW9qardPJa23wxxqU4UnUHLtr61MEvW9BBPs1g59ayLq3x",
    );
}

// ── TASK-135 step 11: height-gap classification ───────────────────

#[test]
fn classify_inbound_height_behind_when_below_tip() {
    assert_eq!(
        classify_inbound_height(10, 5),
        BlockInboundClass::Behind,
        "received height strictly below tip must be Behind (dedup)"
    );
}

#[test]
fn classify_inbound_height_behind_at_tip() {
    assert_eq!(
        classify_inbound_height(10, 10),
        BlockInboundClass::Behind,
        "received height equal to tip is already on-chain — Behind"
    );
}

#[test]
fn classify_inbound_height_next_when_exactly_one_ahead() {
    assert_eq!(
        classify_inbound_height(10, 11),
        BlockInboundClass::Next,
        "tip+1 is the next expected block — no gap"
    );
}

#[test]
fn classify_inbound_height_gap_of_one_when_two_ahead() {
    assert_eq!(
        classify_inbound_height(10, 12),
        BlockInboundClass::Gap { ahead_by: 1 },
        "tip+2 means exactly one block missing between us and sender"
    );
}

#[test]
fn classify_inbound_height_gap_large_offset() {
    assert_eq!(
        classify_inbound_height(10, 1_000),
        BlockInboundClass::Gap { ahead_by: 989 },
    );
}

#[test]
fn classify_inbound_height_from_genesis() {
    // Cold-start edge case: local tip is 0 and first gossip block is
    // height 1 — must classify as Next, not Gap.
    assert_eq!(classify_inbound_height(0, 1), BlockInboundClass::Next,);
}

// ── TASK-179: envelope↔topic binding (SPEC-P2P-002 §4.2) ──────────

#[test]
fn expected_topic_matches_topics_for_chain_table() {
    // Mirrors the §4.3 table: each MessageType has exactly one
    // canonical topic string derived from Topics::for_chain.
    let cid = "viper-devnet-3";
    assert_eq!(
        expected_topic_for(cid, MessageType::Block),
        format!("/viper/{cid}/blocks/1.0.0"),
    );
    assert_eq!(
        expected_topic_for(cid, MessageType::ConsensusVote),
        format!("/viper/{cid}/consensus/votes/1.0.0"),
    );
    assert_eq!(
        expected_topic_for(cid, MessageType::Transaction),
        format!("/viper/{cid}/mempool/txs/1.0.0"),
    );
    assert_eq!(
        expected_topic_for(cid, MessageType::ValidatorUpdate),
        format!("/viper/{cid}/validators/updates/1.0.0"),
    );
}

#[test]
fn envelope_matches_topic_accepts_aligned_pair() {
    let cid = "viper-devnet-3";
    let msg = GossipMessage::new(MessageType::Transaction, cid, vec![0u8; 1]);
    assert!(envelope_matches_topic(
        &msg,
        &format!("/viper/{cid}/mempool/txs/1.0.0"),
    ));
}

#[test]
fn envelope_matches_topic_rejects_cross_topic_publish() {
    // A Transaction envelope arriving on the blocks topic is the
    // canonical §4.2 failure case — must be rejected.
    let cid = "viper-devnet-3";
    let msg = GossipMessage::new(MessageType::Transaction, cid, vec![0u8; 1]);
    assert!(!envelope_matches_topic(
        &msg,
        &format!("/viper/{cid}/blocks/1.0.0"),
    ));
}

#[test]
fn envelope_matches_topic_rejects_wrong_chain_id() {
    // chain_id mismatch is also a mismatch: a frame claiming
    // chain-a on a chain-b topic must be dropped.
    let msg = GossipMessage::new(MessageType::Block, "chain-a", vec![0u8; 1]);
    assert!(!envelope_matches_topic(&msg, "/viper/chain-b/blocks/1.0.0",));
}
