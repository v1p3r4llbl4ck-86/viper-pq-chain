// SPDX-License-Identifier: BUSL-1.1
//! Tests for `kem_session`.
//!
//! Extracted from `kem_session.rs` 2026-05-10. `use super::*;`
//! brings every private item from the parent module into scope.

//! Tests for the Gap B fix — `PHASE-4-KEY-ROTATION-RESEARCH.md` §2.4
//! and §2.6. Pure unit tests; no I/O, no tokio runtime.
//!
//! Test surface (mapped to the §2.6 list):
//!  - `kem_keypair_changes_per_epoch` — derive at epoch K and K+1,
//!    assert pk and sk seed differ.
//!  - `kem_keypair_with_different_salt_differs` — same node_id +
//!    same epoch + two different salts → different pk.
//!  - `kem_keypair_without_salt_falls_back_to_legacy` — `None` salt
//!    reproduces the legacy `node_id`-only derivation; identical
//!    output for the same node_id, regardless of epoch (the legacy
//!    path is non-rotating, intentionally — back-compat for nodes
//!    that have not yet run `pqcd wallet kem-init`).
//!  - `kem_session_grace_window_accepts_previous_epoch_keypair` —
//!    KemKeyset rotated to a new epoch decapsulates a ciphertext
//!    that was encapsulated against the previous-epoch pk, until
//!    the retire height passes.
//!  - `kem_keyset_rotate_to_drops_stale_previous_after_retire` —
//!    once `current_height` exceeds `previous`'s retire_height, the
//!    grace window closes; previous-epoch ciphertexts no longer
//!    decapsulate via `decapsulate_all`.
use super::*;
use pqc_crypto::kem_encapsulate;

/// Two epochs, same node_id, same salt → distinct keypairs. The
/// behavioural promise of Strategy 1: rotation per epoch boundary.
#[test]
fn kem_keypair_changes_per_epoch() {
    let node_id = "validator-1";
    let salt: [u8; 32] = [0xA1; 32];

    let m_e10 = derive_kem_keypair(node_id, Some(&salt), 10);
    let m_e11 = derive_kem_keypair(node_id, Some(&salt), 11);

    assert_ne!(
        m_e10.pk, m_e11.pk,
        "ML-KEM pk MUST differ across epochs — rotation precondition"
    );
    assert_ne!(
        m_e10.sk.as_bytes(),
        m_e11.sk.as_bytes(),
        "ML-KEM sk seed MUST differ across epochs"
    );
    assert_eq!(m_e10.epoch_number, 10);
    assert_eq!(m_e11.epoch_number, 11);
}

/// Same node_id + same epoch + different salt → different keypair.
/// The behavioural promise of secret-salt: the "public-from-public"
/// recompute attack is closed, because an attacker who only knows
/// node_id + epoch cannot reproduce the keypair without the salt.
#[test]
fn kem_keypair_with_different_salt_differs() {
    let node_id = "validator-1";
    let salt_a: [u8; 32] = [0x01; 32];
    let salt_b: [u8; 32] = [0x02; 32];

    let m_a = derive_kem_keypair(node_id, Some(&salt_a), 7);
    let m_b = derive_kem_keypair(node_id, Some(&salt_b), 7);

    assert_ne!(
        m_a.pk, m_b.pk,
        "ML-KEM pk MUST differ across salts — closes Gap B's \
         public-from-public derivation bug"
    );
    assert_ne!(
        m_a.sk.as_bytes(),
        m_b.sk.as_bytes(),
        "ML-KEM sk seed MUST differ across salts"
    );
}

/// Legacy fallback path: `None` salt MUST reproduce the pre-fix
/// derivation. Two derivations with the same node_id but different
/// epoch_number under `None` MUST be IDENTICAL because the legacy
/// path doesn't include epoch_number — by design (back-compat for
/// nodes that have not yet run `pqcd wallet kem-init`).
///
/// This is the back-compat invariant: existing node.json files
/// without `kem_seed_salt_hex` keep producing the same key on
/// restart, just like before. The startup `warn!` path flags the
/// residual exposure but does not change behaviour.
#[test]
fn kem_keypair_without_salt_falls_back_to_legacy() {
    let node_id = "validator-1";

    // Legacy derivation under no salt at two different epochs:
    // identical output. (Pre-Gap-B: derivation = SHAKE-256(node_id
    // || "-kem-d") — no epoch input.)
    let m_e10 = derive_kem_keypair(node_id, None, 10);
    let m_e11 = derive_kem_keypair(node_id, None, 11);
    assert_eq!(
        m_e10.pk, m_e11.pk,
        "legacy back-compat path MUST be epoch-invariant — \
         pre-fix node.json files produce the same key on every restart"
    );
    assert_eq!(m_e10.sk.as_bytes(), m_e11.sk.as_bytes());

    // Legacy with salt-None vs salt-Some at the same node_id:
    // different outputs (proves the salt path actually salts).
    let salt: [u8; 32] = [0xCC; 32];
    let m_legacy = derive_kem_keypair(node_id, None, 0);
    let m_salted = derive_kem_keypair(node_id, Some(&salt), 0);
    assert_ne!(
        m_legacy.pk, m_salted.pk,
        "salt MUST be a non-trivial input to the derivation"
    );
}

/// KemKeyset retains the previous-epoch keypair across a rotation.
/// A ciphertext encapsulated against `previous.pk` decapsulates to
/// the same shared secret as the encapsulation produced — i.e. the
/// grace window functionally accepts pre-rotation ciphertexts.
#[test]
fn kem_session_grace_window_accepts_previous_epoch_keypair() {
    let node_id = "validator-2";
    let salt: [u8; 32] = [0x44; 32];
    let epoch_duration = 60u64;

    // Build a keyset at epoch K-1 (epoch=10).
    let m_prev = derive_kem_keypair(node_id, Some(&salt), 10);
    let prev_pk = m_prev.pk;

    let mut keyset = KemKeyset::new(m_prev);
    // Rotate to epoch K (epoch=11) at a hypothetical block height
    // 660 (epoch 11 starts at 11 * 60 = 660). The previous keypair
    // slides into `previous` with retire_height = 660 + 60 = 720.
    let m_curr = derive_kem_keypair(node_id, Some(&salt), 11);
    keyset.rotate_to(m_curr, 660, epoch_duration);

    // Sanity: previous slot is populated, current is the new one.
    assert!(
        keyset.previous.is_some(),
        "after rotate_to, previous MUST be populated for grace window"
    );
    assert_eq!(keyset.current.epoch_number, 11);

    // Encapsulate against the PREVIOUS pk (simulating a peer that
    // raced the rotation: fetched pk before, sent ciphertext after).
    let mut rand_bytes = [0u8; 32];
    // Deterministic seed for reproducibility — getrandom is not
    // necessary here because we're testing the decap, not the RNG.
    for (i, b) in rand_bytes.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(17);
    }
    let (ct, peer_shared_secret) =
        kem_encapsulate(&prev_pk, &rand_bytes).expect("KEM encap against previous.pk");

    // Decapsulate via the keyset at a height inside the grace
    // window (current_height = 700, well below retire_height = 720).
    let candidates = keyset.decapsulate_all(&ct, 700);
    assert_eq!(
        candidates.len(),
        2,
        "grace window open: must yield current + previous candidates"
    );

    // Exactly ONE of the two candidates MUST match the peer's
    // encap shared_secret — the previous-epoch one. The current-
    // epoch decap returns implicit-rejection garbage for this
    // ciphertext.
    let prev_match = candidates
        .iter()
        .find(|c| c.shared_secret == peer_shared_secret);
    assert!(
        prev_match.is_some(),
        "previous-epoch decap MUST recover the peer's shared_secret \
         — grace window functionally validates pre-rotation ciphertexts"
    );
    assert_eq!(
        prev_match.unwrap().epoch_number,
        10,
        "the matching candidate MUST be tagged with the previous epoch number"
    );
}

/// Once the grace-window retire height passes, `decapsulate_all`
/// returns ONLY the current-epoch candidate even though
/// `previous` is still occupied. This pins the documented
/// retire-height behaviour without requiring an explicit drop.
///
/// Drop happens at the NEXT `rotate_to` call; the slot is
/// retained as `Some` until then. The retire-height check inside
/// `decapsulate_all` is the runtime-effective gate that closes
/// the grace window.
#[test]
fn kem_keyset_decap_closes_after_retire_height() {
    let node_id = "validator-3";
    let salt: [u8; 32] = [0x55; 32];
    let epoch_duration = 60u64;

    // Same setup as the previous test.
    let m_prev = derive_kem_keypair(node_id, Some(&salt), 10);
    let prev_pk = m_prev.pk;
    let mut keyset = KemKeyset::new(m_prev);
    let m_curr = derive_kem_keypair(node_id, Some(&salt), 11);
    keyset.rotate_to(m_curr, 660, epoch_duration);

    // Encap against previous.pk.
    let mut rand_bytes = [0u8; 32];
    for (i, b) in rand_bytes.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(13);
    }
    let (ct, peer_shared_secret) =
        kem_encapsulate(&prev_pk, &rand_bytes).expect("KEM encap against previous.pk");

    // current_height = 720 = retire_height — exactly at the edge.
    // Implementation detail: `current_height < *retire_height` is
    // the gate, so 720 < 720 is false → grace window closed.
    let candidates_at_edge = keyset.decapsulate_all(&ct, 720);
    assert_eq!(
        candidates_at_edge.len(),
        1,
        "at retire_height, only current-epoch candidate yields"
    );
    // The single candidate MUST NOT match peer_shared_secret
    // (current.sk decapped a ciphertext encrypted under a different
    // pk — implicit-rejection output).
    assert_ne!(
        candidates_at_edge[0].shared_secret, peer_shared_secret,
        "current-epoch decap of previous-pk-encap MUST yield \
         implicit-rejection garbage, NOT the peer's actual shared_secret"
    );

    // current_height = 999 — well past retire. Same outcome.
    let candidates_late = keyset.decapsulate_all(&ct, 999);
    assert_eq!(candidates_late.len(), 1);
}

/// Exhaustive: salt-collision check. Different node_ids with the
/// same salt + same epoch MUST produce different keypairs. This
/// was implicit in the salted derivation but is worth pinning so a
/// future refactor that drops node_id from the input would fail
/// loudly (e.g. someone "simplifying" to `salt || epoch`).
#[test]
fn kem_keypair_with_different_node_ids_differs() {
    let salt: [u8; 32] = [0x77; 32];
    let m1 = derive_kem_keypair("validator-1", Some(&salt), 5);
    let m2 = derive_kem_keypair("validator-2", Some(&salt), 5);
    assert_ne!(
        m1.pk, m2.pk,
        "node_id MUST be a non-trivial input to the derivation"
    );
}
