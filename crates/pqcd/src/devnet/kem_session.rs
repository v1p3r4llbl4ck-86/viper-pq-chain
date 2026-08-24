// SPDX-License-Identifier: BUSL-1.1
//! ML-KEM-768 session crypto for the devnet HTTP P2P channel.
//!
//! Extracted from `devnet.rs` 2026-05-10 as part of the M-effort split
//! (CONCERNS.md "[MEDIUM] crates/pqcd/src/devnet.rs is 7,247 lines").
//! Self-contained: depends only on `pqc_crypto` primitives, the
//! returned types (`KemKeyMaterial`, `KemKeyset`, `KemDecapResult`)
//! are consumed by `LiveNodeState` initialisation, the epoch-boundary
//! rotation code, and the `handle_p2p_*` HTTP handlers in the parent
//! module.
//!
//! See the private design notes "Gap B" and
//! `PHASE-4-KEY-ROTATION-RESEARCH.md` §2 for the design rationale —
//! the public-from-public bug and the Strategy 1 + salt closure.

use pqc_crypto::{kem_decapsulate, kem_generate, shake256_32, KemSeed, KEM_CT_LEN, KEM_PK_LEN};

/// ML-KEM-768 long-term identity-keypair material for the devnet HTTP P2P
/// session-bootstrap channel — see `CONCERNS-DECISIONS.md` "Gap B" and
/// `PHASE-4-KEY-ROTATION-RESEARCH.md` §2 (Strategy 1 + salt).
///
/// Carries the 1184-byte encapsulation key alongside the 64-byte FIPS 203
/// `d || z` decapsulation seed (wrapped in `KemSeed` for `ZeroizeOnDrop`)
/// and the chain-aligned `epoch_number` the keypair was derived for. The
/// epoch tag is used by the grace-window logic in `KemKeyset` so log lines
/// can report which epoch's secret decapsulated a session.
pub(super) struct KemKeyMaterial {
    pub(super) pk: [u8; KEM_PK_LEN],
    pub(super) sk: KemSeed,
    pub(super) epoch_number: u64,
}

/// Atomic-swap wrapper around the active and previous-epoch ML-KEM keypairs.
///
/// `current` is what new sessions encapsulate against (served by
/// `handle_p2p_kem_pubkey`). `previous` is retained for the grace-window
/// length so a session whose ciphertext was sent against the just-rotated
/// pk still validates after the boundary. Retirement is triggered by
/// `KemKeyset::rotate_to_epoch` whenever the `current_height` exceeds
/// `previous_retire_height`.
///
/// One full epoch of grace is intentional — it matches the cadence at which
/// follower nodes refresh sessions in steady state. Shorter grace would
/// briefly lock peers out across the boundary; longer grace would extend
/// the exposure window of a now-stale secret without functional benefit.
pub(super) struct KemKeyset {
    pub(super) current: KemKeyMaterial,
    /// Previous epoch's keypair, retained for the grace window. Tuple
    /// member 1 is the height at which `previous` becomes eligible to
    /// drop; the next call to `rotate_to_epoch` whose `current_height`
    /// exceeds this value will free the slot.
    pub(super) previous: Option<(KemKeyMaterial, u64)>,
}

impl KemKeyset {
    pub(super) fn new(current: KemKeyMaterial) -> Self {
        Self {
            current,
            previous: None,
        }
    }

    /// Rotate to a freshly-derived keypair for `new_epoch`, retaining
    /// the prior `current` as `previous` for the grace window
    /// (`current_height + epoch_duration`).
    ///
    /// No-op if `new_material.epoch_number == self.current.epoch_number`
    /// — calling this on every block would otherwise re-rotate at the
    /// boundary block itself. The producer/consensus loops gate the call
    /// with `is_epoch_boundary` so this is defence-in-depth.
    pub(super) fn rotate_to(
        &mut self,
        new_material: KemKeyMaterial,
        current_height: u64,
        epoch_duration: u64,
    ) {
        if new_material.epoch_number == self.current.epoch_number {
            return;
        }
        // Drop a stale previous entry if its retire height has passed.
        // This is a cheap second-line defence on top of the boundary gate
        // — the new boundary always replaces `previous` with the just-
        // rotated `current` anyway, but if rotate_to ever gets called
        // off-boundary (test fixtures, future code path), the bound on
        // `previous` lifetime is still the documented one.
        if let Some((_, retire_height)) = &self.previous {
            if current_height >= *retire_height {
                self.previous = None;
            }
        }
        let retire_at = current_height.saturating_add(epoch_duration);
        let prior = std::mem::replace(&mut self.current, new_material);
        self.previous = Some((prior, retire_at));
    }

    /// Decapsulate `ct` and return one or two `(shared_secret, epoch_number,
    /// session_id)` triples — current first, previous second when the grace
    /// window is open.
    ///
    /// The grace-window semantics for the devnet HTTP P2P channel are
    /// asymmetric:
    ///
    /// - **Already-established sessions** (entries in `p2p_sessions`)
    ///   are unaffected by rotation; the session_id → shared_secret
    ///   map persists. The "grace" for them is structurally infinite
    ///   (until process restart). No code change needed.
    ///
    /// - **New session establishment** that races a rotation: peer
    ///   may have fetched the pre-rotation pk, encapsulated against
    ///   it, then sent the ciphertext post-rotation. Decap with
    ///   `current.sk` returns ML-KEM implicit-rejection garbage in
    ///   that case; decap with `previous.sk` returns the peer's actual
    ///   shared secret. We populate `p2p_sessions` with **both** decap
    ///   outputs so whichever ciphertext the peer sent, the resulting
    ///   session_id is registered. We return the current-epoch
    ///   session_id in the HTTP response — peers in this codebase
    ///   trust the response session_id, so a previous-pk encap will
    ///   visibly fail and the peer must retry with a refreshed pk.
    ///
    /// The dual-insert path is defence-in-depth: it costs ~1 ms of
    /// extra ML-KEM decap on a path that runs once per peer per
    /// session, and it produces an audit-trail entry under
    /// `previous.epoch_number` if any caller does manage to use the
    /// previous-pk-derived session_id (e.g. an out-of-band protocol
    /// extension we have not yet implemented).
    ///
    /// In the non-rotating (legacy) deployment, `previous` is always
    /// `None` and this collapses to a single decap call.
    pub(super) fn decapsulate_all(
        &self,
        ct: &[u8; KEM_CT_LEN],
        current_height: u64,
    ) -> Vec<KemDecapResult> {
        let mut out = Vec::with_capacity(2);

        // Always run current-epoch decap first — this is the result
        // that gets returned in the response.
        let ss_current = kem_decapsulate(self.current.sk.as_bytes(), ct);
        out.push(KemDecapResult {
            shared_secret: ss_current,
            epoch_number: self.current.epoch_number,
        });

        if let Some((prev, retire_height)) = &self.previous {
            if current_height < *retire_height {
                let ss_previous = kem_decapsulate(prev.sk.as_bytes(), ct);
                out.push(KemDecapResult {
                    shared_secret: ss_previous,
                    epoch_number: prev.epoch_number,
                });
            }
        }
        out
    }
}

/// One candidate `(shared_secret, epoch_number)` from a KEM decap. Returned
/// by `KemKeyset::decapsulate_all` so the session-establishment handler can
/// register both current- and previous-epoch session_ids (grace-window) in
/// the active session map.
pub(super) struct KemDecapResult {
    pub(super) shared_secret: [u8; 32],
    pub(super) epoch_number: u64,
}

/// Derive a 1184-byte ML-KEM-768 encapsulation key + 64-byte FIPS 203 seed
/// from `(node_id, secret_salt, epoch_number)`.
///
/// Closes Gap B from the private design notes and
/// implements Strategy 1 + salt from `PHASE-4-KEY-ROTATION-RESEARCH.md`
/// §2.4. The combination of (public node_id, secret salt, public epoch)
/// makes the keypair unrecoverable by an attacker who only knows the
/// public inputs — closing the public-from-public bug.
///
/// `secret_salt` is `Some(32 bytes)` when `node.json` carries a populated
/// `kem_seed_salt_hex`; `None` for legacy back-compat where derivation
/// falls back to the `node_id`-only path with a startup `warn!`.
pub(super) fn derive_kem_keypair(
    node_id: &str,
    secret_salt: Option<&[u8; 32]>,
    epoch_number: u64,
) -> KemKeyMaterial {
    let (kem_d, kem_z) = match secret_salt {
        Some(salt) => {
            // Strategy 1 + salt: SHAKE-256(node_id || salt || domain || epoch_be).
            // The `-kem-d-` / `-kem-z-` domain separators ensure d and z are
            // independent 32-byte seeds for the FIPS 203 §5.1 keygen; both
            // domain strings are hyphen-suffixed so an epoch boundary
            // produces a fully-fresh derivation pair.
            let kem_d = shake256_32(
                &[
                    node_id.as_bytes(),
                    salt.as_slice(),
                    b"-kem-d-",
                    &epoch_number.to_be_bytes(),
                ]
                .concat(),
            );
            let kem_z = shake256_32(
                &[
                    node_id.as_bytes(),
                    salt.as_slice(),
                    b"-kem-z-",
                    &epoch_number.to_be_bytes(),
                ]
                .concat(),
            );
            (kem_d, kem_z)
        }
        None => {
            // Legacy back-compat path — public-from-public. A startup
            // `warn!` flags the residual exposure (see Gap B). Retained
            // so existing tests + a 3-node devnet running pre-fix
            // node.json still boots without operator action; not the
            // recommended steady state.
            let kem_d = shake256_32(&[node_id.as_bytes(), b"-kem-d"].concat());
            let kem_z = shake256_32(&[node_id.as_bytes(), b"-kem-z"].concat());
            (kem_d, kem_z)
        }
    };
    let (pk, sk) = kem_generate(&kem_d, &kem_z);
    KemKeyMaterial {
        pk,
        sk,
        epoch_number,
    }
}

#[cfg(test)]
mod kem_rotation_tests;
