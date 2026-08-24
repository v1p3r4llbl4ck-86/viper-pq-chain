// SPDX-License-Identifier: Apache-2.0
//! Sync-committee + compact-header scaffolding — SPEC-LIGHT-CLIENT-001
//! (ADR-053 §T3.6, TASK-197 / TASK-207).
//!
//! Purpose: a 2046 verifier of a 2026 attestation MUST be able to verify
//! without full-syncing 20 years of chain history. The light-client
//! protocol commits the launch chain to a small **sync committee** that
//! signs compact-header attestations every epoch; future light-verifier
//! clients follow finality through these compact headers and verify
//! state-tree witnesses against the `state_root` they carry.
//!
//! ## Scope of this module
//!
//! This file pins the consensus surface — the committee size constant,
//! the quorum threshold, the gossip topic string, the compact-header
//! preimage domain, the canonical preimage construction, the
//! deterministic stake-weighted [`select_committee`] sampler, and the
//! [`LightClientAttestation`] gossip envelope — at launch time so
//! future P-COMPAT-001 upgrades inherit a forward-compatible base.
//! `pqc-p2p::topics::Topics::light_client_attestations` carries the
//! per-chain topic string that wraps this module's slug.
//!
//! Out of scope for this module (still tracked as follow-ups):
//!
//! - producer-side compact-header signing + emission on the gossip
//!   topic at every block finalisation (sync-committee members
//!   hot-path)
//! - the slashing rule code for sync-committee equivocation /
//!   invalid-header signing (§6 of SPEC-LIGHT-CLIENT-001) — the rules
//!   are normatively specified at launch but their on-chain
//!   verifier implementation + reserved-slot wiring (`0x0005` /
//!   `0x0006`) lands together with the producer-side gossip
//! - the verifier SDK crate (`viper-light-client`) that walks
//!   compact-header attestations + verifies state-tree witnesses
//!
//! ## Cross-references
//!
//! - SPEC-LIGHT-CLIENT-001 — the normative spec
//! - ADR-053 §T3.6 — the architectural decision
//! - SPEC-FORK-V1 / TASK-191 — `ForkDigest` prefix used in the preimage
//! - SPEC-CONSENSUS-001 §10 — BFT finality the light client tracks

use ciborium::value::Value;

use pqc_crypto::{shake256_n, tagged_hash};

// ── Public constants ─────────────────────────────────────────────────────────

/// Size of the sync committee per epoch (SPEC-LIGHT-CLIENT-001 §2.1).
///
/// 16 is conservative under PQ signing: 16 × ML-DSA-65 (3,309 bytes) ≈
/// 53 KB per attestation, gossip-feasible without aggregation. Raising
/// this requires a P-COMPAT-001 upgrade once a PQ-aggregable signature
/// scheme matures (ADR-053 §T4.1).
pub const SYNC_COMMITTEE_SIZE: usize = 16;

/// Quorum threshold for a valid compact-header attestation
/// (SPEC-LIGHT-CLIENT-001 §4.1): `2f + 1` where
/// `f = floor((n-1)/3)`; for `n = 16`, `f = 5`, quorum = `11`.
///
/// Mirrors the BFT `2f + 1` rule (SPEC-CONSENSUS-001 §10 — quorum is
/// `≥ 2/3 + 1` of voting power). A light verifier that observes fewer
/// than 11 distinct committee signatures MUST reject the attestation.
pub const SYNC_COMMITTEE_QUORUM: usize = 11;

/// GossipSub topic slug for light-client attestations
/// (SPEC-LIGHT-CLIENT-001 §5.1). The full libp2p topic at SDK landing
/// time is `format!("/viper/{chain_id}/{slug}/1.0.0", slug = TOPIC)`.
///
/// Locked from genesis; raising to `-v2` requires a P-COMPAT-001 dual
/// path landing.
pub const SYNC_COMMITTEE_GOSSIP_TOPIC: &str = "viper-light-client-attestations-v1";

/// Domain tag for the compact-header signing preimage
/// (SPEC-LIGHT-CLIENT-001 §3.3). Consumed under the BIP340 double-tagged
/// hash (ADR-053 §T2.4) the same way the BFT vote preimage uses
/// `VIPER-VOTE-V1`.
pub const COMPACT_HEADER_DOMAIN: &[u8] = b"VIPER-LIGHT-HEADER-V1";

// ── CompactHeader ────────────────────────────────────────────────────────────

/// The light-client compact header — a strict subset of `BlockHeader`
/// carrying only the fields a light verifier needs to follow finality
/// and verify state-tree witnesses (SPEC-LIGHT-CLIENT-001 §3.1).
///
/// Field-key allocation follows ADR-053 §T1.1 (gaps reserved; never
/// renumber). Encoding is deterministic CBOR (RFC 8949 §4.2) with
/// integer keys 1..=7 in ascending order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactHeader {
    /// Forward-compat dispatch tag (ADR-053 §T1.1).
    pub header_version: u16,
    /// Position in the canonical chain.
    pub height: u64,
    /// Backward link the light verifier walks across epoch boundaries.
    pub prev_hash: [u8; 32],
    /// Root of the binary Merkle state tree (ADR-053 §T3.1).
    pub state_root: [u8; 32],
    /// Root of the per-block transaction tree.
    pub tx_root: [u8; 32],
    /// Forward-compat commitment slot (ADR-053 §T1.1, §T3.4).
    pub extension_root: [u8; 32],
    /// Selects the signing committee (SPEC-LIGHT-CLIENT-001 §2).
    pub epoch: u64,
}

impl CompactHeader {
    /// Build the canonical signing preimage for a sync-committee
    /// signature over this compact header (SPEC-LIGHT-CLIENT-001 §3.3).
    ///
    /// ```text
    /// preimage = "VIPER-LIGHT-HEADER-V1" || fork_digest[4] || cbor(self)
    /// ```
    ///
    /// The `fork_digest` prefix scopes the signature to a specific
    /// `(fork_version, genesis_validators_root)` pair so a committee
    /// signature on `viper-pq-1` cannot be replayed on any future fork
    /// or parallel chain (ADR-053 §T1.2 / SPEC-FORK-V1, TASK-191).
    ///
    /// Sync-committee members sign this preimage with their ML-DSA-65
    /// consensus key (SPEC-VAL-001 §5.2); reusing the consensus key
    /// keeps key management simple and ensures slashing for
    /// sync-committee equivocation reaches the same `self_bond` slashed
    /// for BFT equivocation (SPEC-LIGHT-CLIENT-001 §6.1).
    pub fn preimage(&self, fork_digest: [u8; 4]) -> Vec<u8> {
        let body = self.cbor_bytes();
        let mut out =
            Vec::with_capacity(COMPACT_HEADER_DOMAIN.len() + fork_digest.len() + body.len());
        out.extend_from_slice(COMPACT_HEADER_DOMAIN);
        out.extend_from_slice(&fork_digest);
        out.extend_from_slice(&body);
        out
    }

    /// Compute the digest-of-preimage used by the gossip envelope's
    /// `header_root` field (SPEC-LIGHT-CLIENT-001 §4.3) — the BIP340
    /// double-tagged hash of the preimage under a distinct domain tag
    /// from the signing tag (so a `header_root` byte string cannot be
    /// confused with a signing preimage).
    pub fn header_root(&self, fork_digest: [u8; 4]) -> [u8; 32] {
        tagged_hash(b"VIPER-LIGHT-HEADER-ROOT-V1", &self.preimage(fork_digest))
    }

    /// Deterministic CBOR encoding per SPEC-LIGHT-CLIENT-001 §3.2
    /// (integer keys 1..=7 in ascending order).
    fn cbor_bytes(&self) -> Vec<u8> {
        let entries: Vec<(Value, Value)> = vec![
            (
                Value::Integer(1.into()),
                Value::Integer(u64::from(self.header_version).into()),
            ),
            (Value::Integer(2.into()), Value::Integer(self.height.into())),
            (
                Value::Integer(3.into()),
                Value::Bytes(self.prev_hash.to_vec()),
            ),
            (
                Value::Integer(4.into()),
                Value::Bytes(self.state_root.to_vec()),
            ),
            (
                Value::Integer(5.into()),
                Value::Bytes(self.tx_root.to_vec()),
            ),
            (
                Value::Integer(6.into()),
                Value::Bytes(self.extension_root.to_vec()),
            ),
            (Value::Integer(7.into()), Value::Integer(self.epoch.into())),
        ];
        cbor_to_vec(&Value::Map(entries))
    }
}

// ── Committee selection (stub) ───────────────────────────────────────────────

/// Validator address — the 32-byte canonical address derived under the
/// `viper-pq-1` BIP340 double-tagged scheme (ADR-053 §T1.3 / TASK-202).
pub type ValidatorAddr = [u8; 32];

/// Bonded stake in venom (`u128` per SPEC-VAL-001 / SPEC-SLASH-001 §10).
pub type Stake = u128;

/// Encode a CBOR value into a fresh byte vector.
///
/// `ciborium::into_writer` can only fail through its writer, and writing
/// into a `Vec<u8>` is infallible, so the `expect` below is unreachable.
/// It is kept (rather than swallowed into an empty or truncated encoding)
/// so that an impossible failure stays loud: a verifier must never emit
/// bytes it did not fully encode.
#[allow(clippy::expect_used)]
fn cbor_to_vec(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)
        .expect("ciborium encoding into an in-memory Vec cannot fail");
    out
}

/// Compute the 16-member sync committee for an epoch
/// (SPEC-LIGHT-CLIENT-001 §2.2 weighted-by-stake without replacement;
/// §7.2 total-set fallback when `validators.len() <= SYNC_COMMITTEE_SIZE`).
///
/// Inputs:
/// - `state_root`: the binary-Merkle state root at the epoch boundary
/// - `epoch`: the epoch number (used 8 bytes big-endian in the seed)
/// - `validators`: the active set, **sorted by address** (the same
///   canonical order used elsewhere in consensus); each entry carries
///   the validator's voting power
///
/// Returns the indices into `validators` of the selected members:
/// - if `validators.len() <= SYNC_COMMITTEE_SIZE` (16): the entire
///   active set in stake-sorted order (descending stake; address
///   ascending breaks ties for determinism) — §7.2 fallback
/// - otherwise: 16 distinct indices sampled stake-proportionally
///   without replacement (§2.2)
///
/// Determinism: any two honest nodes that observe the same
/// `(epoch, state_root, validators)` produce a byte-identical index
/// list. Pin tests in `tests::select_committee_*` enforce this.
pub fn select_committee(
    state_root: &[u8; 32],
    epoch: u64,
    validators: &[(ValidatorAddr, Stake)],
) -> Vec<usize> {
    if validators.is_empty() {
        return Vec::new();
    }

    // §7.2 — small active set short-circuit. Genesis launch has 3
    // validators; the first committee is exactly those three in
    // stake-sorted order. A future epoch with > 16 active validators
    // falls through to the weighted-shuffle path below.
    if validators.len() <= SYNC_COMMITTEE_SIZE {
        let mut order: Vec<(usize, &(ValidatorAddr, Stake))> =
            validators.iter().enumerate().collect();
        order.sort_by(|(_, a), (_, b)| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        return order.into_iter().map(|(idx, _)| idx).collect();
    }

    // §2.2 weighted-by-stake without replacement.
    let mut seed_input = Vec::with_capacity(8 + 32);
    seed_input.extend_from_slice(&epoch.to_be_bytes());
    seed_input.extend_from_slice(state_root);
    let seed = tagged_hash(b"VIPER-SYNC-COMMITTEE-V1", &seed_input);

    let stake_of = |orig_idx: usize| validators.get(orig_idx).map_or(0, |v| v.1);
    let mut total_stake: u128 = validators.iter().map(|v| v.1).sum();
    let mut remaining: Vec<usize> = (0..validators.len()).collect();
    let mut committee: Vec<usize> = Vec::with_capacity(SYNC_COMMITTEE_SIZE);

    for i in 0..SYNC_COMMITTEE_SIZE {
        if remaining.is_empty() || total_stake == 0 {
            break;
        }
        // chunk = SHAKE-256(seed || (i as u64) BE, 32 bytes)
        let i_be = (i as u64).to_be_bytes();
        let chunk: [u8; 32] = shake256_n::<32>(&[&seed, &i_be]);

        // selector ∈ [0, total_stake)
        let selector = reduce_u256_be_mod_u128(&chunk, total_stake);

        // Walk `remaining` (in input order — matches the §2.2 spec
        // pseudocode `weighted_select` description) accumulating stake
        // until cumulative weight exceeds `selector`.
        let mut cumulative: u128 = 0;
        let mut picked_remaining_idx: usize = remaining.len() - 1;
        for (j, &orig_idx) in remaining.iter().enumerate() {
            cumulative = cumulative.saturating_add(stake_of(orig_idx));
            if cumulative > selector {
                picked_remaining_idx = j;
                break;
            }
        }

        let picked_orig = remaining.remove(picked_remaining_idx);
        committee.push(picked_orig);
        total_stake = total_stake.saturating_sub(stake_of(picked_orig));
    }

    committee
}

/// Compute `chunk_u256_be mod m` where `chunk` is 32 bytes interpreted
/// as a 256-bit unsigned big-endian integer and `m` is a `u128` modulus.
///
/// Implementation: bit-by-bit doubling. `acc` is reduced after every
/// shift, so the only overflow case is the high bit shifting out of
/// `u128`; that case is handled by adding `2^128 mod m` precomputed
/// once. 256 iterations × constant-time arithmetic — called at most
/// `SYNC_COMMITTEE_SIZE` times per epoch (negligible).
fn reduce_u256_be_mod_u128(chunk: &[u8; 32], m: u128) -> u128 {
    debug_assert!(m > 0, "modulus must be > 0");
    let pow128_mod_m = (u128::MAX % m).wrapping_add(1) % m;
    let mut acc: u128 = 0;
    for &byte in chunk.iter() {
        for shift in (0..8u32).rev() {
            let bit = ((byte >> shift) & 1) as u128;
            let high_carry = acc >> 127;
            let shifted = acc.wrapping_shl(1) | bit;
            acc = if high_carry == 1 {
                ((shifted % m) + pow128_mod_m) % m
            } else {
                shifted % m
            };
        }
    }
    acc
}

// ── LightClientAttestation gossip envelope ───────────────────────────────────

/// Sync-committee compact-header attestation envelope, gossipped on
/// `Topics::light_client_attestations` (SPEC-LIGHT-CLIENT-001 §4.3 / §5).
///
/// Either the per-member single-signature pre-aggregation form (`sigs`
/// length 1) or the aggregator's collected `≥ 11` form. Verifiers
/// reject attestations carrying fewer than [`SYNC_COMMITTEE_QUORUM`]
/// signatures (§4.1) — pre-aggregation envelopes are still gossiped
/// to let aggregators collect them.
///
/// Wire format (CBOR map, integer keys; SPEC-LIGHT-CLIENT-001 §4.3):
///
/// ```text
///   1 -> uint(u64)        epoch
///   2 -> bstr(32)         header_root
///   3 -> array            sigs: [(u8 committee_index, bstr signature), …]
///   4 -> null | bstr      agg_proof  (reserved; null at launch)
/// ```
///
/// `header_root` lets peers de-duplicate without re-deriving the
/// preimage; recipients look up signers by `committee_index` against
/// the per-epoch committee derivation in [`select_committee`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightClientAttestation {
    /// Epoch the compact-header refers to. Receivers MUST drop
    /// envelopes whose epoch does not match the current scope.
    pub epoch: u64,
    /// 32-byte digest of the canonical signing preimage
    /// (`tagged_hash("VIPER-LIGHT-HEADER-ROOT-V1", preimage)`).
    pub header_root: [u8; 32],
    /// `(committee_index, ML-DSA-65 signature)` pairs. `committee_index`
    /// is `0..16` (§2 — position within the epoch's committee), NOT
    /// the validator's address; recipients look up the address via
    /// the deterministic committee derivation.
    pub sigs: Vec<(u8, Vec<u8>)>,
    /// `None` at launch (reserved for future PQ aggregation per
    /// ADR-053 §T4.1 / ADR-049). When set, carries an inner
    /// version-tagged TLV; verifiers that don't recognise the version
    /// MUST reject the envelope rather than ignore the field.
    pub agg_proof: Option<Vec<u8>>,
}

impl LightClientAttestation {
    /// Deterministic CBOR encoding (SPEC-LIGHT-CLIENT-001 §4.3): integer
    /// keys 1..=4 in ascending order; `sigs` as a fixed-shape `[u8 idx,
    /// bstr sig]` pair array; `agg_proof` always present and CBOR `null`
    /// when reserved.
    pub fn encode(&self) -> Vec<u8> {
        let sigs_array: Vec<Value> = self
            .sigs
            .iter()
            .map(|(idx, sig)| {
                Value::Array(vec![
                    Value::Integer(u64::from(*idx).into()),
                    Value::Bytes(sig.clone()),
                ])
            })
            .collect();
        let agg_proof_value = match &self.agg_proof {
            None => Value::Null,
            Some(bytes) => Value::Bytes(bytes.clone()),
        };
        let entries: Vec<(Value, Value)> = vec![
            (Value::Integer(1.into()), Value::Integer(self.epoch.into())),
            (
                Value::Integer(2.into()),
                Value::Bytes(self.header_root.to_vec()),
            ),
            (Value::Integer(3.into()), Value::Array(sigs_array)),
            (Value::Integer(4.into()), agg_proof_value),
        ];
        cbor_to_vec(&Value::Map(entries))
    }

    /// Strict CBOR decoder. Rejects malformed envelopes (missing keys,
    /// unknown keys, wrong types, signature byte arrays of zero length)
    /// per SPEC-LIGHT-CLIENT-001 §5.2 "Validation rule".
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        let value: Value = ciborium::from_reader(bytes).map_err(|_| "cbor decode failed")?;
        let entries = match value {
            Value::Map(m) => m,
            _ => return Err("envelope must be a CBOR map"),
        };

        let mut epoch: Option<u64> = None;
        let mut header_root: Option<[u8; 32]> = None;
        let mut sigs: Option<Vec<(u8, Vec<u8>)>> = None;
        let mut agg_proof: Option<Option<Vec<u8>>> = None;

        for (key, val) in entries {
            let key_int: u64 = match key {
                Value::Integer(i) => i.try_into().map_err(|_| "key out of range")?,
                _ => return Err("non-integer key"),
            };
            match key_int {
                1 => {
                    let i = match val {
                        Value::Integer(i) => i,
                        _ => return Err("epoch is not uint"),
                    };
                    epoch = Some(i.try_into().map_err(|_| "epoch out of u64 range")?);
                }
                2 => {
                    let bs = match val {
                        Value::Bytes(b) => b,
                        _ => return Err("header_root is not bstr"),
                    };
                    if bs.len() != 32 {
                        return Err("header_root is not 32 bytes");
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bs);
                    header_root = Some(arr);
                }
                3 => {
                    let entries = match val {
                        Value::Array(a) => a,
                        _ => return Err("sigs is not array"),
                    };
                    let mut decoded = Vec::with_capacity(entries.len());
                    for entry in entries {
                        let [idx_val, sig_val] = match entry {
                            Value::Array(p) => match <[Value; 2]>::try_from(p) {
                                Ok(pair) => pair,
                                Err(_) => return Err("sig pair is not 2-array"),
                            },
                            _ => return Err("sig pair is not 2-array"),
                        };
                        let idx_u64: u64 = match idx_val {
                            Value::Integer(i) => i.try_into().map_err(|_| "idx out of u64")?,
                            _ => return Err("committee_index is not uint"),
                        };
                        let idx_u8: u8 = idx_u64.try_into().map_err(|_| "committee_index > 255")?;
                        if (idx_u8 as usize) >= SYNC_COMMITTEE_SIZE {
                            return Err("committee_index out of [0, 16)");
                        }
                        let sig_bytes = match sig_val {
                            Value::Bytes(b) => b,
                            _ => return Err("signature is not bstr"),
                        };
                        if sig_bytes.is_empty() {
                            return Err("signature is empty");
                        }
                        decoded.push((idx_u8, sig_bytes));
                    }
                    sigs = Some(decoded);
                }
                4 => {
                    agg_proof = Some(match val {
                        Value::Null => None,
                        Value::Bytes(b) => Some(b),
                        _ => return Err("agg_proof is not null or bstr"),
                    });
                }
                _ => return Err("unknown key"),
            }
        }

        Ok(Self {
            epoch: epoch.ok_or("missing key 1 (epoch)")?,
            header_root: header_root.ok_or("missing key 2 (header_root)")?,
            sigs: sigs.ok_or("missing key 3 (sigs)")?,
            agg_proof: agg_proof.ok_or("missing key 4 (agg_proof)")?,
        })
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
