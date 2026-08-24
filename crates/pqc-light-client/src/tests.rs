// SPDX-License-Identifier: Apache-2.0
//! Tests for `light_client`.
//!
//! Extracted from `light_client.rs` 2026-05-10. `use super::*;`
//! brings every private item from the parent module into scope.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use super::*;

/// Pin-test on the four normative constants. A change to any of
/// these byte values is a wire/protocol break that MUST land via a
/// P-COMPAT-001 dual-path upgrade — never silently. CI failure
/// here is the first line of defense.
#[test]
fn constants_are_stable() {
    assert_eq!(SYNC_COMMITTEE_SIZE, 16);
    assert_eq!(SYNC_COMMITTEE_QUORUM, 11);
    assert_eq!(
        SYNC_COMMITTEE_GOSSIP_TOPIC,
        "viper-light-client-attestations-v1"
    );
    assert_eq!(COMPACT_HEADER_DOMAIN, b"VIPER-LIGHT-HEADER-V1");

    // Quorum is normatively `2f + 1` where `f = (n - 1) / 3`
    // (BFT-style — same rule as SPEC-CONSENSUS-001 §10). Re-derive
    // on the chosen size so a future committee-size bump that
    // forgets to update the quorum constant breaks here.
    let f = (SYNC_COMMITTEE_SIZE - 1) / 3;
    let derived = 2 * f + 1;
    assert_eq!(derived, SYNC_COMMITTEE_QUORUM);
}

/// Round-trip the preimage of a fixture compact header through a
/// hard-coded expected hex. A renamed domain tag, a reordered CBOR
/// key, or a changed encoding strategy breaks this test loudly,
/// which is the entire point — the preimage is the wire format
/// every future light-verifier signs against.
#[test]
fn preimage_round_trips_known_fixture() {
    let header = CompactHeader {
        header_version: 1,
        height: 42,
        prev_hash: [0xab; 32],
        state_root: [0xcd; 32],
        tx_root: [0xef; 32],
        extension_root: [0x12; 32],
        epoch: 7,
    };
    let fork_digest = [0x9a, 0xbc, 0xde, 0xf0];

    let preimage = header.preimage(fork_digest);

    // The preimage layout is:
    //   "VIPER-LIGHT-HEADER-V1" (21 bytes) || fork_digest (4) || cbor(header)
    // Lengths and structural prefix:
    assert_eq!(&preimage[..21], COMPACT_HEADER_DOMAIN);
    assert_eq!(&preimage[21..25], &fork_digest);

    // CBOR(header) — deterministic encoding with integer keys 1..=7.
    // a7 = map(7); 01 = unsigned 1; 19 0001 = u16 1 minimal-form
    // is `01` not `19 0001`, so ciborium encodes header_version=1
    // as `01`. Each [u8;32] is `5820 || 32 bytes`. Verify a few
    // anchor bytes — a structural change blows this up.
    let cbor = &preimage[25..];
    // Map of 7 entries:
    assert_eq!(cbor[0], 0xa7);
    // First key: 0x01 (uint 1), value 0x01 (uint 1, header_version):
    assert_eq!(cbor[1], 0x01);
    assert_eq!(cbor[2], 0x01);
    // Second key: 0x02 (uint 2), value: uint 42 = 0x18 0x2a:
    assert_eq!(cbor[3], 0x02);
    assert_eq!(cbor[4], 0x18);
    assert_eq!(cbor[5], 0x2a);

    // Pin the full preimage in hex. Any change anywhere — domain
    // tag bytes, CBOR key order, field encoding — flips this loud.
    let expected_hex = concat!(
        // "VIPER-LIGHT-HEADER-V1" (21 ASCII bytes)
        "56495045522d4c494748542d4845414445522d5631",
        // fork_digest (4 bytes)
        "9abcdef0",
        // cbor(map(7)):
        "a7",
        // key 1 -> u16 1 (encoded as minor-type-0 single-byte 0x01)
        "0101",
        // key 2 -> u64 42 (encoded as 0x18 0x2a — uint8 follow byte)
        "02182a",
        // key 3 -> bstr(32) of 0xab — 0x58 0x20 || 32 bytes
        "035820abababababababababababababababababababababababababababababababab",
        // key 4 -> bstr(32) of 0xcd
        "045820cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        // key 5 -> bstr(32) of 0xef
        "055820efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef",
        // key 6 -> bstr(32) of 0x12
        "0658201212121212121212121212121212121212121212121212121212121212121212",
        // key 7 -> u64 7 (single-byte 0x07)
        "0707",
    );
    let actual_hex = hex::encode(&preimage);
    assert_eq!(actual_hex, expected_hex, "preimage byte layout drifted");

    // Also verify domain separation: changing the fork_digest
    // changes the preimage.
    let other = header.preimage([0u8; 4]);
    assert_ne!(preimage, other);
}

// SPEC-LIGHT-CLIENT-001 §2.3 invariants. The four properties the
// weighted-shuffle implementation MUST satisfy are split across the
// tests below — keep them all green together; loosening any one
// breaks the light-client trust model.

/// §2.3 — Determinism. Two calls with identical inputs MUST return
/// byte-identical output. Pinned at SDK landing because every
/// honest node depends on this to compute the same committee.
#[test]
fn select_committee_is_deterministic() {
    let state_root = [0u8; 32];
    let validators: Vec<(ValidatorAddr, Stake)> = (0..32u8)
        .map(|i| ([i; 32], 1_000_000_u128 + u128::from(i)))
        .collect();

    let a = select_committee(&state_root, 0, &validators);
    let b = select_committee(&state_root, 0, &validators);
    assert_eq!(a, b, "selection must be deterministic");
    assert_eq!(a.len(), SYNC_COMMITTEE_SIZE);
}

/// §2.3 — Distinctness. The 16 committee indices are pairwise
/// distinct (no validator appears twice in the same committee —
/// "without replacement").
#[test]
fn select_committee_indices_are_distinct() {
    let state_root = [0xab; 32];
    let validators: Vec<(ValidatorAddr, Stake)> = (0..32u8)
        .map(|i| ([i; 32], 1_000_000_u128 + u128::from(i) * 1_000))
        .collect();

    let committee = select_committee(&state_root, 42, &validators);
    assert_eq!(committee.len(), SYNC_COMMITTEE_SIZE);

    let mut sorted = committee.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        committee.len(),
        "committee indices must be distinct"
    );
}

/// §2.3 — Different epochs over the same active set MUST produce
/// different committees with high probability. Pin: pick two
/// adjacent epochs and assert the index lists are not identical.
/// (A weak rotation property — the strong "every validator gets
/// a turn over many epochs" is checked by the proportional-sampling
/// test below.)
#[test]
fn select_committee_rotates_across_epochs() {
    let state_root = [0xcd; 32];
    let validators: Vec<(ValidatorAddr, Stake)> =
        (0..32u8).map(|i| ([i; 32], 1_000_000_u128)).collect();

    let e0 = select_committee(&state_root, 0, &validators);
    let e1 = select_committee(&state_root, 1, &validators);
    assert_ne!(e0, e1, "adjacent epochs must produce different committees");
}

/// §2.3 — Stake-proportional sampling. A high-stake validator
/// should be selected materially more often than a low-stake
/// validator over many epochs. Use a 32-validator set where
/// validator 0 has 100x stake of the others; over 200 epochs,
/// validator 0 should appear in the committee in a clear majority
/// of them while a baseline validator should appear in roughly
/// `200 * 16/32 = ~100` epochs. We assert validator 0 is sampled
/// at least 1.5x as often as a typical baseline — loose enough
/// to avoid flakiness, tight enough to catch the bug class
/// (uniform shuffle masquerading as weighted).
#[test]
fn select_committee_is_stake_proportional() {
    let mut validators: Vec<(ValidatorAddr, Stake)> =
        (0..32u8).map(|i| ([i; 32], 1_000_000_u128)).collect();
    validators[0].1 = 100_000_000_u128; // 100x

    let mut counts = [0u32; 32];
    for epoch in 0..200u64 {
        let state_root = [(epoch & 0xff) as u8; 32];
        for &idx in &select_committee(&state_root, epoch, &validators) {
            counts[idx] += 1;
        }
    }

    let high_stake_count = counts[0];
    // Average baseline frequency over indices 1..32.
    let baseline_avg: f64 = counts[1..].iter().map(|&c| c as f64).sum::<f64>() / 31.0;
    assert!(
        (high_stake_count as f64) > 1.5 * baseline_avg,
        "high-stake validator (count={high_stake_count}) should appear ≥1.5x baseline avg ({baseline_avg:.1}) \
         over 200 epochs — selection looks non-weighted"
    );
}

/// §7.2 — Total-set fallback. When `validators.len() < 16`, the
/// committee is the entire active set in stake-sorted (descending)
/// order. Pin both the size-3 genesis case (the actual launch
/// state of `viper-pq-1`) and the size-15 boundary.
#[test]
fn select_committee_total_set_fallback() {
    // Genesis launch state: 3 validators with equal stake.
    let validators_3: Vec<(ValidatorAddr, Stake)> = vec![
        ([0xA1; 32], 1_000_000),
        ([0xA2; 32], 1_000_000),
        ([0xA3; 32], 1_000_000),
    ];
    let committee = select_committee(&[0u8; 32], 0, &validators_3);
    assert_eq!(committee.len(), 3);
    // Equal stake — address ascending tie-break: 0xA1 < 0xA2 < 0xA3.
    assert_eq!(committee, vec![0, 1, 2]);

    // Mixed stake — descending order.
    let validators_3_mixed: Vec<(ValidatorAddr, Stake)> =
        vec![([0x01; 32], 100), ([0x02; 32], 1_000), ([0x03; 32], 50)];
    let committee = select_committee(&[0u8; 32], 0, &validators_3_mixed);
    // Stake desc: idx 1 (1000) > idx 0 (100) > idx 2 (50).
    assert_eq!(committee, vec![1, 0, 2]);

    // Size-15 boundary (one below SYNC_COMMITTEE_SIZE).
    let validators_15: Vec<(ValidatorAddr, Stake)> = (0..15u8)
        .map(|i| ([i; 32], (15 - u128::from(i)) * 1_000))
        .collect();
    let committee = select_committee(&[0u8; 32], 0, &validators_15);
    // Stake decreases with index, so descending sort = (0..15).
    assert_eq!(committee, (0..15).collect::<Vec<_>>());
}

/// §7.2 — Empty active set returns empty committee (defensive,
/// the chain shouldn't reach this state but the fn must not panic).
#[test]
fn select_committee_empty_set() {
    let committee = select_committee(&[0u8; 32], 0, &[]);
    assert!(committee.is_empty());
}

/// Round-trip a single-signer pre-aggregation envelope and a
/// quorum-sized aggregated envelope. Pin on both to catch any
/// regression in the CBOR shape (key order / array shape /
/// agg_proof null vs bstr handling).
#[test]
fn light_client_attestation_round_trips() {
    // Single-signer (committee member self-publishing).
    let single = LightClientAttestation {
        epoch: 7,
        header_root: [0xab; 32],
        sigs: vec![(3, vec![0x11, 0x22, 0x33])],
        agg_proof: None,
    };
    let encoded = single.encode();
    let decoded = LightClientAttestation::decode(&encoded).expect("decode single");
    assert_eq!(decoded, single);

    // Aggregated form: 11 signatures (quorum), agg_proof still null.
    let aggregated = LightClientAttestation {
        epoch: 42,
        header_root: [0xcd; 32],
        sigs: (0u8..11).map(|i| (i, vec![0xee; 64])).collect(),
        agg_proof: None,
    };
    let encoded = aggregated.encode();
    let decoded = LightClientAttestation::decode(&encoded).expect("decode aggregated");
    assert_eq!(decoded, aggregated);
    assert_eq!(decoded.sigs.len(), SYNC_COMMITTEE_QUORUM);

    // With agg_proof set (post-PQ-aggregation activation simulation).
    let with_proof = LightClientAttestation {
        epoch: 99,
        header_root: [0x55; 32],
        sigs: vec![(0, vec![0x01; 32])],
        agg_proof: Some(vec![0xfe, 0xed, 0xfa, 0xce]),
    };
    let encoded = with_proof.encode();
    let decoded = LightClientAttestation::decode(&encoded).expect("decode with_proof");
    assert_eq!(decoded, with_proof);
}

/// SPEC-LIGHT-CLIENT-001 §5.2 "Validation rule" — every malformed
/// envelope SHOULD be rejected, never silently dropped + accepted.
/// Pin a representative set of malformations.
#[test]
fn light_client_attestation_decode_rejects_malformed() {
    // Random non-CBOR bytes.
    assert!(LightClientAttestation::decode(b"not cbor").is_err());

    // Valid CBOR but not a map (e.g. an array).
    let mut not_a_map = Vec::new();
    ciborium::into_writer(
        &Value::Array(vec![Value::Integer(1.into())]),
        &mut not_a_map,
    )
    .unwrap();
    assert!(LightClientAttestation::decode(&not_a_map).is_err());

    // Map missing a required key.
    let missing_root = LightClientAttestation {
        epoch: 1,
        header_root: [0u8; 32],
        sigs: vec![],
        agg_proof: None,
    };
    let mut bytes = missing_root.encode();
    // Strip key 2 by re-encoding without it.
    let stripped: Vec<(Value, Value)> = vec![
        (Value::Integer(1.into()), Value::Integer(1u64.into())),
        (Value::Integer(3.into()), Value::Array(vec![])),
        (Value::Integer(4.into()), Value::Null),
    ];
    bytes.clear();
    ciborium::into_writer(&Value::Map(stripped), &mut bytes).unwrap();
    let err = LightClientAttestation::decode(&bytes).unwrap_err();
    assert!(
        err.contains("header_root"),
        "expected header_root err, got {err}"
    );

    // committee_index out of [0, 16) range.
    let bad_idx = LightClientAttestation {
        epoch: 1,
        header_root: [0u8; 32],
        sigs: vec![(SYNC_COMMITTEE_SIZE as u8, vec![0xaa; 32])],
        agg_proof: None,
    };
    let bytes = bad_idx.encode();
    assert!(LightClientAttestation::decode(&bytes).is_err());

    // Empty signature bstr.
    let empty_sig = LightClientAttestation {
        epoch: 1,
        header_root: [0u8; 32],
        sigs: vec![(0, vec![])],
        agg_proof: None,
    };
    let bytes = empty_sig.encode();
    assert!(LightClientAttestation::decode(&bytes).is_err());
}

/// `reduce_u256_be_mod_u128` correctness over edge cases. Tests
/// in this module pin the helper rather than the generic property
/// because it is the only u128-arithmetic pinch point in the
/// committee-selection path.
#[test]
fn reduce_u256_be_mod_u128_known_values() {
    // 0 mod m = 0
    assert_eq!(reduce_u256_be_mod_u128(&[0; 32], 7), 0);

    // u256_max mod 1 = 0
    assert_eq!(reduce_u256_be_mod_u128(&[0xff; 32], 1), 0);

    // u256_max mod 2 = 1 (u256_max is odd)
    assert_eq!(reduce_u256_be_mod_u128(&[0xff; 32], 2), 1);

    // 256 mod 100 = 56 — encoded as 0x...0100 (last two bytes).
    let mut chunk = [0u8; 32];
    chunk[30] = 0x01;
    chunk[31] = 0x00;
    assert_eq!(reduce_u256_be_mod_u128(&chunk, 100), 56);

    // Compare against u128 native modulo for any value < u128::MAX.
    // chunk encodes 0x0123456789abcdef in last 8 bytes — value 81985529216486895.
    let mut chunk = [0u8; 32];
    chunk[24..].copy_from_slice(&0x0123456789abcdefu64.to_be_bytes());
    assert_eq!(
        reduce_u256_be_mod_u128(&chunk, 1_000_000_007),
        81985529216486895u128 % 1_000_000_007
    );

    // Modulus near u128::MAX: pick m = u128::MAX. Result should equal
    // (high * 2^128 + low) mod m where if value < m, result = value.
    // Easier sanity: u256_max mod u128::MAX. u256_max = (u128::MAX << 128) | u128::MAX.
    // = u128::MAX * 2^128 + u128::MAX
    // = u128::MAX * (2^128 + 1)
    // Note 2^128 mod u128::MAX = 1 (since 2^128 = u128::MAX + 1).
    // So u256_max mod u128::MAX = u128::MAX * (1 + 1) mod u128::MAX = 0.
    assert_eq!(reduce_u256_be_mod_u128(&[0xff; 32], u128::MAX), 0);
}
