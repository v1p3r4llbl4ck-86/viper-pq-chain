// SPDX-License-Identifier: Apache-2.0
//! Tests for `consensus_msg`.
//!
//! Extracted from `consensus_msg.rs` 2026-05-10. `use super::*;`
//! brings every private item from the parent module into scope.

use super::*;

fn make_vote(msg_type: u8) -> SignedVote {
    SignedVote {
        msg_type,
        height: 42,
        round: 1,
        block_hash: [0x11; 32],
        validator_address: [0x22; 32],
        // ML-DSA-65 signature length = 3 309 bytes (SPEC-CONSENSUS-001 §8.4).
        signature: vec![0xAA; 3309],
    }
}

// SPEC-CONSENSUS-001 §8.2 / §8.3 — both vote types round-trip byte-for-byte.
// If this fails, two validators on the same release cannot exchange votes.
#[test]
fn prevote_and_precommit_roundtrip_through_cbor() {
    for mt in [MSG_TYPE_PREVOTE, MSG_TYPE_PRECOMMIT] {
        let original = make_vote(mt);
        let bytes = encode_signed_vote_bytes(&original);
        let decoded = decode_signed_vote(&bytes).expect("decode");
        assert_eq!(
            decoded, original,
            "round-trip failed for msg_type {mt:#04x}"
        );
    }
}

// Nil votes are represented by block_hash = [0; 32]; must survive round-trip
// with byte-exact fidelity (any corruption changes the signed preimage).
#[test]
fn nil_block_hash_preserved_through_roundtrip() {
    let mut original = make_vote(MSG_TYPE_PREVOTE);
    original.block_hash = [0u8; 32];
    let bytes = encode_signed_vote_bytes(&original);
    let decoded = decode_signed_vote(&bytes).expect("decode");
    assert_eq!(decoded.block_hash, [0u8; 32]);
    assert_eq!(decoded, original);
}

// A signature at the upper bound for SLH-DSA-SHAKE-192s (16 224 bytes, per
// SPEC-CONSENSUS-001 §8.2) must round-trip. Guards against a silent size
// limit in the encoder or `GossipMessage` wrapping.
#[test]
fn slh_dsa_sized_signature_roundtrips() {
    let mut original = make_vote(MSG_TYPE_PRECOMMIT);
    original.signature = vec![0xC3; 16_224];
    let bytes = encode_signed_vote_bytes(&original);
    let decoded = decode_signed_vote(&bytes).expect("decode");
    assert_eq!(decoded.signature.len(), 16_224);
    assert_eq!(decoded, original);
}

// Any msg_type other than 0xC2 / 0xC3 must fail to decode — prevents a
// Proposal (0xC1) or an envelope tag (0x02) from silently being treated
// as a vote by the consensus layer.
#[test]
fn rejects_non_vote_msg_type() {
    for bad in [0x00u8, 0x01, 0x02, 0xC1, 0xC4, 0xFF] {
        let mut v = make_vote(MSG_TYPE_PREVOTE);
        v.msg_type = bad;
        // Hand-encode with the invalid msg_type (encode_signed_vote doesn't validate).
        let bytes = encode_signed_vote_bytes(&v);
        let err = decode_signed_vote(&bytes).expect_err("must reject");
        assert_eq!(err, SignedVoteDecodeError::InvalidMsgType(bad));
    }
}

// block_hash of wrong length must be rejected with a typed error, not
// silently truncated or panicked on.
#[test]
fn rejects_short_block_hash() {
    let bad = Value::Map(vec![
        (
            Value::Integer(1i64.into()),
            Value::Integer((MSG_TYPE_PREVOTE as i64).into()),
        ),
        (Value::Integer(2i64.into()), Value::Integer(42i64.into())),
        (Value::Integer(3i64.into()), Value::Integer(0i64.into())),
        (Value::Integer(4i64.into()), Value::Bytes(vec![0xAA; 31])),
        (Value::Integer(5i64.into()), Value::Bytes(vec![0xBB; 32])),
        (Value::Integer(6i64.into()), Value::Bytes(vec![0xCC; 16])),
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&bad, &mut buf).unwrap();
    let err = decode_signed_vote(&buf).expect_err("must reject");
    assert!(matches!(err, SignedVoteDecodeError::InvalidField(4, _)));
}

// Unknown keys must be rejected — SPEC-CONSENSUS-001 §8.2 (implicit via
// the `slashing::EquivocationVote` convention). A future release adding
// a 7th field MUST define a new wire type (or version-bump the envelope)
// rather than extending this one in place.
#[test]
fn rejects_unknown_field() {
    let mut bytes = encode_signed_vote_bytes(&make_vote(MSG_TYPE_PREVOTE));
    // Decode back to Value, inject an extra key, re-encode, decode again.
    let mut value: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
    if let Value::Map(entries) = &mut value {
        entries.push((Value::Integer(99i64.into()), Value::Integer(1i64.into())));
    }
    bytes.clear();
    ciborium::ser::into_writer(&value, &mut bytes).unwrap();
    let err = decode_signed_vote(&bytes).expect_err("must reject");
    assert!(matches!(err, SignedVoteDecodeError::InvalidFormat(s) if s.contains("unknown key 99")));
}

// Missing required fields must surface which one — ops-debuggability when
// an old-format gossip message reaches a new node.
#[test]
fn missing_signature_field_is_reported() {
    let bad = Value::Map(vec![
        (
            Value::Integer(1i64.into()),
            Value::Integer((MSG_TYPE_PRECOMMIT as i64).into()),
        ),
        (Value::Integer(2i64.into()), Value::Integer(42i64.into())),
        (Value::Integer(3i64.into()), Value::Integer(0i64.into())),
        (Value::Integer(4i64.into()), Value::Bytes(vec![0xAA; 32])),
        (Value::Integer(5i64.into()), Value::Bytes(vec![0xBB; 32])),
        // field 6 omitted
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&bad, &mut buf).unwrap();
    let err = decode_signed_vote(&buf).expect_err("must reject");
    assert_eq!(err, SignedVoteDecodeError::MissingField(6));
}

// Decode error messages surface the field number — operators triaging a
// gossip decode failure need enough to grep the spec.
#[test]
fn decode_error_display_includes_field_number() {
    let err = SignedVoteDecodeError::InvalidField(4, "block_hash too short".into());
    let rendered = format!("{err}");
    assert!(rendered.contains("field 4"), "got: {rendered}");
    assert!(rendered.contains("block_hash"), "got: {rendered}");
}
