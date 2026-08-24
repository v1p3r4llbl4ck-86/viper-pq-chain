// SPDX-License-Identifier: Apache-2.0
//! Deterministic CBOR encoding tests — SPEC-TX-001 §4.
//!
//! Two properties are verified:
//!   1. `round_trip_preserves_structure` — decode(encode(tx)) is field-equal to tx
//!   2. `encode_decode_encode_is_byte_stable` — encode(decode(encode(tx))) == encode(tx)
//!      This is the canonical encoding contract: bytes are stable across a full round-trip.

use crate::codec::{decode_tx, encode_tx};
use pqc_crypto::AlgId;
use pqc_types::{
    account::Address,
    transaction::{MsgType, Transaction},
};

/// Build a synthetic valid transaction for testing.
/// All fields are structurally valid; signature content is a zero-filled placeholder.
fn synthetic_tx(fee_tip: u64) -> Transaction {
    Transaction {
        tx_version: 1,
        chain_id: vec![0xDE, 0xAD, 0xBE, 0xEF],
        msg_type: MsgType::TokenTransfer,
        sender: Address([0x42u8; 32]),
        nonce: 7,
        fee: 1_000,
        fee_tip,
        gas_limit: 200_000,
        payload: vec![0x01, 0x02, 0x03],
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        // ML-DSA-65 signatures are 3,309 bytes; placeholder with known pattern
        signature: vec![0xABu8; 3_309],
    }
}

#[test]
fn round_trip_preserves_structure() {
    let original = synthetic_tx(0);

    let encoded = encode_tx(&original).expect("encode must succeed");
    let decoded = decode_tx(&encoded).expect("decode must succeed");

    assert_eq!(decoded.tx_version, original.tx_version);
    assert_eq!(decoded.chain_id, original.chain_id);
    assert_eq!(decoded.msg_type, original.msg_type);
    assert_eq!(decoded.sender, original.sender);
    assert_eq!(decoded.nonce, original.nonce);
    assert_eq!(decoded.fee, original.fee);
    assert_eq!(decoded.fee_tip, original.fee_tip);
    assert_eq!(decoded.gas_limit, original.gas_limit);
    assert_eq!(decoded.payload, original.payload);
    assert_eq!(decoded.sig_alg_id, original.sig_alg_id);
    assert_eq!(decoded.sig_key_version, original.sig_key_version);
    assert_eq!(decoded.signature, original.signature);
}

/// The core canonical encoding invariant: bytes are stable across encode→decode→encode.
/// Any non-determinism in the encoder would cause this to fail.
#[test]
fn encode_decode_encode_is_byte_stable() {
    for fee_tip in [0u64, 500, u64::MAX / 2] {
        let tx = synthetic_tx(fee_tip);

        let bytes_1 = encode_tx(&tx).expect("first encode must succeed");
        let decoded = decode_tx(&bytes_1).expect("decode must succeed");
        let bytes_2 = encode_tx(&decoded).expect("second encode must succeed");

        assert_eq!(
            bytes_1,
            bytes_2,
            "encoding is not byte-stable for fee_tip={fee_tip}: \
             first={} bytes, second={} bytes",
            bytes_1.len(),
            bytes_2.len()
        );
    }
}

/// fee_tip=0 must be omitted from the envelope (SPEC-TX-001 §3).
/// The decoded tx must still have fee_tip=0.
#[test]
fn zero_fee_tip_is_omitted_from_encoding() {
    let tx_with_zero_tip = synthetic_tx(0);
    let tx_with_explicit_tip = synthetic_tx(999);

    let bytes_zero = encode_tx(&tx_with_zero_tip).expect("encode");
    let bytes_tip = encode_tx(&tx_with_explicit_tip).expect("encode");

    // The zero-tip encoding must be strictly shorter (field 7 absent)
    assert!(
        bytes_zero.len() < bytes_tip.len(),
        "zero fee_tip encoding ({} bytes) should be shorter than explicit tip encoding ({} bytes)",
        bytes_zero.len(),
        bytes_tip.len()
    );

    // Decoding a zero-tip tx must yield fee_tip=0
    let decoded = decode_tx(&bytes_zero).expect("decode");
    assert_eq!(
        decoded.fee_tip, 0,
        "fee_tip must be 0 after decoding zero-tip tx"
    );
}

/// Non-canonical CBOR (tampered bytes) must be rejected with EncodingInvalid.
/// We simulate this by appending a byte after a valid encoding.
#[test]
fn non_canonical_cbor_is_rejected() {
    let tx = synthetic_tx(0);
    let mut bad_bytes = encode_tx(&tx).expect("encode");

    // Append a trailing byte — round-trip check will catch it
    bad_bytes.push(0xFF);

    let result = decode_tx(&bad_bytes);
    assert!(
        result.is_err(),
        "trailing bytes should cause decode to fail"
    );
}

/// All 12 supported MsgType values must survive a round-trip through encode/decode.
#[test]
fn all_msg_types_round_trip() {
    use MsgType::*;
    let all_types = [
        VaultCreate,
        VaultPolicyUpdate,
        TokenTransfer,
        AttestationCreate,
        AttestationRevoke,
        ProofAnchor,
        KeyAdd,
        KeyRotate,
        KeyRevoke,
        ConsensusKeyRotate,
        GovernanceProposal,
        GovernanceVote,
    ];

    for msg_type in all_types {
        let mut tx = synthetic_tx(0);
        tx.msg_type = msg_type;

        let encoded = encode_tx(&tx).expect("encode");
        let decoded = decode_tx(&encoded).expect("decode");

        assert_eq!(
            decoded.msg_type, msg_type,
            "msg_type {msg_type:?} did not survive round-trip"
        );
    }
}

/// All Phase 1 signing algorithms must survive a round-trip.
#[test]
fn all_signing_alg_ids_round_trip() {
    use AlgId::*;
    let signing_algs = [MlDsa44, MlDsa65, MlDsa87, FnDsaPadded512, SlhDsaSha2128s];

    for alg_id in signing_algs {
        let mut tx = synthetic_tx(0);
        tx.sig_alg_id = alg_id;

        let encoded = encode_tx(&tx).expect("encode");
        let decoded = decode_tx(&encoded).expect("decode");

        assert_eq!(
            decoded.sig_alg_id, alg_id,
            "sig_alg_id {alg_id:?} did not survive round-trip"
        );
    }
}
