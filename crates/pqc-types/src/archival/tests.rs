// SPDX-License-Identifier: Apache-2.0
//! Tests for `archival`.
//!
//! Extracted from `archival.rs` 2026-05-10. `use super::*;`
//! brings every private item from the parent module into scope.

use super::*;

/// Build an address of the form `[b, b, ..., b]`.
fn addr(b: u8) -> [u8; 32] {
    [b; 32]
}

/// Build a pseudo SLH-DSA-SHAKE-256s signature of the correct wire size.
/// Deterministic in `seed` so the byte-stability pin is reproducible.
fn slh_sig(seed: u8) -> Vec<u8> {
    (0..SLH_DSA_SHAKE_256S_SIG_LEN)
        .map(|i| ((seed as usize + i) & 0xFF) as u8)
        .collect()
}

fn sample_tsa_ref() -> TsaRef {
    TsaRef {
        url: "https://tsa.aruba.it".to_string(),
        cert_fingerprint_sha256: [0xAB; 32],
        policy_oid: Some("1.2.3.4".to_string()),
    }
}

fn sample_rfc3161_anchor() -> TimestampAnchor {
    TimestampAnchor {
        kind: AnchorKind::Rfc3161Tsa,
        tsa_ref: Some(sample_tsa_ref()),
        external_hash: vec![0xDE, 0xAD, 0xBE, 0xEF],
        posted_at_height: 1000,
    }
}

// ── Required tests ────────────────────────────────────────────────────────

#[test]
fn archival_record_cbor_roundtrip_empty() {
    let r = ArchivalRecord {
        epoch_number: 0,
        epoch_root: [0u8; 32],
        signer_addresses: Vec::new(),
        slh_signatures: Vec::new(),
        timestamp_anchors: Vec::new(),
        evidence_record_version: 0,
    };
    let bytes = encode_archival_record(&r);
    let decoded = decode_archival_record(&bytes).expect("decode");
    assert_eq!(decoded, r);
}

#[test]
fn archival_record_cbor_roundtrip_one_signer() {
    let r = ArchivalRecord {
        epoch_number: 42,
        epoch_root: [0x11; 32],
        signer_addresses: vec![addr(0x01)],
        slh_signatures: vec![slh_sig(7)],
        timestamp_anchors: vec![sample_rfc3161_anchor()],
        evidence_record_version: 0,
    };
    let bytes = encode_archival_record(&r);
    let decoded = decode_archival_record(&bytes).expect("decode");
    assert_eq!(decoded, r);
}

#[test]
fn archival_record_cbor_roundtrip_many_signers() {
    // 24 validators = ADR-013 mainnet active-set size.
    let signers: Vec<[u8; 32]> = (0..24u8).map(addr).collect();
    let sigs: Vec<Vec<u8>> = (0..24u8).map(slh_sig).collect();

    let r = ArchivalRecord {
        epoch_number: 10_000,
        epoch_root: [0x5A; 32],
        signer_addresses: signers,
        slh_signatures: sigs,
        timestamp_anchors: vec![
            sample_rfc3161_anchor(),
            TimestampAnchor {
                kind: AnchorKind::BitcoinOpReturn,
                tsa_ref: None,
                external_hash: vec![0xCA; 32],
                posted_at_height: 2000,
            },
        ],
        evidence_record_version: 1,
    };
    let bytes = encode_archival_record(&r);
    let decoded = decode_archival_record(&bytes).expect("decode");
    assert_eq!(decoded, r);
}

#[test]
fn archival_record_rejects_unsorted_signers() {
    // Construct an encoded record with signers in the wrong order. We
    // encode by bypassing the type invariant on purpose (we write the
    // CBOR manually via ciborium Value), then feed the bytes to the
    // decoder which must reject.
    let r = ArchivalRecord {
        epoch_number: 7,
        epoch_root: [0x22; 32],
        signer_addresses: vec![addr(0x05), addr(0x02)], // unsorted
        slh_signatures: vec![slh_sig(1), slh_sig(2)],
        timestamp_anchors: Vec::new(),
        evidence_record_version: 0,
    };
    let bytes = encode_archival_record(&r);
    let err = decode_archival_record(&bytes).expect_err("must reject");
    assert_eq!(err, ArchivalDecodeError::SignersUnsorted);
}

#[test]
fn archival_record_rejects_signer_sig_count_mismatch() {
    let r = ArchivalRecord {
        epoch_number: 7,
        epoch_root: [0x22; 32],
        signer_addresses: vec![addr(0x01), addr(0x02)],
        slh_signatures: vec![slh_sig(1)], // only one sig for two signers
        timestamp_anchors: Vec::new(),
        evidence_record_version: 0,
    };
    let bytes = encode_archival_record(&r);
    let err = decode_archival_record(&bytes).expect_err("must reject");
    assert!(
        matches!(
            err,
            ArchivalDecodeError::SignerSignatureCountMismatch {
                signers: 2,
                sigs: 1
            }
        ),
        "got {err:?}"
    );
}

#[test]
fn timestamp_anchor_cbor_roundtrip_all_kinds() {
    let cases = vec![
        sample_rfc3161_anchor(),
        TimestampAnchor {
            kind: AnchorKind::BitcoinOpReturn,
            tsa_ref: None,
            external_hash: vec![0x01, 0x02, 0x03],
            posted_at_height: 111,
        },
        TimestampAnchor {
            kind: AnchorKind::EthereumL1,
            tsa_ref: None,
            external_hash: vec![0xFF; 32],
            posted_at_height: 222,
        },
        TimestampAnchor {
            kind: AnchorKind::OtherTsa,
            tsa_ref: None,
            external_hash: vec![],
            posted_at_height: 333,
        },
    ];

    for anchor in cases {
        let bytes = encode_timestamp_anchor(&anchor);
        let decoded = decode_timestamp_anchor(&bytes).expect("decode");
        assert_eq!(decoded, anchor);
    }
}

#[test]
fn validator_archival_key_cbor_roundtrip() {
    let k = ValidatorArchivalKey {
        operator: [0x77; 32],
        archival_alg_id: ARCHIVAL_ALG_ID_SLH_DSA_SHAKE_256S,
        archival_pk: vec![0xAA; SLH_DSA_SHAKE_256S_PK_LEN],
        registered_at_height: 12_345,
    };
    let bytes = encode_validator_archival_key(&k);
    let decoded = decode_validator_archival_key(&bytes).expect("decode");
    assert_eq!(decoded, k);
}

#[test]
fn archival_record_byte_stability_pin() {
    // Determinism pin: encoding the same input twice must produce
    // byte-identical output. This is the on-chain assurance we need for
    // state-root binding at TASK-161.
    let signers: Vec<[u8; 32]> = (0..8u8).map(addr).collect();
    let sigs: Vec<Vec<u8>> = (0..8u8).map(slh_sig).collect();

    let r = ArchivalRecord {
        epoch_number: 999,
        epoch_root: [0x33; 32],
        signer_addresses: signers,
        slh_signatures: sigs,
        timestamp_anchors: vec![sample_rfc3161_anchor()],
        evidence_record_version: 3,
    };

    let bytes1 = encode_archival_record(&r);
    let bytes2 = encode_archival_record(&r);
    assert_eq!(bytes1, bytes2, "encoder must be deterministic");

    // And round-trips to the same bytes.
    let decoded = decode_archival_record(&bytes1).expect("decode");
    let bytes3 = encode_archival_record(&decoded);
    assert_eq!(bytes1, bytes3, "decode/encode must be a fixed point");
}

// ── Supplementary coverage ────────────────────────────────────────────────

#[test]
fn tsa_ref_roundtrip_without_policy_oid() {
    let t = TsaRef {
        url: "https://tsa.infocert.it".to_string(),
        cert_fingerprint_sha256: [0x01; 32],
        policy_oid: None,
    };
    let bytes = encode_tsa_ref(&t);
    let decoded = decode_tsa_ref(&bytes).expect("decode");
    assert_eq!(decoded, t);
}

#[test]
fn anchor_kind_wire_codes_are_stable() {
    assert_eq!(AnchorKind::Rfc3161Tsa.as_u8(), 0x01);
    assert_eq!(AnchorKind::BitcoinOpReturn.as_u8(), 0x02);
    assert_eq!(AnchorKind::EthereumL1.as_u8(), 0x03);
    assert_eq!(AnchorKind::OtherTsa.as_u8(), 0xFF);

    assert_eq!(AnchorKind::from_u8(0x01), Some(AnchorKind::Rfc3161Tsa));
    assert_eq!(AnchorKind::from_u8(0x02), Some(AnchorKind::BitcoinOpReturn));
    assert_eq!(AnchorKind::from_u8(0x03), Some(AnchorKind::EthereumL1));
    assert_eq!(AnchorKind::from_u8(0xFF), Some(AnchorKind::OtherTsa));
    assert_eq!(AnchorKind::from_u8(0x04), None);
}

#[test]
fn timestamp_anchor_rejects_unknown_kind() {
    // Encode a map with an unknown kind byte and check the decoder.
    let map = Value::Map(vec![
        (
            Value::Integer(KEY_ANCHOR_KIND.into()),
            Value::Integer(0xAAu64.into()),
        ),
        (
            Value::Integer(KEY_ANCHOR_EXTERNAL_HASH.into()),
            Value::Bytes(vec![]),
        ),
        (
            Value::Integer(KEY_ANCHOR_POSTED_AT_HEIGHT.into()),
            Value::Integer(0u64.into()),
        ),
    ]);
    let mut bytes = Vec::new();
    ciborium::into_writer(&map, &mut bytes).unwrap();
    let err = decode_timestamp_anchor(&bytes).expect_err("must reject");
    assert_eq!(err, ArchivalDecodeError::UnknownAnchorKind(0xAA));
}

#[test]
fn timestamp_anchor_rejects_mismatched_tsa_ref() {
    // kind = BitcoinOpReturn but tsa_ref is Some — must be rejected.
    let map = Value::Map(vec![
        (
            Value::Integer(KEY_ANCHOR_KIND.into()),
            Value::Integer((AnchorKind::BitcoinOpReturn.as_u8() as u64).into()),
        ),
        (
            Value::Integer(KEY_ANCHOR_TSA_REF.into()),
            tsa_ref_to_cbor_value(&sample_tsa_ref()),
        ),
        (
            Value::Integer(KEY_ANCHOR_EXTERNAL_HASH.into()),
            Value::Bytes(vec![0xAB]),
        ),
        (
            Value::Integer(KEY_ANCHOR_POSTED_AT_HEIGHT.into()),
            Value::Integer(1u64.into()),
        ),
    ]);
    let mut bytes = Vec::new();
    ciborium::into_writer(&map, &mut bytes).unwrap();
    let err = decode_timestamp_anchor(&bytes).expect_err("must reject");
    assert_eq!(err, ArchivalDecodeError::AnchorTsaRefInconsistent);

    // And: kind = Rfc3161Tsa but tsa_ref is absent — must also be rejected.
    let map2 = Value::Map(vec![
        (
            Value::Integer(KEY_ANCHOR_KIND.into()),
            Value::Integer((AnchorKind::Rfc3161Tsa.as_u8() as u64).into()),
        ),
        (
            Value::Integer(KEY_ANCHOR_EXTERNAL_HASH.into()),
            Value::Bytes(vec![0xAB]),
        ),
        (
            Value::Integer(KEY_ANCHOR_POSTED_AT_HEIGHT.into()),
            Value::Integer(1u64.into()),
        ),
    ]);
    let mut bytes2 = Vec::new();
    ciborium::into_writer(&map2, &mut bytes2).unwrap();
    let err2 = decode_timestamp_anchor(&bytes2).expect_err("must reject");
    assert_eq!(err2, ArchivalDecodeError::AnchorTsaRefInconsistent);
}

#[test]
fn timestamp_anchor_rejects_oversized_external_hash() {
    let a = TimestampAnchor {
        kind: AnchorKind::OtherTsa,
        tsa_ref: None,
        external_hash: vec![0u8; TIMESTAMP_ANCHOR_EXTERNAL_HASH_MAX_LEN + 1],
        posted_at_height: 0,
    };
    let bytes = encode_timestamp_anchor(&a);
    let err = decode_timestamp_anchor(&bytes).expect_err("must reject");
    assert!(
        matches!(err, ArchivalDecodeError::ExternalHashTooLarge(n)
            if n == TIMESTAMP_ANCHOR_EXTERNAL_HASH_MAX_LEN + 1),
        "got {err:?}"
    );
}

#[test]
fn archival_record_rejects_short_epoch_root() {
    // Build an ArchivalRecord map with epoch_root of wrong length.
    let map = Value::Map(vec![
        (
            Value::Integer(KEY_AR_EPOCH_NUMBER.into()),
            Value::Integer(1u64.into()),
        ),
        (
            Value::Integer(KEY_AR_EPOCH_ROOT.into()),
            Value::Bytes(vec![0u8; 16]), // wrong: should be 32
        ),
        (
            Value::Integer(KEY_AR_SIGNER_ADDRESSES.into()),
            Value::Array(vec![]),
        ),
        (
            Value::Integer(KEY_AR_SLH_SIGNATURES.into()),
            Value::Array(vec![]),
        ),
        (
            Value::Integer(KEY_AR_TIMESTAMP_ANCHORS.into()),
            Value::Array(vec![]),
        ),
        (
            Value::Integer(KEY_AR_EVIDENCE_RECORD_VERSION.into()),
            Value::Integer(0u64.into()),
        ),
    ]);
    let mut bytes = Vec::new();
    ciborium::into_writer(&map, &mut bytes).unwrap();
    let err = decode_archival_record(&bytes).expect_err("must reject");
    assert!(
        matches!(
            err,
            ArchivalDecodeError::InvalidByteLength {
                expected: 32,
                actual: 16,
                ..
            }
        ),
        "got {err:?}"
    );
}

#[test]
fn epoch_number_is_a_newtype_wrapper() {
    let n = EpochNumber(17);
    assert_eq!(n.0, 17);
    assert!(n < EpochNumber(18));
}
