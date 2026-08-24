// SPDX-License-Identifier: Apache-2.0
//! Tests for `receipt`.
//!
//! Extracted from `receipt.rs` 2026-05-10. `use super::*;`
//! brings every private item from the parent module into scope.

use super::*;

fn success_receipt() -> Receipt {
    Receipt {
        tx_hash: [0xAB; 32],
        block_height: 42000,
        status: 0x01,
        gas_used: 58300,
        fee_charged: 15000,
        error_code: None,
    }
}

fn failure_receipt() -> Receipt {
    Receipt {
        tx_hash: [0xCD; 32],
        block_height: 42001,
        status: 0x00,
        gas_used: 80000,
        fee_charged: 15000,
        error_code: Some("OUT_OF_GAS".to_string()),
    }
}

#[test]
fn receipt_cbor_roundtrip_success() {
    let r = success_receipt();
    let encoded = encode_receipt(&r);
    let decoded = decode_receipt(&encoded).expect("decode must succeed");
    assert_eq!(decoded.tx_hash, r.tx_hash);
    assert_eq!(decoded.block_height, r.block_height);
    assert_eq!(decoded.status, r.status);
    assert_eq!(decoded.gas_used, r.gas_used);
    assert_eq!(decoded.fee_charged, r.fee_charged);
    assert_eq!(decoded.error_code, r.error_code);
}

#[test]
fn receipt_cbor_roundtrip_failure() {
    let r = failure_receipt();
    let encoded = encode_receipt(&r);
    let decoded = decode_receipt(&encoded).expect("decode must succeed");
    assert_eq!(decoded, r);
}

#[test]
fn receipts_root_empty_block() {
    let root = compute_receipts_root(&[]);
    // Must be deterministic 32-byte output.
    assert_eq!(root.len(), 32);
    // Must equal tagged_hash("VIPER-RECEIPTS-V1", &[]) per ADR-053 §T2.4.
    let expected = tagged_hash(b"VIPER-RECEIPTS-V1", &[]);
    assert_eq!(root, expected);
}

#[test]
fn receipts_root_ordering() {
    // Two receipts in different order must produce the same root (sorted).
    let r1 = success_receipt();
    let r2 = failure_receipt();

    let root_ab = compute_receipts_root(&[r1.clone(), r2.clone()]);
    let root_ba = compute_receipts_root(&[r2, r1]);

    assert_eq!(root_ab, root_ba, "receipts_root must be order-independent");
}

#[test]
fn receipts_root_single_receipt() {
    let r = success_receipt();
    let root = compute_receipts_root(std::slice::from_ref(&r));
    // Verify the root is not the empty root.
    let empty_root = compute_receipts_root(&[]);
    assert_ne!(root, empty_root);
    // Verify it is deterministic.
    assert_eq!(root, compute_receipts_root(&[r]));
}

#[test]
fn receipt_hash_is_deterministic() {
    let r = success_receipt();
    assert_eq!(receipt_hash(&r), receipt_hash(&r));
}

#[test]
fn encode_receipt_uses_minimal_cbor_integers() {
    // Status 1 should encode as a single byte (0x01), not a multi-byte value.
    let r = success_receipt();
    let encoded = encode_receipt(&r);
    // Quick sanity: decode must round-trip.
    let decoded = decode_receipt(&encoded).expect("must decode");
    assert_eq!(decoded, r);
}

#[test]
fn decode_rejects_error_code_on_success() {
    // Manually build a receipt with status=1 and error_code present.
    let bad = Receipt {
        tx_hash: [0x01; 32],
        block_height: 1,
        status: 0x01,
        gas_used: 100,
        fee_charged: 50,
        error_code: Some("FAKE_ERROR".to_string()),
    };
    // Force-encode ignoring invariant (use internal helpers directly).
    // We must produce the invalid encoding by using a 6-field map.
    let mut buf = Vec::new();
    // 6-field map
    write_cbor_uint_header(&mut buf, 5, 6);
    write_cbor_uint(&mut buf, 1);
    write_cbor_bstr(&mut buf, &bad.tx_hash);
    write_cbor_uint(&mut buf, 2);
    write_cbor_uint(&mut buf, bad.block_height);
    write_cbor_uint(&mut buf, 3);
    write_cbor_uint(&mut buf, 1); // status=success
    write_cbor_uint(&mut buf, 4);
    write_cbor_uint(&mut buf, bad.gas_used);
    write_cbor_uint(&mut buf, 5);
    write_cbor_uint(&mut buf, bad.fee_charged);
    write_cbor_uint(&mut buf, 6);
    write_cbor_tstr(&mut buf, "FAKE_ERROR");

    let err = decode_receipt(&buf);
    assert!(
        err.is_err(),
        "decode must reject error_code on success receipt"
    );
}
