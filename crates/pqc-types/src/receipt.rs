// SPDX-License-Identifier: Apache-2.0
//! Transaction receipt types — SPEC-RECEIPT-001.
//!
//! A receipt is a deterministic CBOR-encoded record of execution outcome for a
//! single transaction. Receipts are produced at block commit time, stored
//! parallel to the transaction list in the block body, and anchored in the
//! block header via `receipts_root`.
//!
//! **Audit scope**: `Receipt` CBOR encoding and `compute_receipts_root` are
//! cryptographically load-bearing (SPEC-RECEIPT-001 §5, §6) and are in scope
//! for external audit.

use pqc_crypto::tagged_hash;

/// Execution outcome for a single transaction — SPEC-RECEIPT-001 §5.
///
/// All fields are required except `error_code`, which MUST be present when
/// and only when `status == 0x00` (failure).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    /// CBOR key 1: SHAKE-256 hash of the raw transaction bytes (32 bytes).
    pub tx_hash: [u8; 32],
    /// CBOR key 2: Height of the block in which this transaction was included.
    pub block_height: u64,
    /// CBOR key 3: Execution outcome — `0x01` = success, `0x00` = failure.
    pub status: u8,
    /// CBOR key 4: Execution units consumed.
    pub gas_used: u64,
    /// CBOR key 5: Venom deducted from the sender's account.
    pub fee_charged: u64,
    /// CBOR key 6: Error code string. Present iff `status == 0x00`.
    /// MUST NOT exceed 64 bytes (SPEC-RECEIPT-001 §5.3).
    pub error_code: Option<String>,
}

// ── CBOR encoding (deterministic, integer keys, ascending key order) ──────────
//
// The encoding is hand-rolled rather than derived with `serde` to guarantee
// the exact key assignment and field order required by SPEC-RECEIPT-001 §5.2
// without depending on a serde derive that might reorder fields.
//
// Key assignment:
//   1 → tx_hash      (bstr, 32 bytes)
//   2 → block_height (uint)
//   3 → status       (uint)
//   4 → gas_used     (uint)
//   5 → fee_charged  (uint)
//   6 → error_code   (tstr, OPTIONAL — absent on success)

/// Encode a `Receipt` as deterministic CBOR with integer keys per
/// SPEC-RECEIPT-001 §5.2. Fields appear in ascending key order; absent
/// OPTIONAL fields are omitted (not encoded as null).
pub fn encode_receipt(receipt: &Receipt) -> Vec<u8> {
    // Invariant: error_code must be absent on success (status == 0x01).
    debug_assert!(
        !(receipt.status == 0x01 && receipt.error_code.is_some()),
        "encode_receipt: error_code must be absent when status == 0x01"
    );
    // Determine map length: always 5 required fields, plus 1 optional.
    let map_len: u64 = if receipt.error_code.is_some() { 6 } else { 5 };

    let mut buf = Vec::with_capacity(256);

    // CBOR map header: major type 5 (map), length = map_len.
    write_cbor_uint_header(&mut buf, 5, map_len);

    // Key 1: tx_hash (bstr, 32 bytes)
    write_cbor_uint(&mut buf, 1);
    write_cbor_bstr(&mut buf, &receipt.tx_hash);

    // Key 2: block_height (uint)
    write_cbor_uint(&mut buf, 2);
    write_cbor_uint(&mut buf, receipt.block_height);

    // Key 3: status (uint)
    write_cbor_uint(&mut buf, 3);
    write_cbor_uint(&mut buf, u64::from(receipt.status));

    // Key 4: gas_used (uint)
    write_cbor_uint(&mut buf, 4);
    write_cbor_uint(&mut buf, receipt.gas_used);

    // Key 5: fee_charged (uint)
    write_cbor_uint(&mut buf, 5);
    write_cbor_uint(&mut buf, receipt.fee_charged);

    // Key 6: error_code (tstr) — OPTIONAL, present only on failure.
    if let Some(ref code) = receipt.error_code {
        write_cbor_uint(&mut buf, 6);
        write_cbor_tstr(&mut buf, code);
    }

    buf
}

/// Decode a deterministic CBOR-encoded `Receipt` per SPEC-RECEIPT-001 §5.2.
///
/// Returns `Err` if the encoding is malformed, a required field is missing,
/// or an invariant is violated (e.g. `error_code` present on success).
pub fn decode_receipt(bytes: &[u8]) -> Result<Receipt, &'static str> {
    // Use ciborium for parsing; we validate key order and field presence manually.
    use ciborium::value::Value;

    let value: Value = ciborium::from_reader(bytes).map_err(|_| "cbor decode failed")?;
    let Value::Map(pairs) = value else {
        return Err("receipt must be a CBOR map");
    };

    let mut tx_hash: Option<[u8; 32]> = None;
    let mut block_height: Option<u64> = None;
    let mut status: Option<u8> = None;
    let mut gas_used: Option<u64> = None;
    let mut fee_charged: Option<u64> = None;
    let mut error_code: Option<String> = None;

    let mut last_key: Option<u64> = None;

    for (k, v) in pairs {
        let key = match k {
            Value::Integer(i) => {
                let n: u64 = i128::from(i).try_into().map_err(|_| "key out of range")?;
                n
            }
            _ => return Err("receipt keys must be integers"),
        };

        // Enforce ascending key order (deterministic CBOR).
        if let Some(prev) = last_key {
            if key <= prev {
                return Err("receipt keys not in ascending order");
            }
        }
        last_key = Some(key);

        match key {
            1 => {
                let Value::Bytes(b) = v else {
                    return Err("tx_hash must be bstr");
                };
                if b.len() != 32 {
                    return Err("tx_hash must be 32 bytes");
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                tx_hash = Some(arr);
            }
            2 => {
                let n = cbor_value_to_u64(v)?;
                block_height = Some(n);
            }
            3 => {
                let n = cbor_value_to_u64(v)?;
                if n > 1 {
                    return Err("status must be 0x00 or 0x01");
                }
                status = Some(n as u8);
            }
            4 => {
                gas_used = Some(cbor_value_to_u64(v)?);
            }
            5 => {
                fee_charged = Some(cbor_value_to_u64(v)?);
            }
            6 => {
                let Value::Text(s) = v else {
                    return Err("error_code must be tstr");
                };
                if s.len() > 64 {
                    return Err("error_code exceeds 64 bytes");
                }
                error_code = Some(s);
            }
            _ => return Err("unknown receipt key"),
        }
    }

    let tx_hash = tx_hash.ok_or("missing tx_hash")?;
    let block_height = block_height.ok_or("missing block_height")?;
    let status = status.ok_or("missing status")?;
    let gas_used = gas_used.ok_or("missing gas_used")?;
    let fee_charged = fee_charged.ok_or("missing fee_charged")?;

    // Invariant: error_code present iff status == 0x00.
    if status == 0x01 && error_code.is_some() {
        return Err("error_code must not be present on success");
    }
    if status == 0x00 && error_code.is_none() {
        return Err("error_code must be present on failure");
    }

    Ok(Receipt {
        tx_hash,
        block_height,
        status,
        gas_used,
        fee_charged,
        error_code,
    })
}

// ── receipt_hash ──────────────────────────────────────────────────────────────

/// Compute the receipt hash for a single receipt: `SHAKE-256(cbor_encode(receipt), 32)`.
///
/// No domain separator is applied at this step; the domain separator is applied
/// at the `receipts_root` computation level (SPEC-RECEIPT-001 §6.2 Step 3).
/// Pure content hash — not a tagged-hash site per ADR-053 §T2.4.
pub fn receipt_hash(receipt: &Receipt) -> [u8; 32] {
    let encoded = encode_receipt(receipt);
    pqc_crypto::shake256_32(&encoded)
}

// ── receipts_root ─────────────────────────────────────────────────────────────

/// Compute the `receipts_root` commitment over an ordered set of receipts.
///
/// Algorithm (SPEC-RECEIPT-001 §6.2 + ADR-053 §T2.4):
/// 1. Hash each receipt with `receipt_hash`.
/// 2. Sort receipt hashes lexicographically.
/// 3. Compute `tagged_hash("VIPER-RECEIPTS-V1", sorted_hashes...)`.
///
/// Empty block edge case: if `receipts` is empty, the result is
/// `tagged_hash("VIPER-RECEIPTS-V1", &[])` (step 3 over an empty body).
///
/// The sort is applied to receipt hashes (not the receipts themselves), so the
/// canonical receipt order (insertion order, parallel to the tx list) is
/// preserved in `block.receipts`. This function is deterministic: the same set
/// of receipts always produces the same root regardless of insertion order.
pub fn compute_receipts_root(receipts: &[Receipt]) -> [u8; 32] {
    const DOMAIN: &[u8] = b"VIPER-RECEIPTS-V1";

    if receipts.is_empty() {
        // Empty block edge case: tagged-hash over empty body.
        return tagged_hash(DOMAIN, &[]);
    }

    // Step 1+2: compute and sort receipt hashes.
    let mut hashes: Vec<[u8; 32]> = receipts.iter().map(receipt_hash).collect();
    hashes.sort_unstable();

    // Step 3: tagged_hash over concatenated sorted hashes.
    let mut body = Vec::with_capacity(hashes.len() * 32);
    for h in &hashes {
        body.extend_from_slice(h);
    }
    tagged_hash(DOMAIN, &body)
}

// ── CBOR primitives ───────────────────────────────────────────────────────────
//
// Minimal deterministic CBOR encoding helpers. These implement exactly the
// subset needed for `encode_receipt` and are not a general-purpose CBOR library.

/// Write a CBOR unsigned integer with the given major type and value.
///
/// Major types: 0=uint, 1=nint, 2=bstr, 3=tstr, 4=array, 5=map.
/// The value is encoded with the minimum required additional info bytes.
fn write_cbor_uint_header(buf: &mut Vec<u8>, major: u8, value: u64) {
    let major_bits = major << 5;
    match value {
        0..=23 => buf.push(major_bits | (value as u8)),
        24..=0xFF => {
            buf.push(major_bits | 24);
            buf.push(value as u8);
        }
        0x100..=0xFFFF => {
            buf.push(major_bits | 25);
            buf.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x10000..=0xFFFF_FFFF => {
            buf.push(major_bits | 26);
            buf.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            buf.push(major_bits | 27);
            buf.extend_from_slice(&value.to_be_bytes());
        }
    }
}

/// Write a CBOR unsigned integer (major type 0).
fn write_cbor_uint(buf: &mut Vec<u8>, value: u64) {
    write_cbor_uint_header(buf, 0, value);
}

/// Write a CBOR byte string (major type 2).
fn write_cbor_bstr(buf: &mut Vec<u8>, bytes: &[u8]) {
    write_cbor_uint_header(buf, 2, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

/// Write a CBOR text string (major type 3).
fn write_cbor_tstr(buf: &mut Vec<u8>, text: &str) {
    let bytes = text.as_bytes();
    write_cbor_uint_header(buf, 3, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

// ── decode helpers ────────────────────────────────────────────────────────────

fn cbor_value_to_u64(v: ciborium::value::Value) -> Result<u64, &'static str> {
    use ciborium::value::Value;
    match v {
        Value::Integer(i) => i128::from(i)
            .try_into()
            .map_err(|_| "integer out of u64 range"),
        _ => Err("expected integer"),
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
