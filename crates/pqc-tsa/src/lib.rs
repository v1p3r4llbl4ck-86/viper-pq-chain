// SPDX-License-Identifier: Apache-2.0
//! Minimal RFC 3161 `TimeStampReq` DER encoder (SHA-256 only).
//!
//! Shared by `viper-archival-sidecar` (in-band archival overlay TSA
//! anchoring per SPEC-ARCHIVAL-001 §6) and `pqcd::cold_storage`
//! (out-of-band cold-storage manifest anchoring per SPEC-COLD-STORAGE-001
//! §9.2 / ADR-060). Extracted to break the duplication that ADR-060 D7
//! flagged as "future cleanup" — the sidecar already depends on `pqcd`,
//! so importing back would create a cycle; a third consumer made the
//! shared-crate the right call.
//!
//! # Wire format (RFC 3161 §2.4.1)
//!
//! ```text
//! TimeStampReq ::= SEQUENCE {
//!     version       INTEGER  { v1(1) },
//!     messageImprint MessageImprint,
//!     reqPolicy     TSAPolicyId              OPTIONAL,
//!     nonce         INTEGER                  OPTIONAL,
//!     certReq       BOOLEAN                  DEFAULT FALSE,
//!     extensions    [0] IMPLICIT Extensions  OPTIONAL
//! }
//! MessageImprint ::= SEQUENCE {
//!     hashAlgorithm  AlgorithmIdentifier,
//!     hashedMessage  OCTET STRING
//! }
//! ```
//!
//! This crate emits the minimal form: `{ version=1,
//! messageImprint=(SHA-256, hash), certReq=TRUE }`. `reqPolicy` and
//! `nonce` are omitted — both are optional and TSAs we target accept
//! their absence. `certReq=TRUE` asks the TSA to include its certificate
//! chain in the reply (useful for the external auditor in §7).
//!
//! # Why hand-roll
//!
//! Pulling in `rasn` (the pure-Rust ASN.1 framework) is ~2 MB of
//! compile-time and ships a parser we only use for outbound encode. The
//! handful of DER primitives this crate needs (SEQUENCE, INTEGER,
//! BOOLEAN, OCTET STRING, NULL, OID) are under 100 LoC. When governance
//! adds a second digest alg (SHA-512 per RFC 5816), extend the OID table
//! rather than reaching for a dep.
//!
//! The reply DER is forwarded opaquely on both consumer sides — the
//! chain does not verify the TST cryptographically on apply. That
//! responsibility belongs to the auditor (SPEC-ARCHIVAL-001 §6.1).

#![forbid(unsafe_code)]
// Indexes used in this module are all bounded by construction —
// `to_be_bytes()` always returns 8 bytes, OID tables are static. The
// alternative `.get(n)` form adds runtime checks for cases that cannot
// occur, hurting both readability and audit clarity.
#![allow(clippy::indexing_slicing)]

/// SHA-256 OID (2.16.840.1.101.3.4.2.1) encoded as DER object identifier
/// bytes (without the outer tag/length prefix).
const SHA256_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

/// Build a RFC 3161 `TimeStampReq` DER blob for the SHA-256 digest of
/// the provided 32-byte hash. Requests `certReq=TRUE` and omits the
/// optional `reqPolicy`, `nonce`, and `extensions`.
///
/// # Determinism
///
/// Output is byte-deterministic for any given input — the function uses
/// no clock, no RNG, no allocator-dependent ordering. Pinned by
/// `timestamp_request_is_deterministic` in this crate's test module.
pub fn build_timestamp_request(sha256_digest: &[u8; 32]) -> Vec<u8> {
    // AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY }
    let mut alg_id_body = Vec::new();
    der_object_identifier(SHA256_OID, &mut alg_id_body);
    der_null(&mut alg_id_body);
    let mut alg_id = Vec::new();
    der_sequence(&alg_id_body, &mut alg_id);

    // MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier,
    //                               hashedMessage OCTET STRING }
    let mut imprint_body = Vec::new();
    imprint_body.extend_from_slice(&alg_id);
    der_octet_string(sha256_digest, &mut imprint_body);
    let mut imprint = Vec::new();
    der_sequence(&imprint_body, &mut imprint);

    // TimeStampReq ::= SEQUENCE { version=1, messageImprint, certReq=TRUE }
    let mut req_body = Vec::new();
    der_integer_u64(1, &mut req_body);
    req_body.extend_from_slice(&imprint);
    der_boolean(true, &mut req_body);

    let mut out = Vec::new();
    der_sequence(&req_body, &mut out);
    out
}

// ── DER helpers ──────────────────────────────────────────────────────────────

fn der_length(len: usize, out: &mut Vec<u8>) {
    if len < 128 {
        out.push(len as u8);
        return;
    }
    let mut bytes = Vec::with_capacity(4);
    let mut n = len;
    while n > 0 {
        bytes.push((n & 0xff) as u8);
        n >>= 8;
    }
    bytes.reverse();
    out.push(0x80 | (bytes.len() as u8));
    out.extend_from_slice(&bytes);
}

fn der_tag(tag: u8, content: &[u8], out: &mut Vec<u8>) {
    out.push(tag);
    der_length(content.len(), out);
    out.extend_from_slice(content);
}

fn der_integer_u64(n: u64, out: &mut Vec<u8>) {
    // Strip leading zeros, add a leading 0x00 if the MSB would otherwise
    // make the INTEGER appear negative (DER sign convention).
    let raw = n.to_be_bytes();
    let mut start = 0;
    while start < raw.len() - 1 && raw[start] == 0 {
        start += 1;
    }
    let mut body = raw[start..].to_vec();
    if body[0] >= 0x80 {
        body.insert(0, 0x00);
    }
    der_tag(0x02, &body, out);
}

fn der_boolean(value: bool, out: &mut Vec<u8>) {
    der_tag(0x01, if value { &[0xff] } else { &[0x00] }, out);
}

fn der_octet_string(bytes: &[u8], out: &mut Vec<u8>) {
    der_tag(0x04, bytes, out);
}

fn der_null(out: &mut Vec<u8>) {
    out.extend_from_slice(&[0x05, 0x00]);
}

fn der_object_identifier(oid_content: &[u8], out: &mut Vec<u8>) {
    der_tag(0x06, oid_content, out);
}

fn der_sequence(content: &[u8], out: &mut Vec<u8>) {
    der_tag(0x30, content, out);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_request_starts_with_sequence_tag() {
        let digest = [0x42u8; 32];
        let der = build_timestamp_request(&digest);
        assert_eq!(der[0], 0x30, "TimeStampReq must start with SEQUENCE tag");
        let has_digest_substring = der.windows(32).any(|w| w == digest);
        assert!(has_digest_substring, "digest bytes missing from DER");
        // Hard-upper-bound: minimal request is ≤ 80 bytes.
        assert!(
            der.len() < 80,
            "unexpectedly large TimeStampReq: {} bytes",
            der.len()
        );
    }

    #[test]
    fn timestamp_request_is_deterministic() {
        let digest = [0xCDu8; 32];
        let a = build_timestamp_request(&digest);
        let b = build_timestamp_request(&digest);
        assert_eq!(a, b);
    }

    #[test]
    fn timestamp_request_carries_sha256_oid() {
        let digest = [0x99u8; 32];
        let der = build_timestamp_request(&digest);
        let oid = SHA256_OID;
        assert!(
            der.windows(oid.len()).any(|w| w == oid),
            "SHA-256 OID missing from DER"
        );
    }

    #[test]
    fn der_length_short_form() {
        let mut out = Vec::new();
        der_length(0, &mut out);
        assert_eq!(out, vec![0x00]);

        out.clear();
        der_length(127, &mut out);
        assert_eq!(out, vec![0x7F]);
    }

    #[test]
    fn der_length_long_form() {
        let mut out = Vec::new();
        der_length(128, &mut out);
        assert_eq!(out, vec![0x81, 0x80]);

        out.clear();
        der_length(256, &mut out);
        assert_eq!(out, vec![0x82, 0x01, 0x00]);

        out.clear();
        der_length(65535, &mut out);
        assert_eq!(out, vec![0x82, 0xff, 0xff]);
    }

    #[test]
    fn der_integer_u64_strips_leading_zeros() {
        let mut out = Vec::new();
        der_integer_u64(1, &mut out);
        assert_eq!(out, vec![0x02, 0x01, 0x01]);

        out.clear();
        der_integer_u64(0, &mut out);
        assert_eq!(out, vec![0x02, 0x01, 0x00]);
    }

    #[test]
    fn der_integer_u64_inserts_sign_byte_when_msb_set() {
        let mut out = Vec::new();
        der_integer_u64(0x80, &mut out);
        // 0x80 alone would be negative under DER sign convention; DER must
        // insert a leading 0x00 to keep the INTEGER positive.
        assert_eq!(out, vec![0x02, 0x02, 0x00, 0x80]);
    }

    #[test]
    fn der_boolean_uses_canonical_encoding() {
        let mut out = Vec::new();
        der_boolean(true, &mut out);
        // DER's BOOLEAN: TRUE is canonically 0xFF (any non-zero would be valid
        // BER, but DER pins it).
        assert_eq!(out, vec![0x01, 0x01, 0xff]);

        out.clear();
        der_boolean(false, &mut out);
        assert_eq!(out, vec![0x01, 0x01, 0x00]);
    }
}
