// SPDX-License-Identifier: Apache-2.0
//! Address derivation and Bech32m encoding — SPEC-ADDRESS-001 + ADR-053 §T1.3 + §T2.4.
//!
//! Canonical: `tagged_hash("VIPER-ADDR-V1", chain_id || sig_alg_id_be16 || pk_bytes)`
//! i.e. `SHAKE-256(H(tag) || H(tag) || chain_id || sig_alg_id_be16 || pk_bytes)[0..32]`.
//!
//! Domain separation via (a) the BIP340 double-tagged `VIPER-ADDR-V1` outer
//! (defends CVE-2012-2459-class domain-tag collisions per ADR-053 §T2.4),
//! (b) the `chain_id` that binds an address to one host chain (cross-chain
//! replay resistance at the address layer — a pk that maps to address A
//! on viper-pq-1 maps to a different address on any other chain), and
//! (c) the 2-byte algorithm identifier that distinguishes pk bytes under
//! different signature algorithms.

use crate::alg::AlgId;
use crate::hash::tagged_hash;

/// Domain-separation tag for viper-pq-1 address derivation
/// (ADR-053 §T1.3, absorbed as a BIP340 double-tag per §T2.4).
pub const ADDRESS_DOMAIN_V1: &[u8] = b"VIPER-ADDR-V1";

/// Canonical address derivation per SPEC-ADDRESS-001 + ADR-053 §T1.3 + §T2.4.
///
/// ```text
/// address = tagged_hash("VIPER-ADDR-V1", chain_id || sig_alg_id_be16 || pk_bytes)
///         = SHAKE-256(H(tag) || H(tag) || chain_id || sig_alg_id_be16 || pk_bytes)[..32]
/// ```
///
/// Bytes after the two tag hashes are absorbed contiguously (no length
/// framing); the field layout is unambiguous per-chain because `chain_id`
/// is fixed for a given host chain, `sig_alg_id_be16` is exactly 2 bytes,
/// and `pk_bytes` length is determined by `alg_id` via the active
/// algorithm registry.
pub fn derive_address(chain_id: &[u8], alg_id: AlgId, pk_bytes: &[u8]) -> [u8; 32] {
    let mut body = Vec::with_capacity(chain_id.len() + 2 + pk_bytes.len());
    body.extend_from_slice(chain_id);
    body.extend_from_slice(&alg_id.as_u16().to_be_bytes());
    body.extend_from_slice(pk_bytes);
    tagged_hash(ADDRESS_DOMAIN_V1, &body)
}

/// Encode a raw 32-byte address to Bech32m with the given HRP.
///
/// HRP values: `"vpr"` for mainnet, `"vpt"` for testnet/devnet.
/// Returns a lowercase Bech32m string per BIP-350.
pub fn address_to_bech32m(raw: &[u8; 32], hrp: &str) -> Result<String, crate::CryptoError> {
    use bech32::{Bech32m, Hrp};

    let hrp =
        Hrp::parse(hrp).map_err(|e| crate::CryptoError::Bech32mEncodingError(e.to_string()))?;
    bech32::encode::<Bech32m>(hrp, raw)
        .map_err(|e| crate::CryptoError::Bech32mEncodingError(e.to_string()))
}

/// Decode a Bech32m address string to a raw 32-byte address.
///
/// Returns `None` if:
/// - The string is not valid Bech32m
/// - The decoded data is not exactly 32 bytes
///
/// The caller is responsible for checking the HRP matches the expected network.
pub fn bech32m_to_address(encoded: &str) -> Option<[u8; 32]> {
    let (_hrp, data) = bech32::decode(encoded).ok()?;
    // bech32 crate v0.11 decode returns the raw byte data directly
    if data.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&data);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CHAIN_ID: &[u8] = b"viper-pq-1";

    #[test]
    fn derive_address_alg_id_domain_separation() {
        // Same pk bytes + same chain_id with different alg_id must produce different addresses.
        let pk = [0xABu8; 64];
        let addr_44 = derive_address(TEST_CHAIN_ID, AlgId::MlDsa44, &pk);
        let addr_65 = derive_address(TEST_CHAIN_ID, AlgId::MlDsa65, &pk);
        let addr_87 = derive_address(TEST_CHAIN_ID, AlgId::MlDsa87, &pk);
        assert_ne!(addr_44, addr_65);
        assert_ne!(addr_65, addr_87);
        assert_ne!(addr_44, addr_87);
    }

    #[test]
    fn derive_address_chain_id_domain_separation() {
        // Same alg_id + same pk bytes under different chain_ids must produce different addresses.
        // ADR-053 §T1.3 cross-chain replay resistance at the address layer.
        let pk = [0xABu8; 64];
        let addr_a = derive_address(b"viper-pq-1", AlgId::MlDsa65, &pk);
        let addr_b = derive_address(b"viper-pq-2", AlgId::MlDsa65, &pk);
        let addr_empty = derive_address(b"", AlgId::MlDsa65, &pk);
        assert_ne!(addr_a, addr_b);
        assert_ne!(addr_a, addr_empty);
        assert_ne!(addr_b, addr_empty);
    }

    #[test]
    fn derive_address_deterministic() {
        let pk = [0x42u8; 128];
        let a = derive_address(TEST_CHAIN_ID, AlgId::MlDsa65, &pk);
        let b = derive_address(TEST_CHAIN_ID, AlgId::MlDsa65, &pk);
        assert_eq!(a, b);
    }

    #[test]
    fn derive_address_preimage_pin() {
        // Regression guard: if the preimage layout changes, this test
        // breaks and forces reviewers to acknowledge the
        // consensus-breaking migration. Body = chain_id || alg_id_be16
        // || pk, wrapped in BIP340 double-tagged hashing under
        // VIPER-ADDR-V1 per ADR-053 §T2.4.
        let pk = [0u8; 1952];
        let addr = derive_address(b"viper-pq-1", AlgId::MlDsa65, &pk);
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(b"viper-pq-1");
        body.extend_from_slice(&AlgId::MlDsa65.as_u16().to_be_bytes());
        body.extend_from_slice(&pk);
        let expected = crate::hash::tagged_hash(b"VIPER-ADDR-V1", &body);
        assert_eq!(addr, expected);
    }

    #[test]
    fn bech32m_roundtrip() {
        let raw = [0x01u8; 32];
        let encoded = address_to_bech32m(&raw, "vpr").expect("encode failed");
        assert!(encoded.starts_with("vpr1"));
        let decoded = bech32m_to_address(&encoded).expect("decode failed");
        assert_eq!(decoded, raw);
    }

    #[test]
    fn bech32m_testnet_hrp() {
        let raw = [0xFFu8; 32];
        let encoded = address_to_bech32m(&raw, "vpt").expect("encode failed");
        assert!(encoded.starts_with("vpt1"));
        let decoded = bech32m_to_address(&encoded).expect("decode failed");
        assert_eq!(decoded, raw);
    }

    #[test]
    fn bech32m_invalid_returns_none() {
        assert!(bech32m_to_address("not-a-bech32m-string").is_none());
        assert!(bech32m_to_address("").is_none());
    }
}
