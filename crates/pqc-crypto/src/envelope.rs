// SPDX-License-Identifier: Apache-2.0
//! TLV signature and public key envelopes — ADR-044 (crypto agility).
//!
//! Wire format:
//!   signature_envelope := <version:u8><algo_id:u16_le><sig_len:u16_le><raw_sig_bytes>
//!   public_key_envelope := <version:u8><algo_id:u16_le><pk_len:u16_le><raw_pk_bytes>
//!
//! version=1 for all current envelopes. Reserved for future changes.
//! algo_id is the AlgId as u16 little-endian.
//! sig_len / pk_len is the byte length of the payload as u16 little-endian.

use crate::{AlgId, CryptoError};

pub const ENVELOPE_VERSION: u8 = 1;
pub const HEADER_SIZE: usize = 5; // version(1) + algo_id(2) + len(2)

/// Encode a raw signature with its algorithm identifier into a TLV envelope.
pub fn encode_sig_envelope(alg_id: AlgId, sig_bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
    encode_envelope(alg_id, sig_bytes)
}

/// Decode a TLV signature envelope. Returns (AlgId, raw_sig_bytes).
pub fn decode_sig_envelope(bytes: &[u8]) -> Result<(AlgId, Vec<u8>), CryptoError> {
    decode_envelope(bytes)
}

/// Encode a raw public key with its algorithm identifier into a TLV envelope.
pub fn encode_pk_envelope(alg_id: AlgId, pk_bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
    encode_envelope(alg_id, pk_bytes)
}

/// Decode a TLV public key envelope. Returns (AlgId, raw_pk_bytes).
pub fn decode_pk_envelope(bytes: &[u8]) -> Result<(AlgId, Vec<u8>), CryptoError> {
    decode_envelope(bytes)
}

fn encode_envelope(alg_id: AlgId, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let payload_len = payload.len();
    if payload_len > u16::MAX as usize {
        return Err(CryptoError::InvalidSignatureSize);
    }
    let mut out = Vec::with_capacity(HEADER_SIZE + payload_len);
    out.push(ENVELOPE_VERSION);
    out.extend_from_slice(&alg_id.as_u16().to_le_bytes());
    out.extend_from_slice(&(payload_len as u16).to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

fn decode_envelope(bytes: &[u8]) -> Result<(AlgId, Vec<u8>), CryptoError> {
    if bytes.len() < HEADER_SIZE {
        return Err(CryptoError::InvalidSignatureSize);
    }
    let version = bytes[0];
    if version != ENVELOPE_VERSION {
        return Err(CryptoError::InvalidSignatureSize);
    }
    let algo_id_raw = u16::from_le_bytes([bytes[1], bytes[2]]);
    let payload_len = u16::from_le_bytes([bytes[3], bytes[4]]) as usize;
    if bytes.len() != HEADER_SIZE + payload_len {
        return Err(CryptoError::InvalidSignatureSize);
    }
    let alg_id = AlgId::from_u16(algo_id_raw).ok_or(CryptoError::InvalidSignatureSize)?;
    Ok((alg_id, bytes[HEADER_SIZE..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AlgId;

    #[test]
    fn round_trip_sig_envelope() {
        let raw_sig = vec![0xAB; 3309]; // ML-DSA-65 sig size
        let envelope = encode_sig_envelope(AlgId::MlDsa65, &raw_sig).unwrap();
        assert_eq!(envelope.len(), HEADER_SIZE + 3309);
        assert_eq!(envelope[0], ENVELOPE_VERSION);
        let (alg_id, decoded) = decode_sig_envelope(&envelope).unwrap();
        assert_eq!(alg_id, AlgId::MlDsa65);
        assert_eq!(decoded, raw_sig);
    }

    #[test]
    fn round_trip_pk_envelope() {
        let raw_pk = vec![0xCD; 1952]; // ML-DSA-65 pk size
        let envelope = encode_pk_envelope(AlgId::MlDsa65, &raw_pk).unwrap();
        let (alg_id, decoded) = decode_pk_envelope(&envelope).unwrap();
        assert_eq!(alg_id, AlgId::MlDsa65);
        assert_eq!(decoded, raw_pk);
    }

    #[test]
    fn wrong_length_is_rejected() {
        let raw_sig = vec![0xAB; 100];
        let mut envelope = encode_sig_envelope(AlgId::MlDsa65, &raw_sig).unwrap();
        envelope.push(0xFF); // extra byte
        assert!(decode_sig_envelope(&envelope).is_err());
    }

    #[test]
    fn truncated_header_is_rejected() {
        assert!(decode_sig_envelope(&[1, 0, 2]).is_err());
    }
}
