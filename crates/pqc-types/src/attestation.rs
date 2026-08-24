// SPDX-License-Identifier: Apache-2.0
//! Attestation state types — SPEC-OPS-001 §6.

use crate::account::Address;

/// 32-byte attestation identifier. Equal to the tx_hash of `attestation_create`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AttestationId(pub [u8; 32]);

impl AttestationId {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationRevocation {
    pub revoked_at_height: u64,
    pub revoker: Address,
    pub revocation_reason_hash: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    pub attestation_id: AttestationId,
    pub attester: Address,
    pub subject: [u8; 32],
    pub attestation_type: u16,
    pub content_hash: [u8; 32],
    pub schema_id: [u8; 32],
    pub metadata_hash: Option<[u8; 32]>,
    pub anchor_height: u64,
    pub expires_at_height: Option<u64>,
    pub status: AttestationStatus,
    pub revocation: Option<AttestationRevocation>,
}

pub fn is_supported_attestation_type(attestation_type: u16) -> bool {
    matches!(attestation_type, 0x0001..=0x0006)
}

pub fn attestation_type_name(attestation_type: u16) -> Option<&'static str> {
    match attestation_type {
        0x0001 => Some("identity_claim"),
        0x0002 => Some("document_notarization"),
        0x0003 => Some("ownership_assertion"),
        0x0004 => Some("custody_proof"),
        0x0005 => Some("metadata_anchor"),
        0x0006 => Some("compliance_record"),
        _ => None,
    }
}
