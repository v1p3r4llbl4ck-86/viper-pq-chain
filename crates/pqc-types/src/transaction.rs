// SPDX-License-Identifier: Apache-2.0
//! Transaction envelope types — SPEC-TX-001 §3.

use crate::account::Address;
use pqc_crypto::AlgId;

/// Operation type routing identifier (u16) — SPEC-OPS-001 §3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MsgType {
    // Vault family
    VaultCreate = 0x0001,
    VaultPolicyUpdate = 0x0002,
    TokenTransfer = 0x0003,
    // Attestation family
    AttestationCreate = 0x0100,
    AttestationRevoke = 0x0101,
    ProofAnchor = 0x0102,
    // Key management family
    KeyAdd = 0x0200,
    KeyRotate = 0x0201,
    KeyRevoke = 0x0202,
    ConsensusKeyRotate = 0x0203,
    // Governance (reserved — SPEC-OPS-001 §13)
    GovernanceProposal = 0x0300,
    GovernanceVote = 0x0301,
    // Validator staking lifecycle (SPEC-VAL-001, TASK-064)
    ValidatorRegister = 0x0400,
    ValidatorExit = 0x0401,
    ValidatorUnjail = 0x0402,
    // Equivocation slashing (SPEC-SLASH-001, TASK-097)
    SubmitEquivocationEvidence = 0x0403,
    // On-chain validator peer-id rotation (ADR-047, TASK-159)
    ValidatorRotatePeerId = 0x0404,
    // Archival-overlay key registration (ADR-045, SPEC-ARCHIVAL-001 §4.5, TASK-161).
    //
    // SPEC-ARCHIVAL-001 §4.5 names opcode 0x0403 for this variant, but that
    // slot was already taken by SubmitEquivocationEvidence before the archival
    // spec landed. We keep the variant in the 0x04xx validator-lifecycle range
    // (next free slot) and treat §4.5's value as a documentation mismatch to
    // be reconciled in a spec erratum. The archival opcodes proper (§4.6) live
    // at 0x0700..=0x0702 as written in SPEC-ARCHIVAL-001 §4.6.
    ValidatorRegisterArchivalKey = 0x0405,
    // Archival-overlay transactions (ADR-045, SPEC-ARCHIVAL-001 §4.6, TASK-161).
    ArchivalRecordSubmit = 0x0700,
    ArchivalRecordAddAnchor = 0x0701,
    ArchivalRecordRenew = 0x0702,
}

impl MsgType {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x0001 => Some(Self::VaultCreate),
            0x0002 => Some(Self::VaultPolicyUpdate),
            0x0003 => Some(Self::TokenTransfer),
            0x0100 => Some(Self::AttestationCreate),
            0x0101 => Some(Self::AttestationRevoke),
            0x0102 => Some(Self::ProofAnchor),
            0x0200 => Some(Self::KeyAdd),
            0x0201 => Some(Self::KeyRotate),
            0x0202 => Some(Self::KeyRevoke),
            0x0203 => Some(Self::ConsensusKeyRotate),
            0x0300 => Some(Self::GovernanceProposal),
            0x0301 => Some(Self::GovernanceVote),
            0x0400 => Some(Self::ValidatorRegister),
            0x0401 => Some(Self::ValidatorExit),
            0x0402 => Some(Self::ValidatorUnjail),
            0x0403 => Some(Self::SubmitEquivocationEvidence),
            0x0404 => Some(Self::ValidatorRotatePeerId),
            0x0405 => Some(Self::ValidatorRegisterArchivalKey),
            0x0700 => Some(Self::ArchivalRecordSubmit),
            0x0701 => Some(Self::ArchivalRecordAddAnchor),
            0x0702 => Some(Self::ArchivalRecordRenew),
            _ => None,
        }
    }

    pub fn required_permission_bit(self) -> u32 {
        use crate::keyset::allowed_tx;
        match self {
            Self::VaultCreate | Self::VaultPolicyUpdate | Self::TokenTransfer => allowed_tx::VAULT,
            Self::AttestationCreate | Self::AttestationRevoke | Self::ProofAnchor => {
                allowed_tx::ATTESTATION
            }
            Self::KeyAdd | Self::KeyRotate | Self::KeyRevoke | Self::ConsensusKeyRotate => {
                allowed_tx::KEY_MGMT
            }
            Self::GovernanceProposal | Self::GovernanceVote => allowed_tx::GOVERNANCE,
            Self::ValidatorRegister
            | Self::ValidatorExit
            | Self::ValidatorUnjail
            | Self::SubmitEquivocationEvidence
            | Self::ValidatorRotatePeerId
            | Self::ValidatorRegisterArchivalKey
            | Self::ArchivalRecordSubmit
            | Self::ArchivalRecordAddAnchor
            | Self::ArchivalRecordRenew => allowed_tx::GOVERNANCE,
        }
    }
}

/// 32-byte transaction hash.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TxHash(pub [u8; 32]);

impl TxHash {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// Decoded transaction envelope — SPEC-TX-001 §3.
#[derive(Debug, Clone)]
pub struct Transaction {
    pub tx_version: u8,
    pub chain_id: Vec<u8>,
    pub msg_type: MsgType,
    pub sender: Address,
    pub nonce: u64,
    pub fee: u64,
    pub fee_tip: u64,
    pub gas_limit: u64,
    pub payload: Vec<u8>,
    pub sig_alg_id: AlgId,
    pub sig_key_version: u32,
    pub signature: Vec<u8>,
}
