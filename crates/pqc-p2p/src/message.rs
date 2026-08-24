// SPDX-License-Identifier: BUSL-1.1
//! P2P gossip message types — ADR-041.

use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

/// Type tag for gossip messages (for routing and IDONTWANT suppression).
///
/// Serialized as a CBOR unsigned integer using the `#[repr(u8)]` discriminant
/// (SPEC-P2P-002 §4.2). `serde_repr` is required — plain `#[derive(Serialize)]`
/// would encode the variant name as a text string, which is the pre-M1
/// behaviour reconciled by TASK-147.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum MessageType {
    Block = 0x01,
    ConsensusVote = 0x02,
    Transaction = 0x03,
    ValidatorUpdate = 0x04,
    /// Sync-committee compact-header attestation (SPEC-LIGHT-CLIENT-001
    /// §5.2). Payload is the CBOR encoding of `pqc_consensus::
    /// light_client::LightClientAttestation`.
    LightClientAttestation = 0x05,
}

/// A message propagated over GossipSub.
///
/// The `payload` is CBOR-encoded and signed at the application layer.
/// GossipSub handles transport-level deduplication via IDONTWANT (v1.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipMessage {
    pub msg_type: MessageType,
    /// Protocol version for this message type.
    pub version: u8,
    /// Chain ID to prevent cross-network delivery (belt-and-suspenders with topics).
    pub chain_id: String,
    /// CBOR-encoded payload (block, vote, tx, etc.).
    pub payload: Vec<u8>,
}

impl GossipMessage {
    pub fn new(msg_type: MessageType, chain_id: impl Into<String>, payload: Vec<u8>) -> Self {
        Self {
            msg_type,
            version: 1,
            chain_id: chain_id.into(),
            payload,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(msg: &GossipMessage) -> GossipMessage {
        let mut buf = Vec::new();
        ciborium::into_writer(msg, &mut buf).expect("encode");
        ciborium::from_reader(buf.as_slice()).expect("decode")
    }

    // SPEC-P2P-002 §10 T2 — wire-format round-trip. If this fails, two nodes
    // on the same release cannot parse each other's gossip — a silent fork.
    #[test]
    fn gossip_message_cbor_roundtrips_for_every_message_type() {
        for mt in [
            MessageType::Block,
            MessageType::ConsensusVote,
            MessageType::Transaction,
            MessageType::ValidatorUpdate,
            MessageType::LightClientAttestation,
        ] {
            let original = GossipMessage::new(mt, "viper-devnet-2", vec![0xDE, 0xAD, 0xBE, 0xEF]);
            let decoded = roundtrip(&original);
            assert_eq!(decoded, original, "round-trip failed for {mt:?}");
        }
    }

    // Empty payload is legal at the envelope layer (the inner protocol may
    // reject it, but the envelope must not corrupt or strip it).
    #[test]
    fn gossip_message_preserves_empty_payload() {
        let original = GossipMessage::new(MessageType::ConsensusVote, "x", Vec::new());
        assert_eq!(roundtrip(&original), original);
    }

    // Large payload — blocks can carry 2-16 KB of PQ signatures, so verify
    // we don't have a hidden ciborium size cap at the envelope layer.
    #[test]
    fn gossip_message_roundtrips_16kb_payload() {
        let payload = vec![0xA5; 16 * 1024];
        let original = GossipMessage::new(MessageType::Block, "viper-devnet-2", payload);
        assert_eq!(roundtrip(&original), original);
    }

    // GossipMessage::new must stamp version=1; any change is a wire bump.
    #[test]
    fn gossip_message_new_sets_version_1() {
        let m = GossipMessage::new(MessageType::Transaction, "x", vec![]);
        assert_eq!(m.version, 1);
    }

    // Wire-format pin (TASK-147 resolution): after migrating from plain
    // `#[derive(Serialize, Deserialize)]` to `serde_repr`, each variant now
    // serializes as a single CBOR unsigned-integer byte equal to its
    // `#[repr(u8)]` discriminant (SPEC-P2P-002 §4.2 table).
    //
    // CBOR major type 0 (unsigned int) with value 0..23 is encoded as a
    // single byte whose value is the integer itself — so Block=0x01 encodes
    // literally as the byte 0x01. This test fails loudly if anyone swaps
    // the derive back, drops `serde_repr`, or reorders the discriminants.
    #[test]
    fn message_type_wire_format_is_u8_discriminant() {
        let cases = [
            (MessageType::Block, 0x01u8),
            (MessageType::ConsensusVote, 0x02u8),
            (MessageType::Transaction, 0x03u8),
            (MessageType::ValidatorUpdate, 0x04u8),
            (MessageType::LightClientAttestation, 0x05u8),
        ];
        for (mt, want_byte) in cases {
            let mut buf = Vec::new();
            ciborium::into_writer(&mt, &mut buf).unwrap();
            assert_eq!(
                buf.len(),
                1,
                "{mt:?} must encode to exactly 1 CBOR byte, got {buf:?}",
            );
            assert_eq!(
                buf[0], want_byte,
                "{mt:?} wire byte mismatch: got {:#04x}, want {want_byte:#04x}",
                buf[0],
            );
        }
    }

    // Integration sanity: an unknown discriminant must fail to decode rather
    // than silently map to a known variant. Protects against forward-compat
    // drift when a future release adds MessageType::Foo at the next slot.
    // Bump the probe byte when a new variant lands.
    #[test]
    fn message_type_rejects_unknown_discriminant() {
        // CBOR uint 6 (one past the current max — 0x05 is
        // LightClientAttestation) is a single byte 0x06.
        let raw = [0x06u8];
        let result: Result<MessageType, _> = ciborium::from_reader(raw.as_slice());
        assert!(
            result.is_err(),
            "unknown discriminant 0x06 must not decode to a valid variant; got {result:?}",
        );
    }
}
