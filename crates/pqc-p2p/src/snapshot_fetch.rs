// SPDX-License-Identifier: BUSL-1.1
//! Snapshot-fetch request-response protocol — Phase 8 M1 cold-start.
//!
//! Wire protocol ID: `/viper/{chain_id}/snapshot/1.0.0`, negotiated
//! per-connection via libp2p Identify (see `protocols::Protocols`).
//! Codec: CBOR, same as gossip envelopes (`message::GossipMessage`)
//! and block-fetch (`block_fetch::*`).
//!
//! Used by a cold-starting follower to pull a trusted-checkpoint
//! snapshot from a running peer before it begins tailing via
//! block-fetch. Replaces the Phase 6 HTTP endpoint `/internal/p2p/snapshot`
//! once `TASK-141` flips `libp2p.enable=true`.
//!
//! Deliberately simpler than block-fetch: one round trip, variable-size
//! payload (the full checkpoint bytes produced by
//! `RocksDbChainStore::export_checkpoint_bytes`). The wire types have
//! NO libp2p dependency so they can be CBOR-round-trip-tested without
//! pulling the `libp2p-backend` feature.

use serde::{Deserialize, Serialize};

/// Request payload. The request body is deliberately a struct (not a
/// unit type) so future revisions can add fields without a wire-format
/// bump — e.g. M2+ may add `at_height: Option<u64>` to fetch an
/// archival snapshot pinned at a specific height.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotFetchRequest {
    /// Reserved for future use. M1 clients MUST set this to `None`,
    /// meaning "give me your latest committed checkpoint". Responders
    /// MUST ignore `Some(_)` during M1 and return their latest — the
    /// multi-snapshot storage model lands with ADR-043 / M2.
    #[serde(default)]
    pub at_height: Option<u64>,
}

/// Response payload. A responder with no committed checkpoint yet
/// (e.g. genesis-bootstrapped, no checkpoint interval reached) replies
/// with `snapshot_bytes.is_empty() && snapshot_height == 0`; the
/// requester MUST treat this as "peer has no snapshot" and either
/// retry against a different peer or fall back to genesis replay.
///
/// `snapshot_height` is duplicated outside the CBOR-encoded snapshot
/// body so the requester can log / trace at response time without
/// paying the decode cost up-front.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotFetchResponse {
    /// Raw output of `RocksDbChainStore::export_checkpoint_bytes`.
    /// Canonical CBOR. Feed directly to `bootstrap_from_external_snapshot`
    /// after validating the embedded `state_root`.
    pub snapshot_bytes: Vec<u8>,
    /// Height represented by the checkpoint. `0` when no snapshot is
    /// available. Callers SHOULD cross-check this against the
    /// `state_root`-bound height decoded from `snapshot_bytes` before
    /// writing, to catch a peer that ships a mismatched pair.
    pub snapshot_height: u64,
}

impl SnapshotFetchResponse {
    /// Whether the responder actually shipped a snapshot (vs the
    /// "I have no checkpoint yet" empty-body reply).
    pub fn is_empty(&self) -> bool {
        self.snapshot_bytes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_request_roundtrips_cbor() {
        let req = SnapshotFetchRequest::default();
        let mut bytes = Vec::new();
        ciborium::into_writer(&req, &mut bytes).unwrap();
        let decoded: SnapshotFetchRequest = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(req, decoded);
        assert!(decoded.at_height.is_none());
    }

    #[test]
    fn request_with_at_height_roundtrips_cbor() {
        // Round-trip a populated at_height even though M1 always sends
        // None — guards against a future wire-format regression that
        // silently drops the new field.
        let req = SnapshotFetchRequest {
            at_height: Some(100_000),
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&req, &mut bytes).unwrap();
        let decoded: SnapshotFetchRequest = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn empty_response_signals_no_snapshot() {
        let r = SnapshotFetchResponse::default();
        assert!(r.is_empty());
        assert_eq!(r.snapshot_height, 0);
    }

    #[test]
    fn populated_response_roundtrips_cbor() {
        // 8 KiB synthetic snapshot — well below the libp2p default
        // frame cap (~1 MiB) so a devnet-2 snapshot (~30 KB at height
        // 100K per TASK-122) fits comfortably in one round trip.
        let payload = vec![0xAB; 8 * 1024];
        let r = SnapshotFetchResponse {
            snapshot_bytes: payload.clone(),
            snapshot_height: 100_000,
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&r, &mut bytes).unwrap();
        let decoded: SnapshotFetchResponse = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(r, decoded);
        assert_eq!(decoded.snapshot_bytes, payload);
        assert!(!decoded.is_empty());
    }
}
