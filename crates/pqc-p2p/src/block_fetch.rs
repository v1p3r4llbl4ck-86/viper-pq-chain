// SPDX-License-Identifier: BUSL-1.1
//! Block-fetch request-response protocol — TASK-135 step 12.
//!
//! Wire protocol ID: `/viper/{chain_id}/block-fetch/1.0.0`, negotiated
//! per-connection via libp2p Identify (see `protocols::Protocols`).
//! Codec: CBOR, same as gossip envelopes (`message::GossipMessage`).
//!
//! Followers use this protocol to close height gaps detected by the
//! TASK-135 step 11 inbound classifier: once a gossiped Block lands more
//! than one height ahead of the local tip, the follower issues a
//! `BlockFetchRequest` for the intermediate range.
//!
//! The request/response wire types intentionally carry NO libp2p
//! dependency — they are pure CBOR-serializable structs so they can be
//! unit-tested and re-used from crates that do not pull the
//! `libp2p-backend` feature (e.g. spec / golden-vector tests).

use serde::{Deserialize, Serialize};

/// Inclusive upper bound on how many block heights a single
/// `BlockFetchRequest` may span.
///
/// Chosen to keep the serialized response comfortably under libp2p's
/// default inbound frame cap: devnet-2 blocks average well below 16 KiB,
/// so 16 × 16 KiB = 256 KiB leaves headroom for encode overhead and
/// occasional fat blocks. A follower that is more than 16 blocks behind
/// issues multiple pipelined requests rather than one large one — this
/// keeps tail-end retries cheap and bounds per-request latency.
pub const MAX_BLOCKS_PER_REQUEST: u64 = 16;

/// Fetch every block with height in `[from_height, to_height]` inclusive.
///
/// `from_height <= to_height` and the range length MUST be
/// `<= MAX_BLOCKS_PER_REQUEST`. Callers MUST call [`Self::validate`]
/// before putting a request on the wire; responders also re-validate on
/// receipt and drop malformed requests without responding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockFetchRequest {
    pub from_height: u64,
    pub to_height: u64,
}

/// The responder's reply: the raw CBOR-encoded `StoredBlock` bytes, one
/// per available height in the requested range.
///
/// `blocks` MUST be ordered ascending by height. A responder MAY return
/// fewer entries than requested when it does not hold the full range —
/// but only by truncating from the TAIL (no gaps). Returning an empty
/// vector means the responder has none of the requested heights (e.g.
/// it is itself behind the requester or has pruned that range).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockFetchResponse {
    pub blocks: Vec<Vec<u8>>,
}

/// Validation errors for [`BlockFetchRequest::validate`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BlockFetchRequestError {
    #[error("empty range: from_height {from} > to_height {to}")]
    EmptyRange { from: u64, to: u64 },
    #[error("range too large: {len} heights requested, max is {max}")]
    RangeTooLarge { len: u64, max: u64 },
}

impl BlockFetchRequest {
    /// Number of heights spanned by the request (1-based, inclusive).
    /// Undefined for requests that have not passed [`Self::validate`]
    /// — callers MUST validate first. (Not named `len` because a
    /// `BlockFetchRequest` is never conceptually empty: an empty-range
    /// request fails validation before it can be observed.)
    pub fn height_count(&self) -> u64 {
        self.to_height - self.from_height + 1
    }

    /// Reject requests that cannot be served by a well-behaved responder.
    /// This is cheap — arithmetic only — and must be called on both
    /// sender and receiver sides (defense in depth: a buggy peer may
    /// still ship a malformed request over the wire).
    pub fn validate(&self) -> Result<(), BlockFetchRequestError> {
        if self.from_height > self.to_height {
            return Err(BlockFetchRequestError::EmptyRange {
                from: self.from_height,
                to: self.to_height,
            });
        }
        let len = self.to_height - self.from_height + 1;
        if len > MAX_BLOCKS_PER_REQUEST {
            return Err(BlockFetchRequestError::RangeTooLarge {
                len,
                max: MAX_BLOCKS_PER_REQUEST,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_accepts_single_height() {
        let r = BlockFetchRequest {
            from_height: 100,
            to_height: 100,
        };
        assert!(r.validate().is_ok());
        assert_eq!(r.height_count(), 1);
    }

    #[test]
    fn validate_accepts_full_cap() {
        let r = BlockFetchRequest {
            from_height: 1,
            to_height: MAX_BLOCKS_PER_REQUEST,
        };
        assert!(r.validate().is_ok());
        assert_eq!(r.height_count(), MAX_BLOCKS_PER_REQUEST);
    }

    #[test]
    fn validate_rejects_empty_range() {
        let r = BlockFetchRequest {
            from_height: 100,
            to_height: 99,
        };
        assert_eq!(
            r.validate().unwrap_err(),
            BlockFetchRequestError::EmptyRange { from: 100, to: 99 }
        );
    }

    #[test]
    fn validate_rejects_over_cap() {
        let r = BlockFetchRequest {
            from_height: 1,
            to_height: MAX_BLOCKS_PER_REQUEST + 1,
        };
        assert_eq!(
            r.validate().unwrap_err(),
            BlockFetchRequestError::RangeTooLarge {
                len: MAX_BLOCKS_PER_REQUEST + 1,
                max: MAX_BLOCKS_PER_REQUEST,
            }
        );
    }

    #[test]
    fn request_cbor_roundtrip() {
        let req = BlockFetchRequest {
            from_height: 42,
            to_height: 57,
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&req, &mut bytes).unwrap();
        let decoded: BlockFetchRequest = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn response_cbor_roundtrip_empty_and_nonempty() {
        // Empty: responder has none of the requested heights.
        let empty = BlockFetchResponse { blocks: vec![] };
        let mut bytes = Vec::new();
        ciborium::into_writer(&empty, &mut bytes).unwrap();
        let decoded: BlockFetchResponse = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(empty, decoded);

        // Non-empty: three synthetic blocks of different sizes — the
        // codec must preserve exact bytes (block hashes on the receive
        // side depend on byte-for-byte fidelity).
        let full = BlockFetchResponse {
            blocks: vec![vec![], vec![1, 2, 3], vec![0xff; 1024]],
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&full, &mut bytes).unwrap();
        let decoded: BlockFetchResponse = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(full, decoded);
    }
}
