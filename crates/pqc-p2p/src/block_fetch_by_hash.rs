// SPDX-License-Identifier: BUSL-1.1
//! Block-fetch-by-hash request-response protocol — ADR-054 §Stage 4.
//!
//! Wire protocol ID: `/viper/{chain_id}/block-fetch-by-hash/1.0.0`,
//! negotiated per-connection via libp2p Identify (see
//! `protocols::Protocols::block_fetch_by_hash`). Codec: CBOR, same as
//! `block_fetch.rs`.
//!
//! Why a second block-fetch protocol?
//!
//! The existing `block-fetch/1.0.0` is height-ranged. Under the bug
//! ADR-054 addresses (a follower has persisted a non-canonical sibling
//! at height H; the canonical version lives on a peer; a child block
//! H+1 has just arrived with a `prev_hash` pointing at the canonical
//! sibling), height-ranged fetch cannot disambiguate which variant the
//! receiver wants — the responder might return either, and the
//! receiver cannot trust the result by inspection alone since both
//! variants are quorum-signed.
//!
//! `BlockFetchByHashRequest` lets the receiver point at the *exact*
//! variant by its `block_hash`. The responder reads the canonical
//! `hash_index` CF first; if absent (the local canonical at that
//! height is a different variant), it falls back to the `siblings` CF
//! introduced by ADR-054 TASK-207 (which retains recently-displaced
//! state-equivalent variants). If neither has it, the responder
//! returns `None`.
//!
//! ## Wire-level constraints
//!
//! - Request carries a single `[u8; 32]` hash and nothing else. There
//!   is no "fetch many hashes" form: a future bulk variant can be
//!   added under a separate protocol ID without breaking existing
//!   peers.
//! - Response carries `Option<Vec<u8>>` (CBOR-encoded `StoredBlock`
//!   bytes), so the absence case is explicit on the wire — peers do
//!   not need to distinguish "I don't have it" from a transport
//!   failure at the application layer.
//! - Request timeout matches `block_fetch`: 10 s. A by-hash lookup is
//!   strictly cheaper than a height-ranged fetch (single block, single
//!   CF read) so the same budget is comfortable.

use serde::{Deserialize, Serialize};

/// A single block by its `block_hash`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockFetchByHashRequest {
    pub hash: [u8; 32],
}

/// Responder reply — `Some(bytes)` when the block was found in either
/// the canonical or the siblings store, `None` otherwise.
///
/// `bytes` is the same CBOR-encoded `StoredBlockRecord` shape returned
/// by `block_fetch::BlockFetchResponse::blocks` entries — receivers
/// can decode it via `RocksDbChainStore::decode_block_bytes` without a
/// second wire-format dance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockFetchByHashResponse {
    pub block: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_cbor_roundtrip() {
        let req = BlockFetchByHashRequest { hash: [0xAB; 32] };
        let mut bytes = Vec::new();
        ciborium::into_writer(&req, &mut bytes).unwrap();
        let decoded: BlockFetchByHashRequest = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn response_cbor_roundtrip_some_and_none() {
        let none = BlockFetchByHashResponse { block: None };
        let mut bytes = Vec::new();
        ciborium::into_writer(&none, &mut bytes).unwrap();
        let decoded: BlockFetchByHashResponse = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(none, decoded);

        let some = BlockFetchByHashResponse {
            block: Some(vec![0x01, 0x02, 0x03]),
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&some, &mut bytes).unwrap();
        let decoded: BlockFetchByHashResponse = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(some, decoded);
    }
}
