// SPDX-License-Identifier: BUSL-1.1
//! Tests for `block_tree_cache`.
//!
//! Extracted from `block_tree_cache.rs` 2026-05-10. `use super::*;`
//! brings every private item from the parent module into scope.

use std::thread::sleep;

use pqc_types::block::{empty_extension_root, Block, BlockHash, BlockHeader, HEADER_VERSION_V1};

use crate::chain::{BlockMetadata, StoredBlock};

use super::{BlockTreeCache, DEFAULT_CAPACITY, DEFAULT_TTL};

/// Build a synthetic StoredBlock at a given height with a chosen
/// `prev_hash` and a trailing-byte-derived `block_hash`. The body
/// is meaningless — these tests exercise the data structure, not
/// the consensus pipeline.
fn synth(height: u64, prev: [u8; 32], hash_byte: u8) -> StoredBlock {
    let block_hash = BlockHash([hash_byte; 32]);
    let header = BlockHeader {
        header_version: HEADER_VERSION_V1,
        height,
        prev_hash: BlockHash(prev),
        state_root: BlockHash([0x00; 32]),
        tx_root: BlockHash([0x00; 32]),
        timestamp: 1,
        proposer: vec![0u8; 32],
        extension_root: empty_extension_root(),
    };
    let block = Block {
        header,
        tx_hashes: Vec::new(),
        commit_signatures: Vec::new(),
    };
    let metadata = BlockMetadata {
        block_hash: block_hash.clone(),
        height,
        prev_hash: BlockHash(prev),
        state_root: BlockHash([0x00; 32]),
        tx_root: BlockHash([0x00; 32]),
        timestamp: 1,
        bytes_used: 0,
        included_count: 0,
        deferred_count: 0,
        skipped_count: 0,
        vc_budget_consumed: 0,
    };
    StoredBlock {
        block,
        metadata,
        included_transactions: Vec::new(),
    }
}

#[test]
fn insert_and_lookup_by_hash() {
    let mut cache = BlockTreeCache::new(DEFAULT_CAPACITY, DEFAULT_TTL);
    let b = synth(1, [0x01; 32], 0xAA);
    cache.insert(b.clone());
    assert_eq!(cache.len(), 1);
    let got = cache.get(&BlockHash([0xAA; 32])).expect("present");
    assert_eq!(got.metadata.block_hash, b.metadata.block_hash);
}

#[test]
fn children_of_returns_blocks_with_matching_prev_hash() {
    let mut cache = BlockTreeCache::new(DEFAULT_CAPACITY, DEFAULT_TTL);
    // parent P; two children A and B both pointing at P; one
    // unrelated child C pointing at Q.
    cache.insert(synth(2, [0x01; 32], 0xAA));
    cache.insert(synth(2, [0x01; 32], 0xBB));
    cache.insert(synth(2, [0x02; 32], 0xCC));

    let children: Vec<_> = cache
        .children_of(&BlockHash([0x01; 32]))
        .into_iter()
        .map(|s| s.metadata.block_hash.0[0])
        .collect();
    assert_eq!(children, vec![0xAA, 0xBB]);

    let other: Vec<_> = cache
        .children_of(&BlockHash([0x02; 32]))
        .into_iter()
        .map(|s| s.metadata.block_hash.0[0])
        .collect();
    assert_eq!(other, vec![0xCC]);

    assert!(cache.children_of(&BlockHash([0x09; 32])).is_empty());
}

#[test]
fn remove_drops_both_indices() {
    let mut cache = BlockTreeCache::new(DEFAULT_CAPACITY, DEFAULT_TTL);
    cache.insert(synth(2, [0x01; 32], 0xAA));
    cache.insert(synth(2, [0x01; 32], 0xBB));
    let dropped = cache.remove(&BlockHash([0xAA; 32])).expect("present");
    assert_eq!(dropped.metadata.block_hash.0[0], 0xAA);
    assert!(cache.get(&BlockHash([0xAA; 32])).is_none());
    // The other child remains discoverable.
    let remaining: Vec<_> = cache
        .children_of(&BlockHash([0x01; 32]))
        .into_iter()
        .map(|s| s.metadata.block_hash.0[0])
        .collect();
    assert_eq!(remaining, vec![0xBB]);
}

#[test]
fn capacity_evicts_oldest_on_overflow() {
    let mut cache = BlockTreeCache::new(2, DEFAULT_TTL);
    cache.insert(synth(2, [0x01; 32], 0x10));
    cache.insert(synth(2, [0x01; 32], 0x20));
    cache.insert(synth(2, [0x01; 32], 0x30)); // forces eviction of 0x10.

    assert_eq!(cache.len(), 2);
    assert!(cache.get(&BlockHash([0x10; 32])).is_none());
    assert!(cache.get(&BlockHash([0x20; 32])).is_some());
    assert!(cache.get(&BlockHash([0x30; 32])).is_some());
}

#[test]
fn prune_expired_drops_stale_entries() {
    let mut cache = BlockTreeCache::new(DEFAULT_CAPACITY, std::time::Duration::from_millis(10));
    cache.insert(synth(2, [0x01; 32], 0xAA));
    sleep(std::time::Duration::from_millis(20));
    let pruned = cache.prune_expired();
    assert_eq!(pruned, 1);
    assert_eq!(cache.len(), 0);
    assert!(cache.get(&BlockHash([0xAA; 32])).is_none());
}

#[test]
fn duplicate_insert_is_idempotent() {
    let mut cache = BlockTreeCache::new(DEFAULT_CAPACITY, DEFAULT_TTL);
    cache.insert(synth(2, [0x01; 32], 0xAA));
    cache.insert(synth(2, [0x01; 32], 0xAA));
    assert_eq!(cache.len(), 1);
    // The parent index does not duplicate the child either.
    let kids = cache.children_of(&BlockHash([0x01; 32]));
    assert_eq!(kids.len(), 1);
}
