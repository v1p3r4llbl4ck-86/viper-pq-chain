// SPDX-License-Identifier: BUSL-1.1
//! ADR-054 §Stage 3 — block reception classifier.
//!
//! Pure-function classifier that takes a freshly-validated block and
//! the local chain tip and decides what the reception pipeline should
//! do with it. The output is a typed enum the dispatch layer in
//! `pqcd::devnet` matches on; each variant maps to a Stage-4
//! resolution path documented in DECISIONS.md §ADR-054.
//!
//! This module is *only* the classifier — the dispatch and recovery
//! logic (sibling swap, orphan buffering, equivocation emission) live
//! at the call sites in pqcd because they need state-store, P2P, and
//! storage access. Keeping the classifier here makes it cheap to test
//! in isolation without spinning up a full node.

use pqc_types::block::BlockHash;

use crate::chain::{BlockMetadata, StoredBlock};

/// Outcome of the Stage-3 tip-linkage classifier (ADR-054 §Stage 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockReceptionClass {
    /// Normal forward append. `B.height == local_height + 1` and
    /// `B.prev_hash == local_tip_hash`. Dispatch to the existing
    /// `append_stored_block` flow.
    LinkAtTip,

    /// `B.block_hash` already exists at `B.height` in the local chain.
    /// Idempotent ok — return success without re-applying.
    Duplicate,

    /// Same height as the local tip, different `block_hash`.
    /// `local` is the local variant's metadata so the dispatch layer
    /// can compare `state_root`/`tx_root` and decide between sibling
    /// swap (state-equivalent) and equivocation evidence
    /// (state-divergent) without re-reading from storage.
    SiblingAtTip { local: BlockMetadata },

    /// `B.height > local_height + 1` OR `B.height == local_height + 1`
    /// with `B.prev_hash` not matching the local tip. Buffer in
    /// `BlockTreeCache` and dispatch a `BlockFetchByHashRequest` for
    /// `B.prev_hash`.
    OrphanFutureChild,

    /// `B.height < local_height` and not a duplicate. Reject — no
    /// reorg below the tip is permitted (Tendermint safety).
    BelowFinalized,
}

/// Reasons the classifier itself rejects a candidate before
/// classification can occur. These are *not* the same as the
/// resolution failures (which the dispatch layer raises); they are
/// failures intrinsic to comparing the candidate with local state.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BlockReceptionError {
    /// The candidate's metadata claims one height but its body header
    /// claims another. Caught by storage/replay too, but cheaper to
    /// reject here.
    #[error("RECEPTION_HEIGHT_INCONSISTENT: metadata height {meta} != header height {header}")]
    HeightInconsistent { meta: u64, header: u64 },

    /// The candidate's `metadata.block_hash` does not equal the hash
    /// of `block` recomputed from scratch. Caught later by
    /// `validate_stored_block` too; rejecting at this boundary spares
    /// the storage layer entirely.
    #[error("RECEPTION_HASH_INCONSISTENT: candidate metadata hash mismatches header recompute")]
    HashInconsistent,
}

/// Classify a candidate block against a local chain summary.
///
/// `local_height` is `chain.height()`; `local_tip` is the optional
/// `chain.tip()` block (None for empty chains). Both are passed in
/// rather than the chain itself so this module stays free of storage
/// dependencies — the dispatch layer reads them from
/// `RocksDbChainStore`.
///
/// `lookup_canonical_at_height(h)` returns the local canonical block
/// metadata at height `h` if any; this lets the classifier detect
/// `Duplicate` (B.hash matches the local canonical at B.height) and
/// `SiblingAtTip { local }` (B at tip height, hash differs from tip)
/// without taking a borrow on the full chain.
pub fn classify_incoming_block<F>(
    candidate: &StoredBlock,
    local_height: u64,
    local_tip: Option<&BlockMetadata>,
    lookup_canonical_at_height: F,
) -> Result<BlockReceptionClass, BlockReceptionError>
where
    F: Fn(u64) -> Option<BlockMetadata>,
{
    // Cheap self-consistency check on the candidate. Catches a class
    // of malformed inputs (mismatched metadata vs body) without going
    // near storage.
    if candidate.metadata.height != candidate.block.header.height {
        return Err(BlockReceptionError::HeightInconsistent {
            meta: candidate.metadata.height,
            header: candidate.block.header.height,
        });
    }
    if candidate.metadata.block_hash != crate::engine::compute_block_hash(&candidate.block) {
        return Err(BlockReceptionError::HashInconsistent);
    }

    let h = candidate.metadata.height;

    // (a) Duplicate — same hash already at this height. This branch
    // dominates over SiblingAtTip when both could match (an exact-
    // hash duplicate is never a sibling).
    if let Some(local_at_h) = lookup_canonical_at_height(h) {
        if local_at_h.block_hash == candidate.metadata.block_hash {
            return Ok(BlockReceptionClass::Duplicate);
        }
    }

    // (b) Below tip and not a duplicate — reject (no reorg below tip).
    if h < local_height {
        return Ok(BlockReceptionClass::BelowFinalized);
    }

    // (c) Same height as tip with a different hash → SiblingAtTip.
    if h == local_height {
        if let Some(tip_meta) = local_tip {
            // Defensive: only fire if there really is a different hash;
            // a tip with the same hash already covered by (a).
            if tip_meta.block_hash != candidate.metadata.block_hash {
                return Ok(BlockReceptionClass::SiblingAtTip {
                    local: tip_meta.clone(),
                });
            }
        }
        // No tip with same height (empty chain at h=0) — treat as
        // orphan, the caller will fetch the parent and the resolver
        // will normalise.
        return Ok(BlockReceptionClass::OrphanFutureChild);
    }

    // (d) One ahead with parent matching the local tip → LinkAtTip.
    if h == local_height + 1 {
        let tip_hash = local_tip.map(|m| m.block_hash.clone()).unwrap_or_else(|| {
            // Empty chain: the only valid prev_hash is the genesis
            // anchor, which by construction matches what the caller
            // expects. The append-time validator enforces this; here
            // we treat any prev_hash as link-at-tip and let the
            // append-time check fail if it really mismatches.
            BlockHash([0u8; 32])
        });
        if local_tip.is_none() || candidate.metadata.prev_hash == tip_hash {
            return Ok(BlockReceptionClass::LinkAtTip);
        }
        // Parent mismatch at exactly local_height + 1 → OrphanFutureChild.
        // The resolver requests `candidate.prev_hash` via by-hash
        // fetch, swaps the local tip if state-equivalent, and re-runs.
        return Ok(BlockReceptionClass::OrphanFutureChild);
    }

    // (e) More than one ahead → OrphanFutureChild. The resolver
    // closes the gap via the existing height-ranged fetch path.
    Ok(BlockReceptionClass::OrphanFutureChild)
}

#[cfg(test)]
mod tests {
    use pqc_types::block::{
        empty_extension_root, Block, BlockHash, BlockHeader, HEADER_VERSION_V1,
    };

    use crate::chain::{BlockMetadata, StoredBlock};
    use crate::engine::compute_block_hash;

    use super::{classify_incoming_block, BlockReceptionClass, BlockReceptionError};

    /// Build a synthetic StoredBlock with internally-consistent
    /// metadata: the recomputed `block_hash` matches `metadata.block_hash`.
    /// Tests that need to violate that invariant override fields after
    /// construction.
    fn synth_block(height: u64, prev: [u8; 32], timestamp: u64) -> StoredBlock {
        let header = BlockHeader {
            header_version: HEADER_VERSION_V1,
            height,
            prev_hash: BlockHash(prev),
            state_root: BlockHash([0x10; 32]),
            tx_root: BlockHash([0x20; 32]),
            timestamp,
            proposer: vec![0u8; 32],
            extension_root: empty_extension_root(),
        };
        let block = Block {
            header: header.clone(),
            tx_hashes: Vec::new(),
            commit_signatures: Vec::new(),
        };
        let block_hash = compute_block_hash(&block);
        let metadata = BlockMetadata {
            block_hash: block_hash.clone(),
            height,
            prev_hash: BlockHash(prev),
            state_root: BlockHash([0x10; 32]),
            tx_root: BlockHash([0x20; 32]),
            timestamp,
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
    fn classify_link_at_tip_when_height_and_parent_match() {
        let tip = synth_block(5, [0x11; 32], 1_000);
        let next = synth_block(6, tip.metadata.block_hash.0, 2_000);
        let class = classify_incoming_block(&next, 5, Some(&tip.metadata), |_| None).unwrap();
        assert_eq!(class, BlockReceptionClass::LinkAtTip);
    }

    #[test]
    fn classify_duplicate_when_same_hash_at_existing_height() {
        let tip = synth_block(5, [0x11; 32], 1_000);
        let dup = tip.clone();
        let tip_meta = tip.metadata.clone();
        let class = classify_incoming_block(&dup, 5, Some(&tip.metadata), {
            move |h| if h == 5 { Some(tip_meta.clone()) } else { None }
        })
        .unwrap();
        assert_eq!(class, BlockReceptionClass::Duplicate);
    }

    #[test]
    fn classify_sibling_at_tip_when_same_height_different_hash() {
        // local tip at h=5 with one timestamp; candidate at h=5 with a
        // different timestamp → different block_hash, same height.
        let local = synth_block(5, [0x11; 32], 1_000);
        let sibling = synth_block(5, [0x11; 32], 1_002); // shifted ts
        assert_ne!(local.metadata.block_hash, sibling.metadata.block_hash);
        let local_meta = local.metadata.clone();
        let class = classify_incoming_block(&sibling, 5, Some(&local.metadata), move |h| {
            if h == 5 {
                Some(local_meta.clone())
            } else {
                None
            }
        })
        .unwrap();
        match class {
            BlockReceptionClass::SiblingAtTip { local: m } => {
                assert_eq!(m.block_hash, local.metadata.block_hash);
            }
            other => panic!("expected SiblingAtTip, got {other:?}"),
        }
    }

    #[test]
    fn classify_orphan_when_more_than_one_ahead() {
        let tip = synth_block(5, [0x11; 32], 1_000);
        let far = synth_block(8, [0xAA; 32], 4_000);
        let class = classify_incoming_block(&far, 5, Some(&tip.metadata), |_| None).unwrap();
        assert_eq!(class, BlockReceptionClass::OrphanFutureChild);
    }

    #[test]
    fn classify_orphan_when_one_ahead_but_parent_differs() {
        // local tip at h=5; candidate at h=6 but pointing to a
        // different parent hash. Triggers orphan resolution: the
        // dispatcher fetches `candidate.prev_hash`, runs sibling
        // resolution at h=5, then retries the original candidate.
        let tip = synth_block(5, [0x11; 32], 1_000);
        let candidate = synth_block(6, [0xCC; 32], 2_000);
        let class = classify_incoming_block(&candidate, 5, Some(&tip.metadata), |_| None).unwrap();
        assert_eq!(class, BlockReceptionClass::OrphanFutureChild);
    }

    #[test]
    fn classify_below_finalized_when_height_below_tip() {
        let tip = synth_block(5, [0x11; 32], 1_000);
        // Candidate at h=3 with a different hash from the local h=3 (lookup returns None
        // here so it is not classified as duplicate).
        let stale = synth_block(3, [0x33; 32], 500);
        let class = classify_incoming_block(&stale, 5, Some(&tip.metadata), |_| None).unwrap();
        assert_eq!(class, BlockReceptionClass::BelowFinalized);
    }

    #[test]
    fn classify_rejects_metadata_height_mismatching_header() {
        let tip = synth_block(5, [0x11; 32], 1_000);
        let mut bad = synth_block(6, tip.metadata.block_hash.0, 2_000);
        bad.metadata.height = 7; // header says 6, metadata says 7
        let err = classify_incoming_block(&bad, 5, Some(&tip.metadata), |_| None).unwrap_err();
        assert_eq!(
            err,
            BlockReceptionError::HeightInconsistent { meta: 7, header: 6 }
        );
    }

    #[test]
    fn classify_rejects_metadata_hash_mismatch() {
        let tip = synth_block(5, [0x11; 32], 1_000);
        let mut bad = synth_block(6, tip.metadata.block_hash.0, 2_000);
        bad.metadata.block_hash = BlockHash([0xFF; 32]);
        let err = classify_incoming_block(&bad, 5, Some(&tip.metadata), |_| None).unwrap_err();
        assert_eq!(err, BlockReceptionError::HashInconsistent);
    }
}
