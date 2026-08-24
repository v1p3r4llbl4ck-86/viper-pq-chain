// SPDX-License-Identifier: BUSL-1.1
//! Archival overlay — deterministic `epoch_root` computation (SPEC-ARCHIVAL-001
//! §4.1, ADR-045, TASK-163 / M4.4).
//!
//! The archival overlay is one level above consensus finality (§4.7). This
//! module carries the only consensus-critical piece: the exact byte-stable
//! `epoch_root` formula that two honest nodes MUST agree on at an epoch
//! boundary. Failure of that invariant is a state-root divergence.
//!
//! Per SPEC-ARCHIVAL-001 §4.1:
//!
//! ```text
//! epoch_root := SHAKE-256(
//!     "VIPER-ARCHIVAL-V1"
//!     || u64_be(epoch_number)
//!     || concat(block_hash_i for i in first_height..=last_height)
//! )
//! ```
//!
//! Iteration order is ascending height with no re-sort. Block hashes are the
//! 32-byte output of `compute_block_hash` (already `PQC-BLOCK-HASH-V1` domain
//! separated).
//!
//! # Bootstrap: block 0
//!
//! The chain store's first record is height 1 — block 0 is a virtual genesis
//! anchor, not a stored block. Epoch 0 (heights `0..=epoch_duration-1`) thus
//! cannot be archived at its boundary because block 0 is missing. The first
//! archival record therefore lands at the close of epoch 1. This is an
//! intentional bootstrap deviation from §4.1's universal statement; the exit
//! criterion in M4.7 (24-hour soak producing `>= 1` `ArchivalRecord`) accounts
//! for it.

use pqc_crypto::TaggedHasher;

use crate::{
    chain::ChainStore,
    epoch::{epoch_for_height, is_epoch_boundary},
};

/// Domain separator for the epoch-root hash (SPEC-ARCHIVAL-001 §4.1).
pub const ARCHIVAL_EPOCH_ROOT_DOMAIN: &[u8] = b"VIPER-ARCHIVAL-V1";

/// Compute the deterministic `epoch_root` over a range of block hashes.
///
/// `block_hashes` MUST be supplied in ascending height order with no gaps
/// and no re-sort. See SPEC-ARCHIVAL-001 §4.1.
pub fn compute_archival_epoch_root(epoch_number: u64, block_hashes: &[[u8; 32]]) -> [u8; 32] {
    let mut d = TaggedHasher::new(ARCHIVAL_EPOCH_ROOT_DOMAIN);
    d.push_u64(epoch_number);
    for h in block_hashes {
        d.push_chunk(h);
    }
    d.finish()
}

/// Summary of a just-closed epoch, produced at the `is_epoch_boundary`
/// transition by `summarize_closed_epoch`. Fed to the archival submission
/// path in `pqcd` so each designated signer can build an
/// `ArchivalRecordSubmit` transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivalEpochSummary {
    /// Number of the epoch that just closed. For `boundary_height=N*duration`,
    /// this is `N - 1`.
    pub epoch_number: u64,
    /// First block height covered by this epoch (inclusive).
    pub first_height: u64,
    /// Last block height covered by this epoch (inclusive).
    pub last_height: u64,
    /// Deterministic `epoch_root` per SPEC §4.1.
    pub epoch_root: [u8; 32],
}

/// Compute the `ArchivalEpochSummary` for the epoch that just closed at
/// `boundary_height`, reading block hashes from the chain store.
///
/// Returns `None` when any of:
/// - `boundary_height` is not an epoch boundary for `epoch_duration`
/// - `boundary_height < epoch_duration` (no full epoch has closed yet —
///   only possible with a non-trivial start offset)
/// - any block in `first_height..=last_height` is missing from the chain
///   store (notably `first_height == 0`, which is always missing — see
///   the bootstrap note in the module docs)
pub fn summarize_closed_epoch(
    chain: &ChainStore,
    boundary_height: u64,
    epoch_duration: u64,
) -> Option<ArchivalEpochSummary> {
    if !is_epoch_boundary(boundary_height, epoch_duration) {
        return None;
    }
    let current_epoch = epoch_for_height(boundary_height, epoch_duration);
    if current_epoch == 0 {
        return None;
    }
    let closed_epoch = current_epoch - 1;
    let first_height = closed_epoch.saturating_mul(epoch_duration);
    let last_height = first_height
        .saturating_add(epoch_duration)
        .saturating_sub(1);

    let count = usize::try_from(epoch_duration).ok()?;
    let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(count);
    for h in first_height..=last_height {
        let meta = chain.get_metadata_by_height(h)?;
        hashes.push(meta.block_hash.0);
    }

    let epoch_root = compute_archival_epoch_root(closed_epoch, &hashes);
    Some(ArchivalEpochSummary {
        epoch_number: closed_epoch,
        first_height,
        last_height,
        epoch_root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_root_is_domain_separated_and_byte_stable() {
        let hashes = vec![[0x11u8; 32], [0x22u8; 32], [0x33u8; 32]];
        let root = compute_archival_epoch_root(1, &hashes);

        // Byte-stable: identical input → identical output.
        let root2 = compute_archival_epoch_root(1, &hashes);
        assert_eq!(root, root2);

        // Epoch number change → different root.
        let root_e2 = compute_archival_epoch_root(2, &hashes);
        assert_ne!(root, root_e2);

        // Order sensitivity: reversing changes the root (concat is ordered).
        let mut rev = hashes.clone();
        rev.reverse();
        let root_rev = compute_archival_epoch_root(1, &rev);
        assert_ne!(root, root_rev);

        // Domain-separated against an empty hash list too.
        let root_empty = compute_archival_epoch_root(1, &[]);
        assert_ne!(root, root_empty);
    }

    #[test]
    fn empty_range_is_domain_separated_from_zero() {
        // A zeroed 32-byte hash is NOT equal to the empty-range epoch root.
        let root_empty = compute_archival_epoch_root(0, &[]);
        assert_ne!(root_empty, [0u8; 32]);
    }
}
