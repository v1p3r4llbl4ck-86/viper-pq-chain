// SPDX-License-Identifier: BUSL-1.1
//! ADR-054 §Stage 4 — bounded in-memory cache for orphan blocks.
//!
//! When a freshly-received block's parent is unknown to the local chain
//! (i.e. the receiver classifies it as `OrphanFutureChild` per ADR-054
//! §Stage 3), it is stored here while the parent is fetched from peers
//! via the `BlockFetchByHashRequest` request-response protocol. Once
//! the parent arrives, descendants are walked out of the cache, re-
//! classified, and dispatched.
//!
//! Constraints:
//!
//! - **Bounded size.** A misbehaving or pathological peer must not be
//!   able to grow our memory unboundedly by streaming blocks for
//!   arbitrary parent hashes. The cache enforces a `capacity` ceiling
//!   in entry count and evicts the least-recently-inserted entry on
//!   overflow.
//! - **Bounded lifetime.** A child whose parent never arrives is
//!   pruned after `ttl`. Default 60 s reflects the SPEC-CONSENSUS-001
//!   propose / prevote / precommit timeout budget at network scale.
//! - **No verification.** This cache is a pure data structure: it does
//!   not run signature checks, quorum checks, or replay. Stage 1
//!   (structural) and Stage 2 (quorum) of ADR-054 run before insert.
//! - **No surprise.** All reads borrow; the only mutation paths are
//!   `insert`, `remove`, and `prune_expired` (or capacity-driven
//!   eviction inside `insert`). Iteration is deterministic by
//!   insertion order.
//!
//! Two indices are kept in sync:
//!
//! - `entries: HashMap<BlockHash, Cached>` — primary by-hash lookup.
//! - `by_parent: HashMap<BlockHash, HashSet<BlockHash>>` — secondary
//!   index for "give me everyone whose parent is this hash".
//!   `children_of` sorts the result by hash bytes before returning so
//!   tests and snapshot diffs are stable across runs.
//!
//! Insertion order tracking uses a `VecDeque<BlockHash>` so eviction
//! is O(1). Total memory cost is O(n) in entries, where n ≤ capacity.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use pqc_types::block::BlockHash;

use crate::chain::StoredBlock;

/// Default cache capacity. 1024 entries × ~10 KB / block ≈ 10 MB
/// resident — small enough to be safe under DoS pressure, large enough
/// to span a few seconds of catch-up at devnet block-rates.
pub const DEFAULT_CAPACITY: usize = 1024;

/// Default per-entry TTL. 60 s mirrors the §7 round-state-machine
/// budget for a single height to complete; orphans older than that
/// almost certainly correspond to a peer that disappeared mid-batch.
pub const DEFAULT_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
struct Cached {
    stored: StoredBlock,
    inserted_at: Instant,
}

#[derive(Debug)]
pub struct BlockTreeCache {
    capacity: usize,
    ttl: Duration,
    entries: HashMap<BlockHash, Cached>,
    by_parent: HashMap<BlockHash, HashSet<BlockHash>>,
    insertion_order: VecDeque<BlockHash>,
}

impl BlockTreeCache {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        let capacity = capacity.max(1);
        Self {
            capacity,
            ttl,
            entries: HashMap::new(),
            by_parent: HashMap::new(),
            insertion_order: VecDeque::new(),
        }
    }

    /// Number of cached entries. Test/observability surface only.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Insert a block whose parent is not yet locally known.
    ///
    /// Idempotent: re-inserting the same hash refreshes its TTL but
    /// does not duplicate the parent index. If `len() == capacity` and
    /// the entry is new, the oldest entry is evicted before insert.
    pub fn insert(&mut self, stored: StoredBlock) {
        let hash = stored.metadata.block_hash.clone();
        let parent = stored.metadata.prev_hash.clone();

        if self.entries.contains_key(&hash) {
            // Refresh insertion timestamp for TTL purposes; do not
            // duplicate the parent index entry. We do NOT bump the
            // LRU position — re-broadcast spam should not extend the
            // life of an entry past the first miss-window.
            if let Some(cached) = self.entries.get_mut(&hash) {
                cached.inserted_at = Instant::now();
            }
            return;
        }

        if self.entries.len() >= self.capacity {
            self.evict_oldest();
        }

        self.entries.insert(
            hash.clone(),
            Cached {
                stored,
                inserted_at: Instant::now(),
            },
        );
        self.by_parent
            .entry(parent)
            .or_default()
            .insert(hash.clone());
        self.insertion_order.push_back(hash);
    }

    /// Lookup by hash. Returns `None` if absent or expired.
    /// Expired entries are NOT proactively pruned here — the caller
    /// runs `prune_expired` periodically (e.g. once per
    /// reception-pipeline tick) for amortized cleanup.
    pub fn get(&self, hash: &BlockHash) -> Option<&StoredBlock> {
        let cached = self.entries.get(hash)?;
        if cached.inserted_at.elapsed() > self.ttl {
            return None;
        }
        Some(&cached.stored)
    }

    /// All currently-cached blocks whose `prev_hash == parent`.
    /// Excludes expired entries. Sorted by `block_hash` bytes so
    /// snapshot diffs and ordered-test assertions are stable across
    /// runs (HashSet iteration would not be).
    pub fn children_of(&self, parent: &BlockHash) -> Vec<&StoredBlock> {
        let Some(set) = self.by_parent.get(parent) else {
            return Vec::new();
        };
        let mut hashes: Vec<&BlockHash> = set.iter().collect();
        hashes.sort_by(|a, b| a.0.cmp(&b.0));
        hashes
            .into_iter()
            .filter_map(|h| self.entries.get(h))
            .filter(|c| c.inserted_at.elapsed() <= self.ttl)
            .map(|c| &c.stored)
            .collect()
    }

    /// Remove and return a single entry by hash.
    pub fn remove(&mut self, hash: &BlockHash) -> Option<StoredBlock> {
        let cached = self.entries.remove(hash)?;
        let parent = cached.stored.metadata.prev_hash.clone();
        if let Some(set) = self.by_parent.get_mut(&parent) {
            set.remove(hash);
            if set.is_empty() {
                self.by_parent.remove(&parent);
            }
        }
        // Lazy purge from insertion_order — `evict_oldest` skips already-removed entries.
        Some(cached.stored)
    }

    /// Drop every entry older than `ttl`. Returns the number pruned.
    pub fn prune_expired(&mut self) -> usize {
        let mut victims: Vec<BlockHash> = Vec::new();
        for (hash, cached) in self.entries.iter() {
            if cached.inserted_at.elapsed() > self.ttl {
                victims.push(hash.clone());
            }
        }
        let n = victims.len();
        for h in victims {
            self.remove(&h);
        }
        n
    }

    /// O(1) eviction of the oldest entry — used when `insert` is
    /// called at capacity.
    fn evict_oldest(&mut self) {
        // The deque may contain stale hashes (entries that were
        // explicitly removed). Skip them until we find a live one.
        while let Some(hash) = self.insertion_order.pop_front() {
            if self.entries.contains_key(&hash) {
                self.remove(&hash);
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests;
