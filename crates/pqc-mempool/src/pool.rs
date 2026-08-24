// SPDX-License-Identifier: BUSL-1.1
//! Pending transaction pool with replacement tracking.

use pqc_types::transaction::Transaction;
use std::collections::HashMap;

/// A pending entry in the mempool.
#[derive(Debug, Clone)]
pub struct PendingEntry {
    pub tx: Transaction,
    pub raw_bytes: Vec<u8>,
    /// tx_hash = SHAKE-256(raw_bytes, 32). Placeholder zeros until hash module is wired.
    pub tx_hash: [u8; 32],
    /// Effective fee = tx.fee (used for replacement policy comparisons).
    pub fee: u64,
    pub fee_tip: u64,
}

/// In-memory pending transaction pool.
///
/// Indexes:
/// - `by_hash`: tx_hash → entry (primary)
/// - `by_sender_nonce`: (sender_addr, nonce) → tx_hash (for replacement lookups)
/// - `vc_admitted_count`: count of V-C (SLH-DSA) transactions admitted this block interval
#[derive(Clone)]
pub struct Mempool {
    by_hash: HashMap<[u8; 32], PendingEntry>,
    /// (sender_addr_bytes, nonce) → tx_hash of the currently pending tx for that slot
    by_sender_nonce: HashMap<([u8; 32], u64), [u8; 32]>,
    /// Count of V-C algorithm transactions in the current block interval.
    /// Reset by the block assembler after each block.
    vc_admitted_count: usize,
    /// Configurable cap for V-C admissions per block interval.
    pub vc_per_block_cap: usize,
}

impl Mempool {
    pub fn new() -> Self {
        Self {
            by_hash: HashMap::new(),
            by_sender_nonce: HashMap::new(),
            vc_admitted_count: 0,
            vc_per_block_cap: 10, // conservative default; Phase 2 calibration target
        }
    }

    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }

    /// Returns the pending entry for a given tx_hash, if present.
    pub fn get(&self, tx_hash: &[u8; 32]) -> Option<&PendingEntry> {
        self.by_hash.get(tx_hash)
    }

    /// Returns the currently pending tx_hash for a given (sender, nonce) slot, if any.
    pub fn pending_for_slot(&self, sender: &[u8; 32], nonce: u64) -> Option<&[u8; 32]> {
        self.by_sender_nonce.get(&(*sender, nonce))
    }

    /// Insert an entry. Caller (admission) is responsible for evicting any replaced entry first.
    pub(crate) fn insert(&mut self, entry: PendingEntry) {
        let sender = entry.tx.sender.0;
        let nonce = entry.tx.nonce;
        let hash = entry.tx_hash;

        self.by_sender_nonce.insert((sender, nonce), hash);
        self.by_hash.insert(hash, entry);
    }

    /// Evict a pending entry by tx_hash.
    ///
    /// Used by replacement logic and by the block assembler after inclusion or
    /// when a pending transaction becomes invalid against the evolving block state.
    pub fn evict(&mut self, tx_hash: &[u8; 32]) -> Option<PendingEntry> {
        if let Some(entry) = self.by_hash.remove(tx_hash) {
            self.by_sender_nonce
                .remove(&(entry.tx.sender.0, entry.tx.nonce));
            Some(entry)
        } else {
            None
        }
    }

    /// Drain all entries with nonce < committed_nonce for a given sender.
    /// Called by the block assembler after including a transaction from this sender.
    pub fn evict_stale(&mut self, sender: &[u8; 32], committed_nonce: u64) {
        let stale_hashes: Vec<[u8; 32]> = self
            .by_hash
            .values()
            .filter(|e| e.tx.sender.0 == *sender && e.tx.nonce < committed_nonce)
            .map(|e| e.tx_hash)
            .collect();
        for hash in stale_hashes {
            self.evict(&hash);
        }
    }

    pub fn vc_admitted_count(&self) -> usize {
        self.vc_admitted_count
    }

    pub(crate) fn increment_vc_count(&mut self) {
        self.vc_admitted_count += 1;
    }

    /// Reset per-block V-C counter. Called by block assembler at each new block interval.
    pub fn reset_vc_count(&mut self) {
        self.vc_admitted_count = 0;
    }

    /// Ordered pending transactions for a given sender, sorted by nonce ascending.
    pub fn pending_for_sender(&self, sender: &[u8; 32]) -> Vec<&PendingEntry> {
        let mut entries: Vec<&PendingEntry> = self
            .by_hash
            .values()
            .filter(|e| e.tx.sender.0 == *sender)
            .collect();
        entries.sort_by_key(|e| e.tx.nonce);
        entries
    }

    /// All pending entries in insertion-arbitrary order.
    /// Block assembler applies its own ordering (fee priority, nonce ordering per sender).
    pub fn all_pending(&self) -> impl Iterator<Item = &PendingEntry> {
        self.by_hash.values()
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}
