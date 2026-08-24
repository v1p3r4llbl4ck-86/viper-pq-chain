// SPDX-License-Identifier: BUSL-1.1
//! Transaction lifecycle states.

/// The status of a transaction as it moves through the node.
///
/// Transitions are append-only: a transaction can never go "backwards"
/// (e.g. from `Admitted` back to `Received`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxStatus {
    /// Transaction received from network or RPC; not yet validated.
    Received,
    /// Transaction failed admission; will not be reconsidered unless resubmitted.
    Rejected { reason: String },
    /// Transaction passed all admission checks; sitting in the pending pool.
    Admitted,
    /// Transaction was included in a finalized block.
    Included { block_height: u64 },
    /// Transaction was evicted from the pool (replaced by a higher-fee tx with same nonce).
    Replaced { by_tx_hash: [u8; 32] },
    /// Transaction was evicted without replacement (timeout, pool pressure, etc.).
    Dropped,
}
