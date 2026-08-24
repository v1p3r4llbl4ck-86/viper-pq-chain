// SPDX-License-Identifier: BUSL-1.1
//! pqc-mempool — Transaction admission, lifecycle, and replacement policy.
//!
//! # Design
//!
//! The mempool is a read-only boundary on state: it validates transactions against
//! a snapshot of chain state but MUST NOT mutate state. State mutation happens in
//! the block execution path (pqc-state::apply).
//!
//! # Transaction lifecycle
//!
//! ```text
//! received → [admission] → admitted (pending)
//!                       ↘ rejected(reason)
//!
//! pending → [block execution] → included(block_height)
//!         → [replacement]     → replaced(by_tx_hash)
//!         → [timeout/evict]   → dropped
//! ```
//!
//! SPEC-FEE-001 §9 — admission pipeline ordering.
//! SPEC-FEE-001 §11 — replacement policy.

pub mod admission;
pub mod error;
pub mod lifecycle;
pub mod pool;

pub use error::MempoolError;
pub use lifecycle::TxStatus;
pub use pool::Mempool;

#[cfg(test)]
mod tests;
