// SPDX-License-Identifier: Apache-2.0
//! pqc-tx — Transaction encoding, preimage construction, and validation pipeline.
//!
//! # Pipeline
//!
//! The 15-step validation pipeline is in [`validate`].
//! CBOR encoding/decoding is in [`codec`].
//! Signed preimage construction is in [`preimage`].

pub mod codec;
pub mod error;
pub mod hash;
pub mod preimage;
pub mod state_view;
pub mod validate;

pub use error::TxError;
pub use hash::compute_tx_hash;
pub use validate::{validate_tx, ValidationContext};

#[cfg(test)]
mod tests;
