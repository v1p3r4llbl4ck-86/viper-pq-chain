// SPDX-License-Identifier: BUSL-1.1
//! cargo-fuzz target: fuzz the CBOR transaction decoder.
//!
//! # Running
//!
//! ```bash
//! # Requires nightly + cargo-fuzz:
//! rustup install nightly
//! cargo install cargo-fuzz
//!
//! # From the workspace root:
//! cargo +nightly fuzz run fuzz_decode_tx --manifest-path fuzz/Cargo.toml
//! ```
//!
//! # Invariant
//!
//! `decode_tx(arbitrary_bytes)` must never panic, overflow, or produce undefined
//! behaviour regardless of input. It must return either `Ok(Transaction)` or
//! `Err(TxError::EncodingInvalid)`.

#![no_main]
use libfuzzer_sys::fuzz_target;
use pqc_tx::codec::decode_tx;
use pqc_tx::error::TxError;

fuzz_target!(|data: &[u8]| {
    match decode_tx(data) {
        Ok(_) => {}
        Err(e) => {
            // Only EncodingInvalid is a valid error from decode_tx.
            // Any other error kind indicates a contract violation.
            assert_eq!(
                e,
                TxError::EncodingInvalid,
                "decode_tx returned unexpected error variant: {e:?}"
            );
        }
    }
});
