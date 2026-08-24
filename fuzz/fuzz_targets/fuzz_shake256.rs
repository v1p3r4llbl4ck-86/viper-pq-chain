// SPDX-License-Identifier: BUSL-1.1
//! cargo-fuzz target: confirm SHAKE-256 never panics for any input.
//!
//! # Running
//!
//! ```bash
//! cargo +nightly fuzz run fuzz_shake256 --manifest-path fuzz/Cargo.toml
//! ```
//!
//! # Invariant
//!
//! `shake256_32(arbitrary_bytes)` must always return exactly 32 bytes and must
//! never panic. This is the hot path for tx hashing, address derivation, and
//! state root computation.

#![no_main]
use libfuzzer_sys::fuzz_target;
use pqc_crypto::shake256_32;

fuzz_target!(|data: &[u8]| {
    let out = shake256_32(data);
    // Length must always be exactly 32 bytes.
    assert_eq!(out.len(), 32, "shake256_32 must always produce 32 bytes");
});
