// SPDX-License-Identifier: BUSL-1.1
//! cargo-fuzz target: fuzz the full tx validation pipeline.
//!
//! # Running
//!
//! ```bash
//! cargo +nightly fuzz run fuzz_validate_tx --manifest-path fuzz/Cargo.toml
//! ```
//!
//! # Invariant
//!
//! `validate_tx(tx, raw, ctx)` must never panic for any combination of:
//!   - a structurally valid Transaction (produced by decoding or hardcoded)
//!   - arbitrary raw bytes (size cap is checked first)
//!   - a stub context (StubVerifier, active lifecycle, zero fees)
//!
//! All failure modes must surface as typed `TxError` variants.

#![no_main]
use libfuzzer_sys::fuzz_target;
use pqc_crypto::{AlgId, Lifecycle, sign::StubVerifier};
use pqc_tx::{
    codec::decode_tx,
    validate::{FeeParams, ValidationContext, validate_tx},
};

fuzz_target!(|data: &[u8]| {
    // Strategy 1: fuzz the raw bytes directly through decode + validate.
    if let Ok(tx) = decode_tx(data) {
        let ctx = ValidationContext {
            chain_id: &[],
            current_height: 100,
            sender_account: None, // sender absent → SenderNotFound error, no panic
            fee_params: FeeParams::default(),
            verifier: &StubVerifier,
            alg_lifecycle: &|_| Some(Lifecycle::Active),
            alg_min_fee: &|_| Some(0),
        };
        let _ = validate_tx(&tx, data, &ctx);
    }

    // Strategy 2: fuzz the raw bytes through the size-cap check with a fixed tx.
    // This ensures the size-cap guard doesn't panic on extreme inputs.
    use pqc_types::{account::Address, transaction::{MsgType, Transaction}};
    let tx = Transaction {
        tx_version: 1,
        chain_id: vec![],
        msg_type: MsgType::TokenTransfer,
        sender: Address([0x11u8; 32]),
        nonce: 1,
        fee: 0,
        fee_tip: 0,
        gas_limit: 100_000,
        payload: vec![],
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![0u8; 3_309],
    };
    let ctx = ValidationContext {
        chain_id: &[],
        current_height: 100,
        sender_account: None,
        fee_params: FeeParams::default(),
        verifier: &StubVerifier,
        alg_lifecycle: &|_| Some(Lifecycle::Active),
        alg_min_fee: &|_| Some(0),
    };
    let _ = validate_tx(&tx, data, &ctx);
});
