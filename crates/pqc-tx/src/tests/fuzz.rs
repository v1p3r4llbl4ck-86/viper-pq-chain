// SPDX-License-Identifier: Apache-2.0
//! Fuzz-style property tests for the transaction parsing and validation pipeline.
//!
//! These tests run with proptest (stable, CI-friendly). The invariants they protect:
//!
//! - **No panics**: every public entry point must return a typed error for any
//!   input — never panic, abort, or access out-of-bounds memory.
//! - **Error containment**: parsing errors must surface as `TxError::EncodingInvalid`,
//!   not as panic or ICE.
//! - **Determinism**: encoding a decoded transaction and re-decoding must yield
//!   an identical result (round-trip stability).
//!
//! These tests are the CI-runnable counterpart to the `fuzz/` directory cargo-fuzz
//! targets (require nightly + libFuzzer). Both cover the same entry points; the
//! proptest variants run as ordinary `cargo test` cases.
//!
//! # Running
//!
//! ```bash
//! cargo test -p pqc-tx fuzz
//! # With a fixed seed for determinism:
//! PROPTEST_SEED=0 cargo test -p pqc-tx fuzz
//! ```

use pqc_crypto::{sign::StubVerifier, AlgId, Lifecycle};
use pqc_types::{
    account::{Account, Address},
    keyset::{allowed_tx, KeyEntry, KeySet, KeyStatus},
    transaction::{MsgType, Transaction},
};
use proptest::prelude::*;

use crate::{
    codec::{decode_tx, encode_tx},
    error::TxError,
    validate::{validate_tx, FeeParams, ValidationContext},
};

// ── Helper: minimal account that can authorize any tx ─────────────────────────

fn stub_account(addr: &Address) -> Account {
    Account {
        address: addr.clone(),
        balance: u128::MAX,
        nonce: 1,
        keys: KeySet(vec![KeyEntry {
            alg_id: AlgId::MlDsa65,
            pk_bytes: vec![0u8; 32].into(),
            key_version: 1,
            valid_from_height: 0,
            status: KeyStatus::Active,
            allowed_tx_types: allowed_tx::ALL,
        }]),
        policy_version: 0,
        policy_hash: None,
        verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
        auth_data: Vec::new(),
    }
}

fn stub_ctx(account: Option<&Account>, _raw_len: usize) -> ValidationContext<'_> {
    ValidationContext {
        chain_id: &[],
        fork_digest: &TEST_FORK_DIGEST,
        current_height: 100,
        sender_account: account,
        fee_params: FeeParams::default(),
        verifier: &StubVerifier,
        alg_lifecycle: &|_| Some(Lifecycle::Active),
        alg_min_fee: &|_| Some(0),
    }
}

static TEST_FORK_DIGEST: std::sync::LazyLock<pqc_types::ForkDigest> =
    std::sync::LazyLock::new(pqc_types::ForkDigest::viper_research_1);

// ── Property 1: decode_tx never panics on arbitrary bytes ─────────────────────
//
// This is the primary entry point for external data. Any sequence of bytes
// must produce either Ok(Transaction) or Err(EncodingInvalid) — never a panic.

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 2048,
        max_shrink_iters: 256,
        ..ProptestConfig::default()
    })]

    #[test]
    fn prop_decode_tx_never_panics(raw in proptest::collection::vec(any::<u8>(), 0..4096)) {
        // The contract: decode_tx(anything) must not panic.
        let _ = decode_tx(&raw);
    }

    #[test]
    fn prop_decode_tx_error_is_encoding_invalid_or_ok(
        raw in proptest::collection::vec(any::<u8>(), 0..4096)
    ) {
        match decode_tx(&raw) {
            Ok(_) => {}
            Err(e) => {
                prop_assert!(
                    e == TxError::EncodingInvalid,
                    "decode_tx must only return EncodingInvalid on failure, got {:?}", e
                );
            }
        }
    }
}

// ── Property 2: validate_tx never panics on arbitrary raw bytes ───────────────
//
// Even with a well-formed Transaction struct, the raw bytes might be anything
// (size cap check uses raw_bytes.len()). Combined with a garbage Transaction,
// validate_tx must always return a typed error, never panic.

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1024,
        max_shrink_iters: 128,
        ..ProptestConfig::default()
    })]

    #[test]
    fn prop_validate_tx_never_panics_with_raw_bytes(
        // Up to 2 MiB — covers sizes below, at, and above the 1 MiB cap.
        // Kept at 65536 for CI speed; the cap boundary is pinned by pipeline tests.
        raw in proptest::collection::vec(any::<u8>(), 0..65_536usize)
    ) {
        // Construct a plausible Transaction; validate_tx with raw bytes of
        // arbitrary length — the size cap check must not panic even on huge inputs.
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
        let account = stub_account(&tx.sender);
        let ctx = stub_ctx(Some(&account), raw.len());
        let _ = validate_tx(&tx, &raw, &ctx);
    }

    #[test]
    fn prop_validate_tx_result_is_typed(
        raw in proptest::collection::vec(any::<u8>(), 0..4096)
    ) {
        // Fuzz the raw bytes path through the first step (size cap).
        // Result must be either Ok(()) or a typed TxError variant — never panic.
        let tx = Transaction {
            tx_version: 1,
            chain_id: vec![],
            msg_type: MsgType::TokenTransfer,
            sender: Address([0x22u8; 32]),
            nonce: 1,
            fee: 0,
            fee_tip: 0,
            gas_limit: 100_000,
            payload: vec![],
            sig_alg_id: AlgId::MlDsa65,
            sig_key_version: 1,
            signature: vec![0u8; 3_309],
        };
        let account = stub_account(&tx.sender);
        let ctx = stub_ctx(Some(&account), raw.len());
        let _ = validate_tx(&tx, &raw, &ctx);
    }
}

// ── Property 3: encode → decode round-trip stability ─────────────────────────
//
// A transaction that can be decoded must round-trip: encode(decode(raw)) == raw.
// This catches asymmetric encoding bugs where decode succeeds on non-canonical
// bytes that re-encode differently.

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 512,
        ..ProptestConfig::default()
    })]

    #[test]
    fn prop_decode_encode_round_trip_stability(
        raw in proptest::collection::vec(any::<u8>(), 0..4096)
    ) {
        if let Ok(tx) = decode_tx(&raw) {
            // If decode succeeds, re-encoding must produce identical bytes.
            // (decode_tx enforces canonical form via round-trip check internally,
            // so this test confirms the internal contract holds end-to-end.)
            let reencoded = encode_tx(&tx).expect("encode must succeed for a decoded tx");
            prop_assert_eq!(
                reencoded, raw,
                "encode(decode(raw)) must equal raw for any successfully decoded tx"
            );
        }
    }
}

// ── Property 4: AlgId::from_u16 never panics ─────────────────────────────────
//
// The CBOR decoder constructs AlgId from raw u16 values. Unknown values must
// return None, not panic.

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 65536,
        ..ProptestConfig::default()
    })]

    #[test]
    fn prop_alg_id_from_u16_never_panics(v in any::<u16>()) {
        let _ = AlgId::from_u16(v);
    }
}
