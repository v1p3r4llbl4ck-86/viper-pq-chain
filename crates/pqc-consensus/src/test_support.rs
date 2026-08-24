// SPDX-License-Identifier: BUSL-1.1
//! Shared test fixtures for `pqc-consensus` integration tests.
//!
//! Compiled only in test mode. Reduces duplication across engine, recovery,
//! and storage test suites within this crate.

use ciborium::value::Value;
use pqc_crypto::{sign::StubVerifier, AlgId};
use pqc_mempool::{admission::try_admit, Mempool};
use pqc_state::StateStore;
use pqc_tx::{codec::encode_tx, validate::FeeParams};
use pqc_types::{
    account::{Account, Address},
    keyset::{allowed_tx, KeyEntry, KeySet, KeyStatus},
    transaction::{MsgType, Transaction},
};

// ── CBOR map builder ─────────────────────────────────────────────────────────

pub enum CborVal {
    Int(u64),
    Bytes(Vec<u8>),
}

/// Encode a CBOR definite-length map from (integer key, value) pairs.
pub fn cbor_map(pairs: Vec<(u64, CborVal)>) -> Vec<u8> {
    let entries: Vec<(Value, Value)> = pairs
        .into_iter()
        .map(|(key, value)| {
            let key = Value::Integer(key.into());
            let value = match value {
                CborVal::Int(int) => Value::Integer(int.into()),
                CborVal::Bytes(bytes) => Value::Bytes(bytes),
            };
            (key, value)
        })
        .collect();

    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(entries), &mut out).unwrap();
    out
}

// ── Account fixtures ──────────────────────────────────────────────────────────

/// An account with a single immediately-active ML-DSA key.
/// Used as a signing account in block assembly and replay tests.
pub fn signer_account(address: Address, balance: u128, nonce: u64, alg_id: AlgId) -> Account {
    Account {
        address,
        balance,
        nonce,
        keys: KeySet(vec![KeyEntry {
            alg_id,
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

// ── Payload builders ──────────────────────────────────────────────────────────

pub fn transfer_payload(recipient: &Address, amount: u64) -> Vec<u8> {
    cbor_map(vec![
        (1, CborVal::Bytes(recipient.0.to_vec())),
        (2, CborVal::Int(amount)),
    ])
}

pub fn vault_payload(alg_id: AlgId, pk_bytes: Vec<u8>) -> Vec<u8> {
    cbor_map(vec![
        (1, CborVal::Int(alg_id.as_u16() as u64)),
        (2, CborVal::Bytes(pk_bytes)),
        (3, CborVal::Int(allowed_tx::ALL as u64)),
        (4, CborVal::Int(0)),
    ])
}

pub fn attestation_payload(
    subject: [u8; 32],
    attestation_type: u16,
    content_hash: [u8; 32],
    schema_id: [u8; 32],
) -> Vec<u8> {
    cbor_map(vec![
        (1, CborVal::Bytes(subject.to_vec())),
        (2, CborVal::Int(attestation_type as u64)),
        (3, CborVal::Bytes(content_hash.to_vec())),
        (4, CborVal::Bytes(schema_id.to_vec())),
    ])
}

// ── Transaction builders ──────────────────────────────────────────────────────

/// A token transfer transaction. `signature_fill` sets all signature bytes to
/// the same value (used to produce distinct raw bytes across test transactions).
pub fn transfer_tx(
    sender: Address,
    _recipient: Address,
    nonce: u64,
    fee: u64,
    fee_tip: u64,
    signature_fill: u8,
    alg_id: AlgId,
) -> Transaction {
    Transaction {
        tx_version: 1,
        chain_id: Vec::new(),
        msg_type: MsgType::TokenTransfer,
        sender,
        nonce,
        fee,
        fee_tip,
        gas_limit: 100_000,
        payload: transfer_payload(&Address([0x11; 32]), 100),
        sig_alg_id: alg_id,
        sig_key_version: 1,
        signature: vec![
            signature_fill;
            match alg_id {
                AlgId::SlhDsaSha2128s => 7_856,
                _ => 3_309,
            }
        ],
    }
}

pub fn vault_create_tx(
    sender: Address,
    nonce: u64,
    fee: u64,
    signature_fill: u8,
    pk_bytes: Vec<u8>,
) -> Transaction {
    Transaction {
        tx_version: 1,
        chain_id: Vec::new(),
        msg_type: MsgType::VaultCreate,
        sender,
        nonce,
        fee,
        fee_tip: 0,
        gas_limit: 500_000,
        payload: vault_payload(AlgId::MlDsa65, pk_bytes),
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![signature_fill; 3_309],
    }
}

pub fn attestation_create_tx(
    sender: Address,
    nonce: u64,
    fee: u64,
    signature_fill: u8,
    subject: [u8; 32],
    attestation_type: u16,
) -> Transaction {
    Transaction {
        tx_version: 1,
        chain_id: Vec::new(),
        msg_type: MsgType::AttestationCreate,
        sender,
        nonce,
        fee,
        fee_tip: 0,
        gas_limit: 100_000,
        payload: attestation_payload(subject, attestation_type, [0x22; 32], [0x33; 32]),
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![signature_fill; 3_309],
    }
}

// ── Mempool helpers ───────────────────────────────────────────────────────────

/// Encode and admit a transaction. Panics if admission fails.
/// Returns the assigned tx_hash.
pub fn admit(pool: &mut Mempool, store: &StateStore, tx: &Transaction) -> [u8; 32] {
    let raw = encode_tx(tx).expect("encode must succeed");
    let verifier = StubVerifier;
    try_admit(pool, raw, store, &verifier, &FeeParams::default())
        .expect("admission must succeed")
        .tx_hash
}
