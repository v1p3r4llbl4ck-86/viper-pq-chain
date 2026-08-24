// SPDX-License-Identifier: BUSL-1.1
//! `token_transfer` state transition — SPEC-OPS-001 §5.3.

use crate::{error::ApplyError, store::StateStore};
use ciborium::value::Value;
use pqc_types::{
    account::{Account, Address},
    keyset::KeySet,
    transaction::Transaction,
};

/// Apply a `token_transfer` operation.
///
/// Preconditions (SPEC-OPS-001 §5.3):
/// - `amount` > 0
/// - `sender ≠ recipient`
/// - `sender.balance ≥ amount + fee_actual + fee_tip`
///
/// State transition:
/// - `sender.balance -= amount + fee_actual + fee_tip`
/// - `sender.nonce += 1`
/// - if recipient does not exist: create with `balance=amount`, empty KeySet
/// - if recipient exists: `recipient.balance += amount`
pub fn apply_token_transfer(store: &mut StateStore, tx: &Transaction) -> Result<(), ApplyError> {
    let payload = decode_token_transfer_payload(&tx.payload)?;

    // amount > 0
    if payload.amount == 0 {
        return Err(ApplyError::TransferAmountZero);
    }

    // sender ≠ recipient
    if tx.sender == payload.recipient {
        return Err(ApplyError::SelfTransfer);
    }

    // Check sender exists (must exist; validated by pipeline step 7)
    let sender_balance = store
        .get_account(&tx.sender)
        .ok_or(ApplyError::InsufficientFunds)?
        .balance;

    if sender_balance < payload.amount {
        return Err(ApplyError::InsufficientFunds);
    }

    // Apply sender: deduct transfer amount only.
    // Envelope-level fee settlement and nonce increment happen in `apply_tx`.
    {
        let sender = store
            .get_account_mut(&tx.sender)
            .ok_or(ApplyError::InsufficientFunds)?;
        sender.balance -= payload.amount;
    }
    store.commit_account_mutation(&tx.sender);

    // Apply recipient: create implicitly if absent, otherwise credit
    if store.get_account(&payload.recipient).is_some() {
        {
            let recipient = store
                .get_account_mut(&payload.recipient)
                .ok_or(ApplyError::InsufficientFunds)?;
            recipient.balance += payload.amount;
        }
        store.commit_account_mutation(&payload.recipient);
    } else {
        // Implicit account creation — SPEC-OPS-001 §5.3
        // Created with empty KeySet: cannot sign until key_add or vault_create
        let new_account = Account {
            address: payload.recipient.clone(),
            balance: payload.amount,
            nonce: 0,
            keys: KeySet::default(),
            policy_version: 0,
            policy_hash: None,
            verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
            auth_data: Vec::new(),
        };
        store.insert_account(new_account);
    }

    tracing::debug!(
        sender = %tx.sender,
        recipient = %payload.recipient,
        amount = payload.amount,
        "token_transfer applied"
    );

    Ok(())
}

struct TokenTransferPayload {
    recipient: Address,
    amount: u128,
}

fn decode_token_transfer_payload(payload: &[u8]) -> Result<TokenTransferPayload, ApplyError> {
    if payload.is_empty() {
        return Err(ApplyError::PayloadDecode("empty payload".into()));
    }

    let value: Value =
        ciborium::from_reader(payload).map_err(|e: ciborium::de::Error<std::io::Error>| {
            ApplyError::PayloadDecode(e.to_string())
        })?;

    let map = match value {
        Value::Map(m) => m,
        _ => {
            return Err(ApplyError::PayloadDecode(
                "payload must be a CBOR map".into(),
            ))
        }
    };

    let mut recipient_bytes: Option<Vec<u8>> = None;
    let mut amount: Option<u128> = None;

    for (k, v) in map {
        let key = match k {
            Value::Integer(i) => i128::from(i),
            _ => return Err(ApplyError::PayloadDecode("non-integer map key".into())),
        };
        match key {
            1 => recipient_bytes = Some(expect_bytes(v)?),
            2 => amount = Some(expect_u128(v)?),
            3 => {} // memo_hash — optional, not stored in Phase 1 state
            _ => {
                return Err(ApplyError::PayloadDecode(format!(
                    "unknown payload key: {key}"
                )))
            }
        }
    }

    let recipient_bytes = recipient_bytes
        .ok_or_else(|| ApplyError::PayloadDecode("missing field 1 (recipient)".into()))?;

    if recipient_bytes.len() != 32 {
        return Err(ApplyError::InvalidRecipient);
    }
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&recipient_bytes);

    Ok(TokenTransferPayload {
        recipient: Address(addr),
        amount: amount
            .ok_or_else(|| ApplyError::PayloadDecode("missing field 2 (amount)".into()))?,
    })
}

fn expect_bytes(v: Value) -> Result<Vec<u8>, ApplyError> {
    match v {
        Value::Bytes(b) => Ok(b),
        _ => Err(ApplyError::PayloadDecode("expected bytes".into())),
    }
}

// Amount (payload key 2) accepts two canonical encodings:
//   - CBOR unsigned integer (major type 0) — for amounts ≤ u64::MAX
//   - 16-byte big-endian bytestring — for amounts that exceed u64::MAX
// The bstr form matches the u128-balance convention in
// pqc_types::multisig::MultisigAccountState::to_cbor_bytes.
fn expect_u128(v: Value) -> Result<u128, ApplyError> {
    match v {
        Value::Integer(i) => u128::try_from(i128::from(i))
            .map_err(|_| ApplyError::PayloadDecode("amount out of u128 range".into())),
        Value::Bytes(b) => {
            if b.len() != 16 {
                return Err(ApplyError::PayloadDecode(format!(
                    "amount bytestring must be exactly 16 bytes, got {}",
                    b.len()
                )));
            }
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&b);
            Ok(u128::from_be_bytes(arr))
        }
        _ => Err(ApplyError::PayloadDecode(
            "amount must be integer or 16-byte bytestring".into(),
        )),
    }
}
