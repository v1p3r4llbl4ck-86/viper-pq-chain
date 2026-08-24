// SPDX-License-Identifier: BUSL-1.1
//! `pqcd validate-tx <hex>` CLI handler.
//!
//! Extracted from `main.rs` 2026-05-10. Decodes a CBOR-encoded
//! transaction from hex and runs the 15-step `validate_tx` pipeline
//! locally — useful for debugging client SDKs without submitting to
//! a node.

use anyhow::{Context, Result};
use pqc_crypto::{alg::AlgId, Lifecycle};
use pqc_tx::validate::{FeeParams, ValidationContext};
use pqc_tx::{codec, validate};

pub fn cmd_validate_tx(hex_input: &str) -> Result<()> {
    let raw = hex::decode(hex_input.trim()).context("input is not valid hex")?;

    let tx = codec::decode_tx(&raw).map_err(|e| anyhow::anyhow!("decode failed: {e}"))?;

    println!("tx_version:      {}", tx.tx_version);
    println!("chain_id:        {}", hex::encode(&tx.chain_id));
    println!("msg_type:        {:?}", tx.msg_type);
    println!("sender:          {}", tx.sender);
    println!("nonce:           {}", tx.nonce);
    println!("fee:             {}", tx.fee);
    println!("fee_tip:         {}", tx.fee_tip);
    println!("gas_limit:       {}", tx.gas_limit);
    println!("sig_alg_id:      {:?}", tx.sig_alg_id);
    println!("sig_key_version: {}", tx.sig_key_version);
    println!("payload_bytes:   {}", tx.payload.len());
    println!("signature_bytes: {}", tx.signature.len());
    println!();

    use pqc_types::{
        account::Account,
        keyset::{allowed_tx, KeyEntry, KeySet, KeyStatus},
    };

    let sender_account = Account {
        address: tx.sender.clone(),
        balance: u128::MAX,
        nonce: tx.nonce,
        keys: KeySet(vec![KeyEntry {
            alg_id: tx.sig_alg_id,
            pk_bytes: tx.signature[..4].to_vec().into(),
            key_version: tx.sig_key_version,
            valid_from_height: 0,
            status: KeyStatus::Active,
            allowed_tx_types: allowed_tx::ALL,
        }]),
        policy_version: 0,
        policy_hash: None,
        verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
        auth_data: Vec::new(),
    };

    let verifier = pqc_crypto::sign::StubVerifier;
    let fork_digest = pqc_types::ForkDigest::viper_research_1();

    let ctx = ValidationContext {
        chain_id: &tx.chain_id,
        fork_digest: &fork_digest,
        current_height: 1,
        sender_account: Some(&sender_account),
        fee_params: FeeParams::default(),
        verifier: &verifier,
        alg_lifecycle: &|alg_id: AlgId| {
            if matches!(
                alg_id,
                AlgId::MlDsa44
                    | AlgId::MlDsa65
                    | AlgId::MlDsa87
                    | AlgId::FnDsaPadded512
                    | AlgId::SlhDsaSha2128s
            ) {
                Some(Lifecycle::Active)
            } else {
                None
            }
        },
        alg_min_fee: &|alg_id: AlgId| {
            if matches!(
                alg_id,
                AlgId::MlDsa44
                    | AlgId::MlDsa65
                    | AlgId::MlDsa87
                    | AlgId::FnDsaPadded512
                    | AlgId::SlhDsaSha2128s
            ) {
                Some(0)
            } else {
                None
            }
        },
    };

    match validate::validate_tx(&tx, &raw, &ctx) {
        Ok(()) => {
            println!("VALID — transaction passed all 15 validation steps");
            Ok(())
        }
        Err(e) => {
            println!("REJECTED — {e}");
            std::process::exit(1);
        }
    }
}
