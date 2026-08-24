// SPDX-License-Identifier: Apache-2.0
//! Tests for `wallet`.
//!
//! Extracted from `wallet.rs` 2026-05-10. `use super::*;`
//! brings every private item from the parent module into scope.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use super::*;
use pqc_crypto::alg::AlgId;

const TEST_CHAIN_ID: &[u8] = b"test-chain";

#[test]
fn test_derive_address_domain_separation() {
    // Same pk bytes with different alg_id produces different addresses.
    let pk = [0xABu8; 1952]; // ML-DSA-65 pk size
    let addr_44 = pqc_crypto::derive_address(TEST_CHAIN_ID, AlgId::MlDsa44, &pk);
    let addr_65 = pqc_crypto::derive_address(TEST_CHAIN_ID, AlgId::MlDsa65, &pk);
    assert_ne!(
        addr_44, addr_65,
        "different alg_id must produce different addresses"
    );
}

#[test]
fn test_bech32m_roundtrip() {
    let raw = [0x42u8; 32];
    let encoded = pqc_crypto::address_to_bech32m(&raw, "vpr").expect("encode failed");
    assert!(encoded.starts_with("vpr1"));
    let decoded = pqc_crypto::bech32m_to_address(&encoded).expect("bech32m decode should succeed");
    assert_eq!(decoded, raw);

    // Also test testnet HRP.
    let encoded_t = pqc_crypto::address_to_bech32m(&raw, "vpt").expect("encode failed");
    assert!(encoded_t.starts_with("vpt1"));
    let decoded_t =
        pqc_crypto::bech32m_to_address(&encoded_t).expect("bech32m decode should succeed");
    assert_eq!(decoded_t, raw);
}

#[test]
fn test_keystore_encrypt_decrypt_roundtrip() {
    let seed = [0x77u8; 32];
    let passphrase = "test-passphrase-123";

    let ks = Keystore::create_from_seed(TEST_CHAIN_ID, AlgId::MlDsa65, &seed, passphrase)
        .expect("create_from_seed should succeed");

    // Save and reload.
    let tmp_dir = std::env::temp_dir().join("pqcd_wallet_test_roundtrip");
    let _ = std::fs::remove_dir_all(&tmp_dir);
    let path = tmp_dir.join("test_keystore.json");
    ks.save(&path).expect("save should succeed");

    let loaded = Keystore::load(&path).expect("load should succeed");
    let decrypted = loaded
        .decrypt_seed(passphrase)
        .expect("decrypt should succeed");
    assert_eq!(decrypted, seed, "decrypted seed must match original");

    // Wrong passphrase should fail.
    let err = loaded.decrypt_seed("wrong-passphrase");
    assert!(err.is_err(), "wrong passphrase must fail");

    // Cleanup.
    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_mnemonic_derivation_deterministic() {
    // Use a fixed mnemonic for determinism.
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let passphrase = "wallet-passphrase";

    let ks1 = Keystore::create_from_mnemonic(TEST_CHAIN_ID, AlgId::MlDsa65, mnemonic, passphrase)
        .expect("first create_from_mnemonic should succeed");
    let ks2 = Keystore::create_from_mnemonic(TEST_CHAIN_ID, AlgId::MlDsa65, mnemonic, passphrase)
        .expect("second create_from_mnemonic should succeed");

    assert_eq!(
        ks1.address, ks2.address,
        "same mnemonic must produce same address"
    );
    assert_eq!(
        ks1.public_key, ks2.public_key,
        "same mnemonic must produce same pk"
    );

    // Different alg_id with same mnemonic must produce different address.
    let ks3 = Keystore::create_from_mnemonic(TEST_CHAIN_ID, AlgId::MlDsa44, mnemonic, passphrase)
        .expect("create_from_mnemonic with different alg should succeed");
    assert_ne!(
        ks1.address, ks3.address,
        "different alg must produce different address"
    );
}

#[test]
fn test_sign_and_verify_roundtrip() {
    let seed = [0x55u8; 32];
    let alg_id = AlgId::MlDsa65;
    let passphrase = "sign-test";

    let ks = Keystore::create_from_seed(TEST_CHAIN_ID, alg_id, &seed, passphrase)
        .expect("create_from_seed should succeed");

    // Build a minimal unsigned transaction.
    let pk_bytes = pqc_crypto::ml_dsa_public_key_from_seed(alg_id, &seed)
        .expect("pk derivation should succeed");
    let address = pqc_crypto::derive_address(TEST_CHAIN_ID, alg_id, &pk_bytes);

    use pqc_types::account::Address;
    use pqc_types::transaction::{MsgType, Transaction};

    let unsigned_tx = Transaction {
        tx_version: 1,
        chain_id: b"test-chain".to_vec(),
        msg_type: MsgType::TokenTransfer,
        sender: Address(address),
        nonce: 1,
        fee: 1000,
        fee_tip: 0,
        gas_limit: 100,
        payload: vec![],
        sig_alg_id: alg_id,
        sig_key_version: 1,
        signature: vec![], // empty — unsigned
    };

    let unsigned_cbor = pqc_tx::codec::encode_tx(&unsigned_tx).expect("encode_tx should succeed");

    // Sign.
    let signed_cbor = ks
        .sign_transaction(passphrase, &unsigned_cbor)
        .expect("sign_transaction should succeed");

    // Decode the signed tx and verify signature.
    let signed_tx =
        pqc_tx::codec::decode_tx(&signed_cbor).expect("decode signed tx should succeed");
    assert!(
        !signed_tx.signature.is_empty(),
        "signature must not be empty"
    );

    // Verify using PqVerifier.
    let verifier = pqc_crypto::MlDsaVerifier;
    let pk = pqc_crypto::PublicKey {
        alg_id,
        bytes: pk_bytes,
    };
    let sig = pqc_crypto::Signature {
        alg_id,
        bytes: signed_tx.signature.clone(),
    };
    let fork_digest = pqc_types::ForkDigest::viper_research_1();
    let preimage = pqc_tx::preimage::build_preimage(&fork_digest, &signed_tx)
        .expect("build_preimage should succeed");

    use pqc_crypto::SignatureVerifier;
    verifier
        .verify(&pk, &preimage, &sig)
        .expect("signature verification should succeed");
}

#[test]
fn test_hkdf_shake256_deterministic() {
    // Same inputs always produce same output.
    let ikm = [0x01u8; 64];
    let salt = b"test-salt";
    let info = [0x00, 0x02];
    let a = hkdf_shake256(&ikm, salt, &info, 32);
    let b = hkdf_shake256(&ikm, salt, &info, 32);
    assert_eq!(a, b);

    // Different info produces different output.
    let c = hkdf_shake256(&ikm, salt, &[0x00, 0x03], 32);
    assert_ne!(a, c);
}

#[test]
fn test_parse_alg_flag() {
    assert_eq!(parse_alg_flag("ml-dsa-44").unwrap(), AlgId::MlDsa44);
    assert_eq!(parse_alg_flag("ml-dsa-65").unwrap(), AlgId::MlDsa65);
    assert_eq!(parse_alg_flag("ml-dsa-87").unwrap(), AlgId::MlDsa87);
    assert!(parse_alg_flag("unknown").is_err());
}
