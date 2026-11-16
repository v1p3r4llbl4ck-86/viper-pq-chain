//! viper-ricordi — the only piece of Viper PQ Chain the Ricordi Indelebili site runs.
//!
//! Commands (all output is one line of JSON on stdout, errors on stderr + exit 1):
//!   keys    <seed-file> <chain-id-hex>                  -> {"public_key_hex","address_hex"}
//!   sign    <seed-file> <message-hex>                   -> {"signature_hex"}   (ML-DSA-65)
//!   verify  <public-key-hex> <message-hex> <sig-hex>    -> {"valid":true|false}
//!   attest  <seed-file> <chain-id-hex> <nonce> <schema-id-hex> <content-hash-hex> <metadata-hash-hex>
//!                                                       -> {"tx_b64","tx_hash_hex"}
//!
//! The seed file holds 64 hex chars (32 bytes). The attestation tx is the same
//! `attestation_create` (document type 1) a notary service builds.

use anyhow::{bail, Context, Result};
use base64::Engine;
use ciborium::value::Value;
use pqc_crypto::{
    derive_address, ml_dsa_public_key_from_seed, ml_dsa_sign_with_seed, AlgId, MlDsaVerifier,
    PublicKey, Signature, SignatureVerifier,
};
use pqc_tx::{codec::encode_tx, compute_tx_hash, preimage::build_preimage};
use pqc_types::{
    transaction::{MsgType, Transaction},
    Address,
};

const ALG: AlgId = AlgId::MlDsa65;
const TX_VERSION: u8 = 1;
const ATTESTATION_TYPE_DOCUMENT: u16 = 1;
const SIG_KEY_VERSION: u32 = 1;
const FEE_BUDGET: u64 = 2_000_000;
const GAS_LIMIT: u64 = 500;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match run(&args) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("viper-ricordi: {e:#}");
            std::process::exit(1);
        }
    }
}

fn run(args: &[String]) -> Result<String> {
    let arg = |i: usize| -> Result<&str> {
        args.get(i)
            .map(String::as_str)
            .context("missing argument (see module doc)")
    };
    match arg(1)? {
        "keys" => {
            let seed = read_seed(arg(2)?)?;
            let chain_id = hex::decode(arg(3)?).context("chain-id-hex")?;
            let pk = ml_dsa_public_key_from_seed(ALG, &seed)?;
            let addr = derive_address(&chain_id, ALG, &pk);
            Ok(format!(
                r#"{{"public_key_hex":"{}","address_hex":"{}"}}"#,
                hex::encode(pk),
                hex::encode(addr)
            ))
        }
        "sign" => {
            let seed = read_seed(arg(2)?)?;
            let msg = hex::decode(arg(3)?).context("message-hex")?;
            let sig = ml_dsa_sign_with_seed(ALG, &seed, &msg)?;
            Ok(format!(r#"{{"signature_hex":"{}"}}"#, hex::encode(sig)))
        }
        "verify" => {
            let pk = hex::decode(arg(2)?).context("public-key-hex")?;
            let msg = hex::decode(arg(3)?).context("message-hex")?;
            let sig = hex::decode(arg(4)?).context("sig-hex")?;
            let valid = MlDsaVerifier
                .verify(
                    &PublicKey {
                        alg_id: ALG,
                        bytes: pk,
                    },
                    &msg,
                    &Signature {
                        alg_id: ALG,
                        bytes: sig,
                    },
                )
                .is_ok();
            Ok(format!(r#"{{"valid":{valid}}}"#))
        }
        "attest" => {
            let seed = read_seed(arg(2)?)?;
            let chain_id = hex::decode(arg(3)?).context("chain-id-hex")?;
            let nonce: u64 = arg(4)?.parse().context("nonce")?;
            let schema = hex32(arg(5)?)?;
            let content = hex32(arg(6)?)?;
            let meta = hex32(arg(7)?)?;
            let pk = ml_dsa_public_key_from_seed(ALG, &seed)?;
            let sender = derive_address(&chain_id, ALG, &pk);
            let (raw, hash) =
                build_attestation(&chain_id, &sender, &seed, nonce, &schema, &content, &meta)?;
            Ok(format!(
                r#"{{"tx_b64":"{}","tx_hash_hex":"{}"}}"#,
                base64::engine::general_purpose::STANDARD.encode(raw),
                hex::encode(hash)
            ))
        }
        other => bail!("unknown command {other}"),
    }
}

fn read_seed(path: &str) -> Result<[u8; 32]> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read seed {path}"))?;
    hex32(text.trim())
}

fn hex32(s: &str) -> Result<[u8; 32]> {
    let v = hex::decode(s).context("hex")?;
    v.try_into()
        .map_err(|_| anyhow::anyhow!("expected 32 bytes"))
}

fn build_attestation(
    chain_id: &[u8],
    sender: &[u8; 32],
    seed: &[u8; 32],
    nonce: u64,
    schema_id: &[u8; 32],
    content_hash: &[u8; 32],
    metadata_hash: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 32])> {
    let map = Value::Map(vec![
        (Value::Integer(1u64.into()), Value::Bytes(sender.to_vec())),
        (
            Value::Integer(2u64.into()),
            Value::Integer(u64::from(ATTESTATION_TYPE_DOCUMENT).into()),
        ),
        (
            Value::Integer(3u64.into()),
            Value::Bytes(content_hash.to_vec()),
        ),
        (
            Value::Integer(4u64.into()),
            Value::Bytes(schema_id.to_vec()),
        ),
        (
            Value::Integer(5u64.into()),
            Value::Bytes(metadata_hash.to_vec()),
        ),
    ]);
    let mut payload = Vec::new();
    ciborium::into_writer(&map, &mut payload).context("encode payload")?;
    let mut tx = Transaction {
        tx_version: TX_VERSION,
        chain_id: chain_id.to_vec(),
        msg_type: MsgType::AttestationCreate,
        sender: Address(*sender),
        nonce,
        fee: FEE_BUDGET,
        fee_tip: 0,
        gas_limit: GAS_LIMIT,
        payload,
        sig_alg_id: ALG,
        sig_key_version: SIG_KEY_VERSION,
        signature: vec![],
    };
    let fork_digest = pqc_types::ForkDigest::viper_research_1();
    let preimage = build_preimage(&fork_digest, &tx).context("preimage")?;
    tx.signature = ml_dsa_sign_with_seed(ALG, seed, &preimage)?;
    let raw = encode_tx(&tx).context("encode tx")?;
    let hash = compute_tx_hash(&raw);
    Ok((raw, hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [7u8; 32];

    #[test]
    fn sign_then_verify_roundtrip() {
        let pk = ml_dsa_public_key_from_seed(ALG, &SEED).unwrap();
        let sig = ml_dsa_sign_with_seed(ALG, &SEED, b"AGWS-RICORDI-v1\nabc").unwrap();
        let ok = MlDsaVerifier.verify(
            &PublicKey {
                alg_id: ALG,
                bytes: pk.clone(),
            },
            b"AGWS-RICORDI-v1\nabc",
            &Signature {
                alg_id: ALG,
                bytes: sig.clone(),
            },
        );
        assert!(ok.is_ok());
        let bad = MlDsaVerifier.verify(
            &PublicKey {
                alg_id: ALG,
                bytes: pk,
            },
            b"AGWS-RICORDI-v1\nabd",
            &Signature {
                alg_id: ALG,
                bytes: sig,
            },
        );
        assert!(bad.is_err());
    }

    #[test]
    fn keys_are_deterministic_from_seed() {
        let a = ml_dsa_public_key_from_seed(ALG, &SEED).unwrap();
        let b = ml_dsa_public_key_from_seed(ALG, &SEED).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn attestation_tx_is_deterministic_and_nonce_sensitive() {
        let chain = b"ricordi-test".to_vec();
        let pk = ml_dsa_public_key_from_seed(ALG, &SEED).unwrap();
        let sender = derive_address(&chain, ALG, &pk);
        let z = [0u8; 32];
        let (_, h1) = build_attestation(&chain, &sender, &SEED, 0, &z, &[1; 32], &z).unwrap();
        let (_, h2) = build_attestation(&chain, &sender, &SEED, 0, &z, &[1; 32], &z).unwrap();
        let (_, h3) = build_attestation(&chain, &sender, &SEED, 1, &z, &[1; 32], &z).unwrap();
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }
}
