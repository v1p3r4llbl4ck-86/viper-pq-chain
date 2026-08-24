// SPDX-License-Identifier: BUSL-1.1
//! Key-material CLI handlers — `pqcd keygen` + `pqcd keystore verify`.
//!
//! Extracted from `main.rs` 2026-05-10. Two operator-facing crypto
//! ops grouped together because both touch keystore artefacts:
//! `keygen` mints a fresh ML-DSA keystore, `keystore verify` parses
//! one with the production loader and reports per-entry summary.

use anyhow::{bail, Context, Result};

use crate::resolve_chain_id_flag;

pub fn cmd_keygen(args: &[String]) -> Result<()> {
    use pqcd::wallet::{default_keystore_path, parse_alg_flag, Keystore};
    use rand::RngCore;

    let mut seed_hex: Option<String> = None;
    let mut alg_name = "ml-dsa-65";
    let mut passphrase = String::new();
    let mut output_path: Option<String> = None;
    let mut chain_id_hex: Option<String> = None;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--seed" => {
                seed_hex = Some(args.get(i + 1).context("--seed requires a value")?.clone());
                i += 2;
            }
            "--alg" => {
                alg_name = args.get(i + 1).context("--alg requires a value")?.as_str();
                i += 2;
            }
            "--passphrase" => {
                passphrase = args
                    .get(i + 1)
                    .context("--passphrase requires a value")?
                    .clone();
                i += 2;
            }
            "--output" => {
                output_path = Some(args.get(i + 1).context("--output requires a path")?.clone());
                i += 2;
            }
            "--chain-id" => {
                chain_id_hex = Some(
                    args.get(i + 1)
                        .context("--chain-id requires a hex string")?
                        .clone(),
                );
                i += 2;
            }
            _ => bail!("unknown flag: {}", args[i]),
        }
    }

    if passphrase.is_empty() {
        if let Ok(p) = std::env::var("VIPER_PASSPHRASE") {
            passphrase = p;
        }
    }
    if passphrase.is_empty() {
        passphrase = rpassword::prompt_password("Keystore passphrase: ")
            .context("failed to read passphrase")?;
    }

    let chain_id = resolve_chain_id_flag(chain_id_hex)?;
    let alg_id = parse_alg_flag(alg_name)?;

    let mut seed = [0u8; 32];
    if let Some(hex) = seed_hex {
        let bytes = hex::decode(hex.trim()).context("--seed must be 64 hex chars")?;
        if bytes.len() != 32 {
            bail!("seed must be 32 bytes");
        }
        seed.copy_from_slice(&bytes);
    } else {
        rand::rng().fill_bytes(&mut seed);
    }
    let seed_out = hex::encode(seed);

    let ks = Keystore::create_from_seed(&chain_id, alg_id, &seed, &passphrase)?;

    let path = match output_path {
        Some(p) => std::path::PathBuf::from(p),
        None => default_keystore_path(&ks.address)?,
    };
    ks.save(&path)?;

    println!(
        "{}",
        serde_json::json!({
            "seed_hex":       seed_out,
            "public_key_hex": ks.public_key,
            "address_hex":    ks.address,
            "alg_id":         2,
            "keystore_path":  path.display().to_string()
        })
    );
    Ok(())
}
pub fn cmd_keystore_verify(args: &[String]) -> Result<()> {
    let path = args
        .get(3)
        .context("Usage: pqcd keystore verify <keystore.json>")?;
    let path_buf = std::path::PathBuf::from(path);
    let store = pqcd::keystore::Keystore::load_from_file(&path_buf)
        .with_context(|| format!("keystore parse failed: {path}"))?;

    let total_entries = store.len();
    let distinct = store.distinct_addresses();
    if total_entries == 0 {
        bail!("keystore at {path} loaded zero validator entries — refusing OK status");
    }

    println!("keystore verify: {path}");
    println!("  distinct validator addresses: {distinct}");
    println!("  total entries (sum across versions): {total_entries}");
    println!("  per-entry summary:");
    // Collect to a sorted Vec so output is deterministic across invocations
    // (HashMap iteration order is otherwise process-randomised).
    let mut rows: Vec<(String, &pqcd::keystore::KeystoreEntry)> = store
        .iter_entries()
        .map(|(addr, entry)| (hex::encode(addr), entry))
        .collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.key_version.cmp(&b.1.key_version)));
    for (addr_hex, entry) in rows {
        println!(
            "    address=0x{}  alg_id={}  key_version={}  pk.len={}  archival_sk={}",
            addr_hex,
            entry.sig_alg_id.as_u16(),
            entry.key_version,
            entry.public_key.len(),
            if entry.archival_sk.is_some() {
                "present"
            } else {
                "absent"
            },
        );
    }
    println!("OK");
    Ok(())
}
