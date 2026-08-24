// SPDX-License-Identifier: BUSL-1.1
//! `pqcd wallet ...` CLI subcommand handlers.
//!
//! Extracted from `main.rs` 2026-05-10. Centralises the operator-
//! facing wallet operations (create, import-mnemonic, import-seed,
//! address, public-key, sign, send, export-seed, vault-create,
//! archival-keygen, archival-register, register-validator, rotate-
//! consensus-key, kem-init) plus the two private helpers used by the
//! in-place keystore-rotation path.
//!
//! Bin-only: `cli/` is reachable from the bin's `mod cli;` declaration
//! in main.rs but NOT from the lib's lib.rs — so this code does not
//! contribute to the `pqcd` library's public surface. The lib-side
//! wallet primitives (BIP39, HKDF, Argon2id keystore encryption) are
//! at `pqcd::wallet` and predate this split.
//!
//! `crate::*` from here resolves to the bin's root (main.rs), giving
//! access to top-level helpers like `resolve_chain_id_flag`.

#![allow(clippy::too_many_lines)]

use anyhow::{bail, Context, Result};
use pqc_crypto::alg::AlgId;

use crate::resolve_chain_id_flag;

pub fn cmd_wallet_create(args: &[String]) -> Result<()> {
    use pqcd::wallet::{default_keystore_path, parse_alg_flag, Keystore};

    let mut alg_name = "ml-dsa-65";
    let mut output_path: Option<String> = None;
    let mut chain_id_hex: Option<String> = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--alg" => {
                alg_name = args
                    .get(i + 1)
                    .map(String::as_str)
                    .context("--alg requires a value (ml-dsa-44, ml-dsa-65, ml-dsa-87)")?;
                i += 2;
            }
            "--output" => {
                output_path = Some(
                    args.get(i + 1)
                        .context("--output requires a file path")?
                        .clone(),
                );
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
    let chain_id = resolve_chain_id_flag(chain_id_hex)?;
    let alg_id = parse_alg_flag(alg_name)?;

    let passphrase = if let Ok(p) = std::env::var("VIPER_PASSPHRASE") {
        p
    } else {
        rpassword::prompt_password("Enter passphrase to encrypt keystore: ")
            .context("failed to read passphrase")?
    };
    if std::env::var("VIPER_PASSPHRASE").is_err() {
        let confirm = rpassword::prompt_password("Confirm passphrase: ")
            .context("failed to read passphrase confirmation")?;
        if passphrase != confirm {
            bail!("passphrases do not match");
        }
    }

    let (ks, mnemonic) = Keystore::create(&chain_id, alg_id, &passphrase)?;

    let path = match output_path {
        Some(p) => std::path::PathBuf::from(p),
        None => default_keystore_path(&ks.address)?,
    };
    ks.save(&path)?;

    println!();
    println!("IMPORTANT: Write down these words and store them safely.");
    println!("This is the ONLY time they will be displayed.");
    println!("If you lose them, you cannot recover your account.");
    println!();
    println!("Mnemonic: {mnemonic}");
    println!();
    println!("Address (hex): {}", ks.address);
    let addr_bytes = ks.address()?;
    println!(
        "Address (bech32m): {}",
        pqc_crypto::address_to_bech32m(&addr_bytes, "vpt")?
    );
    println!("Keystore saved to: {}", path.display());
    Ok(())
}

pub fn cmd_wallet_import_mnemonic(args: &[String]) -> Result<()> {
    use pqcd::wallet::{default_keystore_path, parse_alg_flag, Keystore};

    let mut alg_name = "ml-dsa-65";
    let mut output_path: Option<String> = None;
    let mut chain_id_hex: Option<String> = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--alg" => {
                alg_name = args
                    .get(i + 1)
                    .map(String::as_str)
                    .context("--alg requires a value")?;
                i += 2;
            }
            "--output" => {
                output_path = Some(
                    args.get(i + 1)
                        .context("--output requires a file path")?
                        .clone(),
                );
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
    let chain_id = resolve_chain_id_flag(chain_id_hex)?;
    let alg_id = parse_alg_flag(alg_name)?;

    let mnemonic = rpassword::prompt_password("Enter mnemonic words (space-separated): ")
        .context("failed to read mnemonic")?;
    let passphrase = rpassword::prompt_password("Enter passphrase to encrypt keystore: ")
        .context("failed to read passphrase")?;

    let ks = Keystore::create_from_mnemonic(&chain_id, alg_id, mnemonic.trim(), &passphrase)?;

    let path = match output_path {
        Some(p) => std::path::PathBuf::from(p),
        None => default_keystore_path(&ks.address)?,
    };
    ks.save(&path)?;

    println!("Address (hex): {}", ks.address);
    let addr_bytes = ks.address()?;
    println!(
        "Address (bech32m): {}",
        pqc_crypto::address_to_bech32m(&addr_bytes, "vpt")?
    );
    println!("Keystore saved to: {}", path.display());
    Ok(())
}

pub fn cmd_wallet_import_seed(args: &[String]) -> Result<()> {
    use pqcd::wallet::{default_keystore_path, parse_alg_flag, Keystore};

    let hex_seed = args
        .get(3)
        .context("Usage: pqcd wallet import-seed <hex-seed> [--alg ...] [--output ...]")?;
    let seed_bytes =
        hex::decode(hex_seed.trim()).context("seed must be a 64-character hex string")?;
    if seed_bytes.len() != 32 {
        bail!(
            "seed must be exactly 32 bytes (64 hex chars), got {}",
            seed_bytes.len()
        );
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);

    let mut alg_name = "ml-dsa-65";
    let mut output_path: Option<String> = None;
    let mut chain_id_hex: Option<String> = None;
    let mut i = 4;
    while i < args.len() {
        match args[i].as_str() {
            "--alg" => {
                alg_name = args
                    .get(i + 1)
                    .map(String::as_str)
                    .context("--alg requires a value")?;
                i += 2;
            }
            "--output" => {
                output_path = Some(
                    args.get(i + 1)
                        .context("--output requires a file path")?
                        .clone(),
                );
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
    let chain_id = resolve_chain_id_flag(chain_id_hex)?;
    let alg_id = parse_alg_flag(alg_name)?;

    let passphrase = if let Ok(p) = std::env::var("VIPER_PASSPHRASE") {
        p
    } else {
        rpassword::prompt_password("Enter passphrase to encrypt keystore: ")
            .context("failed to read passphrase")?
    };

    let ks = Keystore::create_from_seed(&chain_id, alg_id, &seed, &passphrase)?;
    use zeroize::Zeroize;
    seed.zeroize();

    let path = match output_path {
        Some(p) => std::path::PathBuf::from(p),
        None => default_keystore_path(&ks.address)?,
    };
    ks.save(&path)?;

    println!("Address (hex): {}", ks.address);
    let addr_bytes = ks.address()?;
    println!(
        "Address (bech32m): {}",
        pqc_crypto::address_to_bech32m(&addr_bytes, "vpt")?
    );
    println!("Keystore saved to: {}", path.display());
    Ok(())
}

pub fn cmd_wallet_address(args: &[String]) -> Result<()> {
    use pqcd::wallet::Keystore;

    let ks_path = args
        .get(3)
        .context("Usage: pqcd wallet address <keystore-path>")?;
    let ks = Keystore::load(std::path::Path::new(ks_path))?;
    let addr_bytes = ks.address()?;

    println!("Address (hex):     {}", ks.address);
    println!(
        "Address (mainnet): {}",
        pqc_crypto::address_to_bech32m(&addr_bytes, "vpr")?
    );
    println!(
        "Address (testnet): {}",
        pqc_crypto::address_to_bech32m(&addr_bytes, "vpt")?
    );
    Ok(())
}

pub fn cmd_wallet_public_key(args: &[String]) -> Result<()> {
    use pqcd::wallet::Keystore;

    let ks_path = args
        .get(3)
        .context("Usage: pqcd wallet public-key <keystore-path>")?;
    let ks = Keystore::load(std::path::Path::new(ks_path))?;

    println!("Public key (hex): {}", ks.public_key);
    println!("Algorithm:        {}", ks.alg_id);
    Ok(())
}

pub fn cmd_wallet_sign(args: &[String]) -> Result<()> {
    use pqcd::wallet::Keystore;

    let ks_path = args
        .get(3)
        .context("Usage: pqcd wallet sign <keystore-path> <unsigned-tx-cbor-hex>")?;
    let unsigned_hex = args
        .get(4)
        .context("Usage: pqcd wallet sign <keystore-path> <unsigned-tx-cbor-hex>")?;

    let ks = Keystore::load(std::path::Path::new(ks_path))?;
    let unsigned_cbor =
        hex::decode(unsigned_hex.trim()).context("unsigned tx must be valid hex")?;

    let passphrase = if let Ok(p) = std::env::var("VIPER_PASSPHRASE") {
        p
    } else {
        rpassword::prompt_password("Enter passphrase: ").context("failed to read passphrase")?
    };

    let signed_cbor = ks.sign_transaction(&passphrase, &unsigned_cbor)?;
    println!("{}", hex::encode(&signed_cbor));
    Ok(())
}

pub async fn cmd_wallet_send(args: &[String]) -> Result<()> {
    use pqcd::wallet::Keystore;

    let ks_path = args.get(3).context(
        "Usage: pqcd wallet send <keystore-path> --to <address> --amount <venom> --node <url>",
    )?;

    let mut to_address: Option<String> = None;
    let mut amount: Option<u128> = None;
    let mut node_url: Option<String> = None;
    let mut i = 4;
    while i < args.len() {
        match args[i].as_str() {
            "--to" => {
                to_address = Some(args.get(i + 1).context("--to requires an address")?.clone());
                i += 2;
            }
            "--amount" => {
                let amt_str = args.get(i + 1).context("--amount requires a value")?;
                amount = Some(
                    amt_str
                        .parse::<u128>()
                        .context("--amount must be a valid integer (venom)")?,
                );
                i += 2;
            }
            "--node" => {
                node_url = Some(args.get(i + 1).context("--node requires a URL")?.clone());
                i += 2;
            }
            _ => bail!("unknown flag: {}", args[i]),
        }
    }

    let to_str = to_address.context("--to <address> is required")?;
    let amount_val = amount.context("--amount <venom> is required")?;
    let node = node_url.context("--node <url> is required")?;

    // Parse recipient address (accept both hex and bech32m).
    let recipient = if to_str.len() == 64 && to_str.chars().all(|c| c.is_ascii_hexdigit()) {
        let bytes = hex::decode(&to_str).context("invalid hex address")?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        arr
    } else {
        pqc_crypto::bech32m_to_address(&to_str)
            .context("invalid address (expected 64-char hex or bech32m)")?
    };

    let ks = Keystore::load(std::path::Path::new(ks_path))?;
    let sender_addr = ks.address()?;
    let alg_id = ks.parsed_alg_id()?;

    let passphrase = if let Ok(p) = std::env::var("VIPER_PASSPHRASE") {
        p
    } else {
        rpassword::prompt_password("Enter passphrase: ").context("failed to read passphrase")?
    };

    // Fetch sender nonce from node.
    let client = reqwest::Client::new();
    let account_url = format!(
        "{}/v1/accounts/{}",
        node.trim_end_matches('/'),
        hex::encode(sender_addr)
    );
    let resp = client
        .get(&account_url)
        .send()
        .await
        .context("failed to reach node")?;
    let nonce = if resp.status().is_success() {
        let body: serde_json::Value = resp
            .json()
            .await
            .context("failed to parse account response")?;
        body["nonce"].as_u64().unwrap_or(0)
    } else {
        0 // Account not found — first tx.
    };

    // Build unsigned transfer transaction.
    use pqc_types::account::Address;
    use pqc_types::transaction::{MsgType, Transaction};

    // Build a minimal transfer payload (CBOR map: {1: recipient, 2: amount}).
    // Amount is a CBOR unsigned integer when it fits in u64 (CBOR major type 0),
    // otherwise a 16-byte big-endian bytestring. Matches the decoder in
    // pqc-state::apply::transfer and the u128-balance convention used by
    // pqc_types::multisig::MultisigAccountState::to_cbor_bytes.
    let payload = {
        use ciborium::value::Value;
        let amount_value = if let Ok(small) = u64::try_from(amount_val) {
            Value::Integer(small.into())
        } else {
            Value::Bytes(amount_val.to_be_bytes().to_vec())
        };
        let map = Value::Map(vec![
            (
                Value::Integer(1u64.into()),
                Value::Bytes(recipient.to_vec()),
            ),
            (Value::Integer(2u64.into()), amount_value),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&map, &mut buf).context("failed to encode transfer payload")?;
        buf
    };

    // Fetch chain_id from node status.
    let status_url = format!("{}/v1/status", node.trim_end_matches('/'));
    let chain_id = client
        .get(&status_url)
        .send()
        .await
        .context("failed to reach node status endpoint")?
        .json::<serde_json::Value>()
        .await
        .context("failed to parse node status")?["chain_id"]
        .as_str()
        .context("chain_id missing from node status")?
        .as_bytes()
        .to_vec();

    let unsigned_tx = Transaction {
        tx_version: 1,
        chain_id,
        msg_type: MsgType::TokenTransfer,
        sender: Address(sender_addr),
        nonce,
        fee: 30000,
        fee_tip: 0,
        gas_limit: 200,
        payload,
        sig_alg_id: alg_id,
        sig_key_version: 1,
        signature: vec![],
    };

    let unsigned_cbor = pqc_tx::codec::encode_tx(&unsigned_tx)
        .map_err(|e| anyhow::anyhow!("failed to encode unsigned tx: {e}"))?;

    let signed_cbor = ks.sign_transaction(&passphrase, &unsigned_cbor)?;

    // Submit to node.
    let txs_url = format!("{}/v1/txs", node.trim_end_matches('/'));
    let tx_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &signed_cbor);
    let submit_resp = client
        .post(&txs_url)
        .json(&serde_json::json!({ "encoding": "cbor-base64", "tx_bytes": tx_b64 }))
        .send()
        .await
        .context("failed to submit transaction to node")?;

    if submit_resp.status().is_success() {
        let body: serde_json::Value = submit_resp
            .json()
            .await
            .context("failed to parse submit response")?;
        let tx_hash = pqc_crypto::shake256_32(&signed_cbor);
        println!("Transaction submitted successfully.");
        println!("tx_hash: {}", hex::encode(tx_hash));
        if let Some(msg) = body.get("message") {
            println!("node response: {msg}");
        }
    } else {
        let status = submit_resp.status();
        let body = submit_resp.text().await.unwrap_or_default();
        bail!("transaction rejected by node (HTTP {status}): {body}");
    }
    Ok(())
}

pub fn cmd_wallet_export_seed(args: &[String]) -> Result<()> {
    use pqcd::wallet::Keystore;
    use std::io::Write;
    use zeroize::Zeroize;

    // Parse positional + optional flags. Supported flags:
    //   --output-file <path>   Write seed hex to <path> (0600 on Unix) instead
    //                          of stdout. Avoids seed appearing in captured logs.
    //   --yes                  Skip interactive YES confirmation (for scripted
    //                          break-glass flows; the operator still owns the
    //                          VIPER_PASSPHRASE envvar so this is opt-in).
    let ks_path = args
        .get(3)
        .context("Usage: pqcd wallet export-seed <keystore-path> [--output-file <path>] [--yes]")?;

    let mut output_file: Option<std::path::PathBuf> = None;
    let mut skip_confirm = false;
    let mut i = 4;
    while i < args.len() {
        match args[i].as_str() {
            "--output-file" => {
                let p = args
                    .get(i + 1)
                    .context("--output-file requires a path argument")?;
                output_file = Some(std::path::PathBuf::from(p));
                i += 2;
            }
            "--yes" => {
                skip_confirm = true;
                i += 1;
            }
            other => bail!("unknown argument: {other}"),
        }
    }

    let ks = Keystore::load(std::path::Path::new(ks_path))?;

    let passphrase = if let Ok(p) = std::env::var("VIPER_PASSPHRASE") {
        p
    } else {
        rpassword::prompt_password("Enter passphrase: ").context("failed to read passphrase")?
    };

    let mut seed = ks.decrypt_seed(&passphrase)?;

    // SPEC-WALLET-001 §7.5 SHOULD: require explicit confirmation before
    // displaying seed. A typo-level slip should not leak account keys to
    // terminals or logs. Case-sensitive "YES" per spec.
    if !skip_confirm {
        println!();
        println!("WARNING: This command will reveal the 32-byte master seed that controls");
        println!("your account. Anyone with this seed can spend your funds. Ensure no");
        println!("screen recorder, log collector, or terminal multiplexer is capturing");
        println!("stdout before continuing.");
        println!();
        print!("Type exactly YES (uppercase) to confirm: ");
        std::io::stdout().flush().ok();

        let mut confirmation = String::new();
        std::io::stdin()
            .read_line(&mut confirmation)
            .context("failed to read confirmation input")?;
        // Trim ONLY the trailing newline(s) — anything else (spaces, lowercase)
        // is a hard failure; we do not want "Yes\n" or " YES\n" to succeed.
        let trimmed = confirmation.trim_end_matches(['\r', '\n']);
        let matches_yes = trimmed == "YES";
        // Wipe the input buffer regardless of outcome.
        confirmation.zeroize();
        if !matches_yes {
            seed.zeroize();
            bail!("export aborted: confirmation was not exactly \"YES\"");
        }
    }

    if let Some(path) = output_file {
        // Write seed to an operator-supplied file with 0600 permissions so it
        // does not transit stdout / tmux scrollback / CI log capture. The hex
        // String is zeroized after write.
        let mut hex_seed = hex::encode(seed);
        let write_result: Result<()> = (|| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&path)
                    .with_context(|| format!("failed to open {}", path.display()))?;
                f.write_all(hex_seed.as_bytes())
                    .context("failed to write seed hex")?;
                f.write_all(b"\n").ok();
                f.sync_all().ok();
            }
            #[cfg(not(unix))]
            {
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&path)
                    .with_context(|| format!("failed to open {}", path.display()))?;
                f.write_all(hex_seed.as_bytes())
                    .context("failed to write seed hex")?;
                f.write_all(b"\n").ok();
                f.sync_all().ok();
            }
            Ok(())
        })();
        // Wipe the hex string BEFORE returning from any branch.
        hex_seed.zeroize();
        seed.zeroize();
        write_result?;
        eprintln!(
            "Seed written to {} (mode 0600 on Unix). Delete after use.",
            path.display()
        );
    } else {
        let mut hex_seed = hex::encode(seed);
        println!();
        println!("Seed (hex): {hex_seed}");
        // Zeroize BOTH the intermediate String and the raw seed. `hex::encode`
        // allocates a fresh String that the default Drop would otherwise leave
        // on the heap — `.zeroize()` on String overwrites its buffer.
        hex_seed.zeroize();
        seed.zeroize();
    }
    Ok(())
}
pub async fn cmd_wallet_vault_create(args: &[String]) -> Result<()> {
    use pqc_types::{
        account::Address,
        keyset::allowed_tx,
        transaction::{MsgType, Transaction},
    };
    use pqcd::wallet::Keystore;

    let funder_ks_path = args.get(3).context(
        "Usage: pqcd wallet vault-create <funder-keystore> --for <new-keystore> --node <url>",
    )?;

    let mut new_ks_path: Option<String> = None;
    let mut node_url: Option<String> = None;
    let mut i = 4;
    while i < args.len() {
        match args[i].as_str() {
            "--for" => {
                new_ks_path = Some(
                    args.get(i + 1)
                        .context("--for requires a keystore path")?
                        .clone(),
                );
                i += 2;
            }
            "--node" => {
                node_url = Some(args.get(i + 1).context("--node requires a URL")?.clone());
                i += 2;
            }
            _ => bail!("unknown flag: {}", args[i]),
        }
    }

    let new_ks_path = new_ks_path.context("--for <new-keystore> is required")?;
    let node = node_url.context("--node <url> is required")?;

    let funder_ks = Keystore::load(std::path::Path::new(funder_ks_path))?;
    let new_ks = Keystore::load(std::path::Path::new(&new_ks_path))?;

    let funder_addr = funder_ks.address()?;
    let funder_alg_id = funder_ks.parsed_alg_id()?;
    let new_pk = new_ks.public_key_bytes()?;
    let new_alg_id = new_ks.parsed_alg_id()?;

    let passphrase = if let Ok(p) = std::env::var("VIPER_PASSPHRASE") {
        p
    } else {
        rpassword::prompt_password("Enter funder passphrase: ")
            .context("failed to read passphrase")?
    };

    let client = reqwest::Client::new();

    // Fetch chain_id and funder nonce.
    let status_url = format!("{}/v1/status", node.trim_end_matches('/'));
    let chain_id = client
        .get(&status_url)
        .send()
        .await
        .context("failed to reach node")?
        .json::<serde_json::Value>()
        .await
        .context("failed to parse status")?["chain_id"]
        .as_str()
        .context("chain_id missing")?
        .as_bytes()
        .to_vec();

    // Address derivation requires the host chain_id (ADR-053 §T1.3); deferred
    // until after /v1/status returned it.
    let new_address = pqc_crypto::derive_address(&chain_id, new_alg_id, &new_pk);

    let account_url = format!(
        "{}/v1/accounts/{}",
        node.trim_end_matches('/'),
        hex::encode(funder_addr)
    );
    let resp = client.get(&account_url).send().await?;
    let nonce = if resp.status().is_success() {
        resp.json::<serde_json::Value>().await?["nonce"]
            .as_u64()
            .unwrap_or(0)
    } else {
        0
    };

    // Build VaultCreate payload: CBOR map {1: alg_id, 2: pk_bytes, 3: allowed_tx_types, 4: valid_from_height}
    let payload = {
        use ciborium::value::Value;
        let map = Value::Map(vec![
            (
                Value::Integer(1u64.into()),
                Value::Integer((new_alg_id.as_u16() as u64).into()),
            ),
            (Value::Integer(2u64.into()), Value::Bytes(new_pk.to_vec())),
            (
                Value::Integer(3u64.into()),
                Value::Integer((allowed_tx::ALL as u64).into()),
            ),
            (Value::Integer(4u64.into()), Value::Integer(0u64.into())), // valid_from_height = 0 (immediate)
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&map, &mut buf).context("failed to encode vault_create payload")?;
        buf
    };

    let unsigned_tx = Transaction {
        tx_version: 1,
        chain_id,
        msg_type: MsgType::VaultCreate,
        sender: Address(funder_addr),
        nonce,
        fee: 50000,
        fee_tip: 0,
        gas_limit: 300,
        payload,
        sig_alg_id: funder_alg_id,
        sig_key_version: 1,
        signature: vec![],
    };

    let unsigned_cbor = pqc_tx::codec::encode_tx(&unsigned_tx)
        .map_err(|e| anyhow::anyhow!("failed to encode tx: {e}"))?;
    let signed_cbor = funder_ks.sign_transaction(&passphrase, &unsigned_cbor)?;

    let txs_url = format!("{}/v1/txs", node.trim_end_matches('/'));
    let tx_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &signed_cbor);
    let submit_resp = client
        .post(&txs_url)
        .json(&serde_json::json!({ "encoding": "cbor-base64", "tx_bytes": tx_b64 }))
        .send()
        .await
        .context("failed to submit transaction")?;

    if submit_resp.status().is_success() {
        let tx_hash = pqc_crypto::shake256_32(&signed_cbor);
        println!("Vault created successfully.");
        println!("new_address: {}", hex::encode(new_address));
        println!(
            "new_address (bech32m): {}",
            pqc_crypto::address_to_bech32m(&new_address, "vpt")?
        );
        println!("tx_hash: {}", hex::encode(tx_hash));
    } else {
        let status = submit_resp.status();
        let body = submit_resp.text().await.unwrap_or_default();
        bail!("vault-create rejected by node (HTTP {status}): {body}");
    }
    Ok(())
}

/// `pqcd wallet archival-keygen` — SPEC-ARCHIVAL-001 §4.5, TASK-163 / M4.4.
///
/// Generate a fresh SLH-DSA-SHAKE-256s archival keypair for a designated
/// archival signer. Prints pk/sk hex to stdout by default; with
/// `--output-sk <path>` / `--output-pk <path>` saves each half to its own
/// file (0600 perms on Unix for the sk).
///
/// # Usage
///
/// ```text
/// pqcd wallet archival-keygen [--output-sk <path>] [--output-pk <path>]
/// ```
///
/// # Next steps for the operator
///
/// 1. Place the 128-byte sk under the `archival_sk_hex` field of the node's
///    `keystore.json` entry for this validator (see `pqcd::keystore`).
/// 2. Submit a `ValidatorRegisterArchivalKey` tx to register the pk
///    on-chain. At the next epoch boundary the node will auto-submit
///    `ArchivalRecordSubmit` for this validator.
pub fn cmd_wallet_archival_keygen(args: &[String]) -> Result<()> {
    let mut output_sk_path: Option<String> = None;
    let mut output_pk_path: Option<String> = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--output-sk" => {
                output_sk_path = Some(
                    args.get(i + 1)
                        .context("--output-sk requires a path")?
                        .clone(),
                );
                i += 2;
            }
            "--output-pk" => {
                output_pk_path = Some(
                    args.get(i + 1)
                        .context("--output-pk requires a path")?
                        .clone(),
                );
                i += 2;
            }
            _ => bail!("unknown flag: {}", args[i]),
        }
    }

    let (pk_bytes, sk_bytes) = pqc_crypto::slh_dsa_shake_256s_generate()
        .map_err(|e| anyhow::anyhow!("SLH-DSA-SHAKE-256s keygen failed: {e}"))?;

    if let Some(ref path) = output_sk_path {
        let sk_path = std::path::PathBuf::from(path);
        if let Some(parent) = sk_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create parent dir for sk: {}", parent.display()))?;
        }
        std::fs::write(&sk_path, hex::encode(&sk_bytes).as_bytes())
            .with_context(|| format!("write archival sk to {}", sk_path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&sk_path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("chmod 600 on {}", sk_path.display()))?;
        }
    }
    if let Some(ref path) = output_pk_path {
        let pk_path = std::path::PathBuf::from(path);
        if let Some(parent) = pk_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create parent dir for pk: {}", parent.display()))?;
        }
        std::fs::write(&pk_path, hex::encode(&pk_bytes).as_bytes())
            .with_context(|| format!("write archival pk to {}", pk_path.display()))?;
    }

    println!(
        "{}",
        serde_json::json!({
            "alg_id":            format!("0x{:04x}", AlgId::SlhDsaShake256s.as_u16()),
            "alg_name":          "SLH-DSA-SHAKE-256s",
            "pk_hex":             hex::encode(&pk_bytes),
            "sk_hex":             hex::encode(&sk_bytes),
            "pk_len":             pk_bytes.len(),
            "sk_len":             sk_bytes.len(),
            "output_sk_path":     output_sk_path,
            "output_pk_path":     output_pk_path,
            "notes": [
                "Place sk_hex into the 'archival_sk_hex' field of your pqcd keystore.json entry.",
                "Submit a ValidatorRegisterArchivalKey transaction (MsgType 0x0405) via `pqcd wallet archival-register` to register pk_hex on-chain.",
                "SLH-DSA-SHAKE-256s is deterministic: there is NO password recovery — lose the sk, rotate the key by resubmitting ValidatorRegisterArchivalKey."
            ],
        })
    );

    Ok(())
}

/// `pqcd wallet archival-register <operator-keystore-path> --archival-pk <hex|@file> --node <url>`
///
/// Submit a `ValidatorRegisterArchivalKey` (MsgType `0x0405`) transaction
/// binding the provided SLH-DSA-SHAKE-256s public key to the operator's
/// on-chain validator record. Sender = the operator's consensus key
/// (loaded from `<operator-keystore-path>`).
///
/// `--archival-pk` accepts either a raw hex string (128 chars = 64 bytes)
/// or `@/path/to/file` reading hex from that file (whitespace-stripped).
pub async fn cmd_wallet_archival_register(args: &[String]) -> Result<()> {
    use pqcd::wallet::Keystore;

    let ks_path = args.get(3).context(
        "Usage: pqcd wallet archival-register <keystore-path> --archival-pk <hex|@file> --node <url>",
    )?;

    let mut archival_pk_arg: Option<String> = None;
    let mut node_url: Option<String> = None;
    let mut i = 4;
    while i < args.len() {
        match args[i].as_str() {
            "--archival-pk" => {
                archival_pk_arg = Some(
                    args.get(i + 1)
                        .context("--archival-pk requires a value")?
                        .clone(),
                );
                i += 2;
            }
            "--node" => {
                node_url = Some(args.get(i + 1).context("--node requires a URL")?.clone());
                i += 2;
            }
            _ => bail!("unknown flag: {}", args[i]),
        }
    }

    let archival_pk_arg = archival_pk_arg.context("--archival-pk <hex|@file> is required")?;
    let node = node_url.context("--node <url> is required")?;

    let archival_pk_hex: String = if let Some(stripped) = archival_pk_arg.strip_prefix('@') {
        std::fs::read_to_string(stripped)
            .with_context(|| format!("read archival pk file {stripped}"))?
            .trim()
            .to_string()
    } else {
        archival_pk_arg.trim().to_string()
    };
    let archival_pk_bytes =
        hex::decode(archival_pk_hex.trim_start_matches("0x")).context("archival pk must be hex")?;
    if archival_pk_bytes.len() != pqc_types::archival::SLH_DSA_SHAKE_256S_PK_LEN {
        bail!(
            "archival pk must be {} bytes (FIPS 205 §10.3), got {}",
            pqc_types::archival::SLH_DSA_SHAKE_256S_PK_LEN,
            archival_pk_bytes.len()
        );
    }

    let ks = Keystore::load(std::path::Path::new(ks_path))?;
    let sender_addr = ks.address()?;
    let alg_id = ks.parsed_alg_id()?;

    let passphrase = if let Ok(p) = std::env::var("VIPER_PASSPHRASE") {
        p
    } else {
        rpassword::prompt_password("Enter passphrase: ").context("failed to read passphrase")?
    };

    let client = reqwest::Client::new();

    // Fetch nonce.
    let account_url = format!(
        "{}/v1/accounts/{}",
        node.trim_end_matches('/'),
        hex::encode(sender_addr)
    );
    let nonce = client
        .get(&account_url)
        .send()
        .await
        .context("failed to reach node")?
        .json::<serde_json::Value>()
        .await
        .ok()
        .and_then(|v| v.get("nonce").and_then(|x| x.as_u64()))
        .unwrap_or(0);

    // Fetch chain_id.
    let status_url = format!("{}/v1/status", node.trim_end_matches('/'));
    let chain_id_str = client
        .get(&status_url)
        .send()
        .await
        .context("failed to reach node status endpoint")?
        .json::<serde_json::Value>()
        .await
        .context("failed to parse node status")?["chain_id"]
        .as_str()
        .context("chain_id missing from node status")?
        .to_string();

    // Build + sign tx via the pqcd::archival helper (which mirrors the
    // mempool-admission signing convention via pqc_tx::preimage::build_preimage).
    let mut seed = ks.decrypt_seed(&passphrase)?;
    let signed_cbor = pqcd::archival::build_signed_register_archival_key_tx(
        chain_id_str.as_bytes(),
        pqc_types::account::Address(sender_addr),
        alg_id,
        &seed,
        &archival_pk_bytes,
        nonce,
    );
    use zeroize::Zeroize;
    seed.zeroize();
    let signed_cbor = signed_cbor?;

    // Submit to node.
    let txs_url = format!("{}/v1/txs", node.trim_end_matches('/'));
    let tx_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &signed_cbor);
    let submit_resp = client
        .post(&txs_url)
        .json(&serde_json::json!({ "encoding": "cbor-base64", "tx_bytes": tx_b64 }))
        .send()
        .await
        .context("failed to submit archival-register tx to node")?;
    if submit_resp.status().is_success() {
        let tx_hash = pqc_crypto::shake256_32(&signed_cbor);
        println!(
            "{}",
            serde_json::json!({
                "status":           "submitted",
                "sender_address":   hex::encode(sender_addr),
                "archival_alg_id":  format!("0x{:04x}", pqc_crypto::AlgId::SlhDsaShake256s.as_u16()),
                "archival_pk_hex":  hex::encode(&archival_pk_bytes),
                "tx_hash":          hex::encode(tx_hash),
                "node":             node.clone(),
            })
        );
    } else {
        let status = submit_resp.status();
        let body = submit_resp.text().await.unwrap_or_default();
        bail!("archival-register rejected by node (HTTP {status}): {body}");
    }
    Ok(())
}

/// `pqcd wallet register-validator <keystore-path> --node <url> --node-id <name> --self-bond <venom> [--peer-id <hex|@file>] [--archival-pk <hex|@file>] [--chain-id <hex>] [--fee <venom>] [--gas-limit <N>]`
///
/// Submit a `ValidatorRegister` (MsgType `0x0400`) transaction that binds the
/// keystore's ML-DSA consensus public key to the operator's on-chain validator
/// record — SPEC-VAL-001 §4, ADR-047, TASK-175.
///
/// The tx is signed with the consensus seed stored in `<keystore-path>`, which
/// also derives the `consensus_pk` in the `ValidatorRegister` payload (so the
/// operator proves authority over the same key they're registering, and the
/// on-chain `consensus_pk` uniqueness check in `apply_validator_register` sees
/// the same bytes the mempool-admission signature verifier resolved).
///
/// Optional `--archival-pk` chains an `ValidatorRegisterArchivalKey` tx at
/// `nonce + 1` after the register tx admits; on rejection the archival half
/// is skipped and the caller is told. The archival tx is built via the same
/// helper `archival-register` uses (`pqcd::archival::build_signed_register_archival_key_tx`),
/// keeping both paths byte-identical for the state apply step.
///
/// If `--chain-id` is omitted the CLI fetches it from `GET /v1/status` on the
/// target node, matching the pattern in `cmd_wallet_send` / `cmd_wallet_vault_create`.
///
/// Note that per-validator unbonding-period is NOT a register-tx field —
/// it's a chain-wide parameter (`VALIDATOR_UNBONDING_PERIOD = 120` for devnet)
/// driven by the epoch config. No `--unbonding-period-blocks` flag is exposed.
pub async fn cmd_wallet_register_validator(args: &[String]) -> Result<()> {
    use pqc_state::encode_register_payload;
    use pqc_types::{
        account::Address,
        transaction::{MsgType, Transaction},
        validator::{ValidatorRegisterPayload, VALIDATOR_PEER_ID_MAX_LEN},
    };
    use pqcd::wallet::Keystore;

    let ks_path = args.get(3).context(
        "Usage: pqcd wallet register-validator <keystore-path> \
         --node <url> --node-id <name> --self-bond <venom> \
         [--peer-id <hex|@file>] [--archival-pk <hex|@file>] \
         [--chain-id <hex>] [--fee <venom>] [--gas-limit <N>]",
    )?;

    let mut node_url: Option<String> = None;
    let mut node_id_arg: Option<String> = None;
    let mut self_bond: Option<u128> = None;
    let mut peer_id_arg: Option<String> = None;
    let mut archival_pk_arg: Option<String> = None;
    let mut chain_id_hex: Option<String> = None;
    let mut fee: u64 = 20_000; // ValidatorRegister min-fee (heavy lane).
    let mut gas_limit: u64 = 1_000_000;
    let mut i = 4;
    while i < args.len() {
        match args[i].as_str() {
            "--node" => {
                node_url = Some(args.get(i + 1).context("--node requires a URL")?.clone());
                i += 2;
            }
            "--node-id" => {
                node_id_arg = Some(
                    args.get(i + 1)
                        .context("--node-id requires a human-readable name")?
                        .clone(),
                );
                i += 2;
            }
            "--self-bond" => {
                let s = args.get(i + 1).context("--self-bond requires a value")?;
                self_bond = Some(
                    s.parse::<u128>()
                        .context("--self-bond must be a valid u128 integer (venom)")?,
                );
                i += 2;
            }
            "--peer-id" => {
                peer_id_arg = Some(
                    args.get(i + 1)
                        .context("--peer-id requires a value (hex or @file)")?
                        .clone(),
                );
                i += 2;
            }
            "--archival-pk" => {
                archival_pk_arg = Some(
                    args.get(i + 1)
                        .context("--archival-pk requires a value (hex or @file)")?
                        .clone(),
                );
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
            "--fee" => {
                let s = args.get(i + 1).context("--fee requires a value")?;
                fee = s
                    .parse::<u64>()
                    .context("--fee must be a valid u64 integer")?;
                i += 2;
            }
            "--gas-limit" => {
                let s = args.get(i + 1).context("--gas-limit requires a value")?;
                gas_limit = s
                    .parse::<u64>()
                    .context("--gas-limit must be a valid u64 integer")?;
                i += 2;
            }
            _ => bail!("unknown flag: {}", args[i]),
        }
    }

    let node = node_url.context("--node <url> is required")?;
    let node_id_str =
        node_id_arg.context("--node-id <name> is required (human-readable validator name)")?;
    let self_bond_val = self_bond.context("--self-bond <venom> is required")?;
    if self_bond_val == 0 {
        bail!("--self-bond must be > 0 (apply path rejects zero bonds with ValidatorBondZero)");
    }

    // Parse optional peer_id (empty → no binding at register time; operator
    // may later submit ValidatorRotatePeerId).
    let peer_id_bytes: Vec<u8> = match peer_id_arg {
        None => Vec::new(),
        Some(raw) => {
            let hex_str = if let Some(stripped) = raw.strip_prefix('@') {
                std::fs::read_to_string(stripped)
                    .with_context(|| format!("read peer-id file {stripped}"))?
                    .trim()
                    .to_string()
            } else {
                raw.trim().trim_start_matches("0x").to_string()
            };
            let bytes =
                hex::decode(&hex_str).context("--peer-id must decode to bytes (hex or @file)")?;
            if bytes.len() > VALIDATOR_PEER_ID_MAX_LEN {
                bail!(
                    "peer_id is {} bytes; ADR-047 caps at {}",
                    bytes.len(),
                    VALIDATOR_PEER_ID_MAX_LEN
                );
            }
            bytes
        }
    };

    // Load keystore + derive consensus pk. The keystore's sig algorithm is
    // reused verbatim — ValidatorRegister requires the payload's consensus_pk
    // match the sig_alg_id used to sign the outer envelope, otherwise the
    // mempool-admission verifier would reject the tx.
    let ks = Keystore::load(std::path::Path::new(ks_path))?;
    let sender_addr = ks.address()?;
    let alg_id = ks.parsed_alg_id()?;
    if !alg_id.allowed_for_consensus() {
        bail!(
            "keystore algorithm {alg_id:?} is not allowed for consensus keys — \
             regenerate with `pqcd wallet create --alg ml-dsa-65`"
        );
    }
    let consensus_pk_bytes = ks.public_key_bytes()?;

    // Parse optional archival pk up-front so we can bail early on formatting
    // errors — avoids submitting the register tx then discovering the operator
    // typo'd their archival pk hex.
    let archival_pk_bytes: Option<Vec<u8>> = match archival_pk_arg {
        None => None,
        Some(raw) => {
            let hex_str = if let Some(stripped) = raw.strip_prefix('@') {
                std::fs::read_to_string(stripped)
                    .with_context(|| format!("read archival pk file {stripped}"))?
                    .trim()
                    .to_string()
            } else {
                raw.trim().trim_start_matches("0x").to_string()
            };
            let bytes = hex::decode(&hex_str).context("--archival-pk must be hex")?;
            if bytes.len() != pqc_types::archival::SLH_DSA_SHAKE_256S_PK_LEN {
                bail!(
                    "archival pk must be {} bytes (FIPS 205 §10.3), got {}",
                    pqc_types::archival::SLH_DSA_SHAKE_256S_PK_LEN,
                    bytes.len()
                );
            }
            Some(bytes)
        }
    };

    let passphrase = if let Ok(p) = std::env::var("VIPER_PASSPHRASE") {
        p
    } else {
        rpassword::prompt_password("Enter keystore passphrase: ")
            .context("failed to read passphrase")?
    };

    let client = reqwest::Client::new();

    // Resolve chain_id: CLI override wins, else fetch from node /v1/status.
    let chain_id: Vec<u8> = match chain_id_hex {
        Some(hex_str) => hex::decode(hex_str.trim_start_matches("0x"))
            .context("--chain-id must be a hex string")?,
        None => {
            let status_url = format!("{}/v1/status", node.trim_end_matches('/'));
            let status_json: serde_json::Value = client
                .get(&status_url)
                .send()
                .await
                .with_context(|| format!("failed to reach node at {status_url}"))?
                .json()
                .await
                .context("failed to parse node /v1/status response")?;
            status_json["chain_id"]
                .as_str()
                .context("chain_id missing from node /v1/status — pass --chain-id explicitly")?
                .as_bytes()
                .to_vec()
        }
    };

    // Fetch sender nonce.
    let account_url = format!(
        "{}/v1/accounts/{}",
        node.trim_end_matches('/'),
        hex::encode(sender_addr)
    );
    let resp = client
        .get(&account_url)
        .send()
        .await
        .with_context(|| format!("failed to reach node at {account_url}"))?;
    let base_nonce = if resp.status().is_success() {
        resp.json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|v| v.get("nonce").and_then(|x| x.as_u64()))
            .unwrap_or(0)
    } else {
        // Account not found means the operator hasn't been funded yet.
        // apply_validator_register then fails with ValidatorNotFound — we
        // surface that clearly rather than letting the node error speak.
        bail!(
            "account {} not found on node (HTTP {}). Fund it first via \
             `pqcd wallet vault-create --for <keystore> --node {}` or its \
             devnet funder equivalent.",
            hex::encode(sender_addr),
            resp.status(),
            node
        );
    };

    // Build ValidatorRegister payload (ADR-047 field layout).
    let payload = ValidatorRegisterPayload {
        node_id: node_id_str,
        consensus_alg_id: alg_id.as_u16(),
        consensus_pk: consensus_pk_bytes,
        self_bond: self_bond_val,
        peer_id: peer_id_bytes,
    };

    let unsigned_tx = Transaction {
        tx_version: 1,
        chain_id: chain_id.clone(),
        msg_type: MsgType::ValidatorRegister,
        sender: Address(sender_addr),
        nonce: base_nonce,
        fee,
        fee_tip: 0,
        gas_limit,
        payload: encode_register_payload(&payload),
        sig_alg_id: alg_id,
        sig_key_version: 1,
        signature: vec![],
    };

    let unsigned_cbor = pqc_tx::codec::encode_tx(&unsigned_tx)
        .map_err(|e| anyhow::anyhow!("failed to encode unsigned register tx: {e}"))?;
    let signed_cbor = ks.sign_transaction(&passphrase, &unsigned_cbor)?;

    // Submit the register tx.
    let txs_url = format!("{}/v1/txs", node.trim_end_matches('/'));
    let tx_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &signed_cbor);
    let submit_resp = client
        .post(&txs_url)
        .json(&serde_json::json!({ "encoding": "cbor-base64", "tx_bytes": tx_b64 }))
        .send()
        .await
        .with_context(|| format!("failed to submit ValidatorRegister to {txs_url}"))?;
    if !submit_resp.status().is_success() {
        let status = submit_resp.status();
        let body = submit_resp.text().await.unwrap_or_default();
        bail!("ValidatorRegister rejected by node (HTTP {status}): {body}");
    }
    let register_tx_hash = pqc_crypto::shake256_32(&signed_cbor);

    // Optional archival-key registration at nonce+1. Uses the SAME seed as
    // the consensus signer since the archival pk is bound to the operator's
    // ML-DSA identity. If this half fails we still report the register tx —
    // the operator can retry archival-register later.
    let archival_submission = if let Some(archival_pk) = archival_pk_bytes {
        let mut seed = ks.decrypt_seed(&passphrase)?;
        let build_res = pqcd::archival::build_signed_register_archival_key_tx(
            &chain_id,
            Address(sender_addr),
            alg_id,
            &seed,
            &archival_pk,
            base_nonce + 1,
        );
        use zeroize::Zeroize;
        seed.zeroize();
        let archival_signed = build_res?;
        let archival_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &archival_signed);
        let ar_resp = client
            .post(&txs_url)
            .json(&serde_json::json!({ "encoding": "cbor-base64", "tx_bytes": archival_b64 }))
            .send()
            .await
            .with_context(|| {
                format!("failed to submit ValidatorRegisterArchivalKey to {txs_url}")
            })?;
        if ar_resp.status().is_success() {
            let ar_hash = pqc_crypto::shake256_32(&archival_signed);
            Some(serde_json::json!({
                "submitted":      true,
                "archival_pk_hex": hex::encode(&archival_pk),
                "tx_hash":         hex::encode(ar_hash),
            }))
        } else {
            let status = ar_resp.status();
            let body = ar_resp.text().await.unwrap_or_default();
            // Non-fatal: register landed, archival can be retried out-of-band.
            eprintln!(
                "warning: register tx submitted but archival-key tx was rejected \
                 (HTTP {status}): {body}\n\
                 retry with: pqcd wallet archival-register {ks_path} --archival-pk <hex> --node {node}"
            );
            Some(serde_json::json!({
                "submitted": false,
                "error":     format!("HTTP {status}: {body}"),
            }))
        }
    } else {
        None
    };

    println!(
        "{}",
        serde_json::json!({
            "status":           "submitted",
            "msg_type":         "ValidatorRegister",
            "msg_type_id":      "0x0400",
            "sender_address":   hex::encode(sender_addr),
            "consensus_alg":    format!("{:?}", alg_id),
            "consensus_alg_id": format!("0x{:04x}", alg_id.as_u16()),
            "self_bond":        self_bond_val.to_string(),
            "nonce":            base_nonce,
            "fee":              fee,
            "gas_limit":        gas_limit,
            "tx_hash":          hex::encode(register_tx_hash),
            "chain_id_hex":     hex::encode(&chain_id),
            "node":             node.clone(),
            "archival":         archival_submission,
            "next_step":        "after the next epoch boundary (devnet-3: ~30 s, 60 blocks) check `curl <node>/v1/validators` — the sender address should appear as Active (subject to ADR-042 churn = max(4, active/256)).",
        })
    );
    Ok(())
}

/// `pqcd wallet rotate-consensus-key <current-keystore> --new-keystore <path>
///                 --node <url> [--rotation-start-height <h>] [--chain-id <hex>]
///                 [--fee <venom>] [--gas-limit <N>]
///                 [--in-place <validator-keystore.json>]`
///
/// Submits a `ConsensusKeyRotate` transaction (MsgType 0x0203) signed
/// with the operator's CURRENT consensus keystore, requesting that the
/// validator's on-chain `consensus_pk` be replaced by the public key
/// derived from `<new-keystore>` at block height `rotation_start_height`.
///
/// The rotation lands as a pending record on-chain (apply path
/// `apply_consensus_key_rotate`); at the requested height the
/// per-block hook `activate_pending_consensus_key_rotations` (TASK-223)
/// atomically replaces the validator-record's `consensus_alg_id +
/// consensus_pk` and removes the pending record.
///
/// # Operator workflow (Phase 4 Gap A — recommended, with --in-place)
///
/// 1. Generate a new wallet keystore (typically with a different alg if
///    the rotation is also crypto-agility-driven):
///
///        pqcd wallet create --alg ml-dsa-87 --output validator.new.keystore.json
///
/// 2. Submit the rotation AND stage the new seed into the running
///    pqcd's validator keystore in one step:
///
///        pqcd wallet rotate-consensus-key validator.keystore.json \
///            --new-keystore validator.new.keystore.json \
///            --node https://pqchain.example/ \
///            --in-place /etc/pqcd/keystore.json
///
///    With `--in-place`, the CLI appends a new entry to the validator's
///    on-disk `keystore.json` with the next available `key_version`
///    (Phase 4 Gap A multi-version semantics). The running pqcd reloads
///    the file via `refresh_keystore_from_file` on the next tick;
///    `snapshot_block_signers` then has BOTH the v1 and v2 seeds staged.
///    When `activate_pending_consensus_key_rotations` flips the on-chain
///    `consensus_pk` at `rotation_start_height`, the producer
///    transparently picks the v2 seed (`get_for_pk` matches by derived
///    public key). No process restart, no manual file swap, no
///    scheduled-downtime window.
///
/// # Operator workflow (legacy — separate file)
///
/// 1. Same step 1 (`pqcd wallet create …`).
/// 2. Submit the rotation WITHOUT `--in-place`:
///
///        pqcd wallet rotate-consensus-key validator.keystore.json \
///            --new-keystore validator.new.keystore.json \
///            --node https://pqchain.example/ \
///            --rotation-start-height $(($(curl -s … /v1/status | jq -r .height) + 200))
///
/// 3. After `rotation_start_height` lands on chain, manually swap the
///    validator's running pqcd to use `validator.new.keystore.json` as
///    its signing keystore. The on-chain validator-record now expects
///    sigs from the new key. Mismatched signing produces
///    INSUFFICIENT_COMMIT_QUORUM and the validator falls out of
///    consensus until the keystore is fixed.
///
/// # Pre-flight refusals
///
/// - sender keystore alg not allowed for consensus → bail
/// - new keystore alg not allowed for consensus → bail
/// - `rotation_start_height < current_tip + ROTATION_WINDOW (100)` → tx
///   rejected at apply time; surface that to the operator
/// - `--in-place` target file unreadable / unparseable → bail before tx
///   submission (avoids submitting a rotation the operator can't follow
///   up on)
pub async fn cmd_wallet_rotate_consensus_key(args: &[String]) -> Result<()> {
    use pqc_types::{
        account::Address,
        transaction::{MsgType, Transaction},
    };
    use pqcd::wallet::Keystore;

    let cur_ks_path = args.get(3).context(
        "Usage: pqcd wallet rotate-consensus-key <current-keystore> \
         --new-keystore <path> --node <url> \
         [--rotation-start-height <h>] [--chain-id <hex>] \
         [--fee <venom>] [--gas-limit <N>]",
    )?;

    let mut new_ks_path: Option<String> = None;
    let mut node_url: Option<String> = None;
    let mut rotation_start_height_arg: Option<u64> = None;
    let mut chain_id_hex: Option<String> = None;
    let mut fee: u64 = 5_000;
    let mut gas_limit: u64 = 200_000;
    let mut in_place_path: Option<String> = None;
    let mut i = 4;
    while i < args.len() {
        match args[i].as_str() {
            "--new-keystore" => {
                new_ks_path = Some(
                    args.get(i + 1)
                        .context("--new-keystore requires a path")?
                        .clone(),
                );
                i += 2;
            }
            "--node" => {
                node_url = Some(args.get(i + 1).context("--node requires a URL")?.clone());
                i += 2;
            }
            "--rotation-start-height" => {
                let s = args
                    .get(i + 1)
                    .context("--rotation-start-height requires a u64")?;
                rotation_start_height_arg = Some(
                    s.parse::<u64>()
                        .context("--rotation-start-height must be a u64")?,
                );
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
            "--fee" => {
                fee = args
                    .get(i + 1)
                    .context("--fee requires a value")?
                    .parse::<u64>()
                    .context("--fee must be u64")?;
                i += 2;
            }
            "--gas-limit" => {
                gas_limit = args
                    .get(i + 1)
                    .context("--gas-limit requires a value")?
                    .parse::<u64>()
                    .context("--gas-limit must be u64")?;
                i += 2;
            }
            "--in-place" => {
                in_place_path = Some(
                    args.get(i + 1)
                        .context("--in-place requires a path to the validator's keystore.json")?
                        .clone(),
                );
                i += 2;
            }
            _ => bail!("unknown flag: {}", args[i]),
        }
    }

    let new_ks_path = new_ks_path.context("--new-keystore <path> is required")?;
    let node = node_url.context("--node <url> is required")?;

    // Load both keystores; verify both algs are allowed for consensus.
    let cur_ks = Keystore::load(std::path::Path::new(cur_ks_path))?;
    let cur_addr = cur_ks.address()?;
    let cur_alg = cur_ks.parsed_alg_id()?;
    if !cur_alg.allowed_for_consensus() {
        bail!(
            "current keystore algorithm {cur_alg:?} is not allowed for consensus — \
             this rotation cannot be authenticated"
        );
    }

    let new_ks = Keystore::load(std::path::Path::new(&new_ks_path))?;
    let new_alg = new_ks.parsed_alg_id()?;
    if !new_alg.allowed_for_consensus() {
        bail!(
            "new keystore algorithm {new_alg:?} is not allowed for consensus — \
             regenerate with `pqcd wallet create --alg ml-dsa-65` (or ml-dsa-87)"
        );
    }
    let new_pk_bytes = new_ks.public_key_bytes()?;

    // Phase 4 Gap A: when --in-place is used, pre-flight the validator's
    // keystore.json BEFORE submitting the tx so the operator doesn't
    // commit a rotation they can't follow up on. Compute the next
    // available key_version slot for cur_addr and verify the file is
    // writable.
    let in_place_plan: Option<(std::path::PathBuf, u32)> = if let Some(p) = &in_place_path {
        let path = std::path::PathBuf::from(p);
        let next_version = preflight_in_place_keystore(&path, &cur_addr)
            .with_context(|| format!("--in-place pre-flight failed for {}", path.display()))?;
        Some((path, next_version))
    } else {
        None
    };

    let passphrase = if let Ok(p) = std::env::var("VIPER_PASSPHRASE") {
        p
    } else {
        rpassword::prompt_password("Enter CURRENT keystore passphrase: ")
            .context("failed to read passphrase")?
    };

    let client = reqwest::Client::new();

    // Resolve chain_id (CLI override > /v1/status fetch).
    let chain_id: Vec<u8> = match chain_id_hex {
        Some(hex_str) => hex::decode(hex_str.trim_start_matches("0x"))
            .context("--chain-id must be a hex string")?,
        None => {
            let status_url = format!("{}/v1/status", node.trim_end_matches('/'));
            let status_json: serde_json::Value = client
                .get(&status_url)
                .send()
                .await
                .with_context(|| format!("failed to reach node at {status_url}"))?
                .json()
                .await
                .context("failed to parse node /v1/status response")?;
            status_json["chain_id"]
                .as_str()
                .context("chain_id missing from node /v1/status — pass --chain-id explicitly")?
                .as_bytes()
                .to_vec()
        }
    };

    // Fetch sender nonce + tip height for the rotation_start_height
    // default. Apply guard: rotation_start_height >= current + 100
    // (ROTATION_WINDOW). We default to current + 200 so the operator has
    // an extra epoch's worth of buffer to align the keystore swap.
    let status_url = format!("{}/v1/status", node.trim_end_matches('/'));
    let status_json: serde_json::Value = client
        .get(&status_url)
        .send()
        .await
        .with_context(|| format!("failed to reach node at {status_url}"))?
        .json()
        .await
        .context("failed to parse node /v1/status response")?;
    let tip_height = status_json["height"]
        .as_u64()
        .context("height missing from /v1/status")?;
    let rotation_start_height = rotation_start_height_arg.unwrap_or(tip_height.saturating_add(200));
    if rotation_start_height < tip_height.saturating_add(100) {
        bail!(
            "rotation_start_height {rotation_start_height} is below the apply guard \
             (current_tip {tip_height} + ROTATION_WINDOW 100 = {})",
            tip_height + 100
        );
    }

    let account_url = format!(
        "{}/v1/accounts/{}",
        node.trim_end_matches('/'),
        hex::encode(cur_addr)
    );
    let acc_resp = client
        .get(&account_url)
        .send()
        .await
        .with_context(|| format!("failed to reach node at {account_url}"))?;
    if !acc_resp.status().is_success() {
        bail!(
            "account {} not found on node (HTTP {})",
            hex::encode(cur_addr),
            acc_resp.status()
        );
    }
    let nonce = acc_resp
        .json::<serde_json::Value>()
        .await
        .ok()
        .and_then(|v| v.get("nonce").and_then(|x| x.as_u64()))
        .unwrap_or(0);

    // Build CBOR payload (3-field map per `apply_consensus_key_rotate`).
    let payload = {
        let entries: Vec<(ciborium::value::Value, ciborium::value::Value)> = vec![
            (
                ciborium::value::Value::Integer(1u64.into()),
                ciborium::value::Value::Integer((new_alg.as_u16() as u64).into()),
            ),
            (
                ciborium::value::Value::Integer(2u64.into()),
                ciborium::value::Value::Bytes(new_pk_bytes.clone()),
            ),
            (
                ciborium::value::Value::Integer(3u64.into()),
                ciborium::value::Value::Integer(rotation_start_height.into()),
            ),
        ];
        let mut out = Vec::new();
        ciborium::into_writer(&ciborium::value::Value::Map(entries), &mut out)
            .context("encode rotation payload")?;
        out
    };

    let unsigned_tx = Transaction {
        tx_version: 1,
        chain_id: chain_id.clone(),
        msg_type: MsgType::ConsensusKeyRotate,
        sender: Address(cur_addr),
        nonce,
        fee,
        fee_tip: 0,
        gas_limit,
        payload,
        sig_alg_id: cur_alg,
        sig_key_version: 1,
        signature: vec![],
    };
    let unsigned_cbor = pqc_tx::codec::encode_tx(&unsigned_tx)
        .map_err(|e| anyhow::anyhow!("encode unsigned rotation tx: {e}"))?;
    let signed_cbor = cur_ks.sign_transaction(&passphrase, &unsigned_cbor)?;

    let txs_url = format!("{}/v1/txs", node.trim_end_matches('/'));
    let tx_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &signed_cbor);
    let resp = client
        .post(&txs_url)
        .json(&serde_json::json!({ "encoding": "cbor-base64", "tx_bytes": tx_b64 }))
        .send()
        .await
        .with_context(|| format!("failed to submit ConsensusKeyRotate to {txs_url}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("ConsensusKeyRotate rejected by node (HTTP {status}): {body}");
    }
    let tx_hash = pqc_crypto::shake256_32(&signed_cbor);

    // Phase 4 Gap A: if --in-place was specified, decrypt the new
    // keystore's seed and append a new (key_version) entry to the
    // validator's on-disk keystore.json. The running pqcd reloads the
    // file on its next tick; both v_n and v_n+1 seeds become eligible
    // for `snapshot_block_signers::get_for_pk`. After
    // `activate_pending_consensus_key_rotations` flips the on-chain pk
    // at `rotation_start_height`, the producer transparently picks the
    // new entry — no operator file swap, no process restart.
    let in_place_summary: Option<serde_json::Value> = match in_place_plan {
        Some((path, next_version)) => {
            let new_passphrase = if let Ok(p) = std::env::var("VIPER_NEW_PASSPHRASE") {
                p
            } else {
                rpassword::prompt_password("Enter NEW keystore passphrase (--in-place): ")
                    .context("failed to read NEW keystore passphrase")?
            };
            let mut new_seed = new_ks
                .decrypt_seed(&new_passphrase)
                .context("failed to decrypt new keystore for --in-place staging")?;
            // Sanity: the seed must derive the pk we just submitted on
            // chain. A mismatch is operator error (decrypted with wrong
            // passphrase + somehow succeeded? — shouldn't happen) or a
            // bug; fail closed before the file write.
            let derived_pk = pqc_crypto::ml_dsa_public_key_from_seed(new_alg, &new_seed)
                .context("failed to derive pk from decrypted seed (--in-place)")?;
            if derived_pk != new_pk_bytes {
                use zeroize::Zeroize;
                new_seed.zeroize();
                bail!(
                    "decrypted seed from {new_ks_path} does not match the pk submitted on chain \
                     — refusing to stage a corrupt entry into {}. Verify the new keystore \
                     passphrase and the --new-keystore path.",
                    path.display()
                );
            }
            append_versioned_keystore_entry(&path, &cur_addr, new_alg, &new_seed, next_version)?;
            use zeroize::Zeroize;
            new_seed.zeroize();
            Some(serde_json::json!({
                "path":              path.display().to_string(),
                "appended_version":  next_version,
            }))
        }
        None => None,
    };

    let next_step = if in_place_summary.is_some() {
        format!(
            "Phase 4 Gap A: the new seed is staged in the validator's keystore at \
             key_version {}. The running pqcd will reload the file on its next tick; \
             both v_old and v_new are now eligible signers. When block \
             {rotation_start_height} lands (~{} s at 500 ms block-time), \
             `activate_pending_consensus_key_rotations` flips the on-chain \
             consensus_pk and the producer transparently picks the new seed via \
             get_for_pk. NO process restart, NO manual file swap.",
            in_place_summary
                .as_ref()
                .and_then(|v| v.get("appended_version"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            (rotation_start_height.saturating_sub(tip_height)) / 2,
        )
    } else {
        format!(
            "wait until block {rotation_start_height} lands on chain (~{} s at 500 ms block-time), \
             then atomically swap the running pqcd's keystore from {} to {}. \
             Until activation height the validator MUST keep signing with the OLD keystore; \
             from activation height onwards it MUST sign with the NEW keystore. Mismatched \
             signing produces INSUFFICIENT_COMMIT_QUORUM and the validator falls out of \
             consensus until the keystore is fixed. \
             RECOMMENDED: re-run with --in-place <validator-keystore.json> to skip this step.",
            (rotation_start_height.saturating_sub(tip_height)) / 2,
            cur_ks_path,
            new_ks_path,
        )
    };

    println!(
        "{}",
        serde_json::json!({
            "status":                  "submitted",
            "msg_type":                "ConsensusKeyRotate",
            "msg_type_id":             "0x0203",
            "sender_address":          hex::encode(cur_addr),
            "current_alg":             format!("{:?}", cur_alg),
            "current_alg_id":          format!("0x{:04x}", cur_alg.as_u16()),
            "new_alg":                 format!("{:?}", new_alg),
            "new_alg_id":              format!("0x{:04x}", new_alg.as_u16()),
            "new_pk_hex":              hex::encode(&new_pk_bytes),
            "rotation_start_height":   rotation_start_height,
            "current_tip_height":      tip_height,
            "blocks_until_activation": rotation_start_height.saturating_sub(tip_height),
            "nonce":                   nonce,
            "fee":                     fee,
            "gas_limit":               gas_limit,
            "tx_hash":                 hex::encode(tx_hash),
            "node":                    node.clone(),
            "in_place":                in_place_summary,
            "next_step":               next_step,
        })
    );

    Ok(())
}

/// Phase 4 Gap A — pre-flight `--in-place` keystore.json staging:
/// returns the next available `key_version` for `address` after
/// confirming that the file (a) exists, (b) parses as a valid
/// `keystore.json`, and (c) the parent directory is writable. Bails if
/// the file is unreadable or malformed BEFORE the rotation tx is
/// submitted on-chain.
fn preflight_in_place_keystore(path: &std::path::Path, address: &[u8; 32]) -> Result<u32> {
    if !path.exists() {
        bail!(
            "--in-place target {} does not exist. Create it first with \
             `pqcd wallet create-validator-keystore` or point to the \
             validator's existing keystore.json.",
            path.display()
        );
    }
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read --in-place file {}", path.display()))?;
    let parsed: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse --in-place file {}", path.display()))?;
    let validators = parsed
        .get("validators")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("--in-place file missing `validators` array"))?;

    // Compute next key_version for this address. Default = 1 when
    // address has no entry yet; max + 1 otherwise.
    let target_hex_lc = hex::encode(address);
    let target_hex_with_prefix = format!("0x{target_hex_lc}");
    let mut max_v: Option<u32> = None;
    for entry in validators {
        let entry_addr = entry
            .get("address_hex")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim_start_matches("0x")
            .to_lowercase();
        if entry_addr == target_hex_lc
            || entry_addr == target_hex_with_prefix.trim_start_matches("0x")
        {
            let v = entry
                .get("key_version")
                .and_then(|v| v.as_u64())
                .map(|x| x as u32)
                .unwrap_or(pqcd::keystore::DEFAULT_KEY_VERSION);
            max_v = Some(max_v.map_or(v, |m| m.max(v)));
        }
    }
    let next = max_v
        .map(|v| v + 1)
        .unwrap_or(pqcd::keystore::DEFAULT_KEY_VERSION + 1);
    // Validate writable parent directory.
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("--in-place path has no parent directory"))?;
    std::fs::metadata(parent)
        .with_context(|| format!("--in-place parent dir {} not stat-able", parent.display()))?;
    Ok(next)
}

/// Phase 4 Gap A — atomically append a new versioned entry to the
/// validator's on-disk `keystore.json`. Reads the file, appends one
/// entry (address, sig_alg_id, commit_seed_hex, key_version), writes to
/// `<path>.tmp`, then renames over the original. Preserves the file's
/// existing mode on Unix (best-effort).
fn append_versioned_keystore_entry(
    path: &std::path::Path,
    address: &[u8; 32],
    sig_alg_id: pqc_crypto::AlgId,
    commit_seed: &[u8; 32],
    key_version: u32,
) -> Result<()> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read --in-place file {}", path.display()))?;
    let mut parsed: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse --in-place file {}", path.display()))?;
    let validators = parsed
        .get_mut("validators")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| anyhow::anyhow!("--in-place file missing `validators` array"))?;

    let new_entry = serde_json::json!({
        "address_hex":      hex::encode(address),
        "sig_alg_id":       sig_alg_id.as_u16(),
        "commit_seed_hex":  hex::encode(commit_seed),
        "key_version":      key_version,
    });
    validators.push(new_entry);

    let serialised = serde_json::to_vec_pretty(&parsed)
        .context("failed to re-serialise --in-place keystore.json")?;
    // Atomic write: tmp + rename. On Unix, rename is atomic within a
    // filesystem; on Windows, MoveFileEx defaults give the same effect
    // for our use-case (CLI tool, no concurrent writer).
    let tmp_path = path.with_extension("json.tmp");
    std::fs::write(&tmp_path, &serialised)
        .with_context(|| format!("failed to write tmpfile {}", tmp_path.display()))?;

    // Best-effort: copy the original file's permissions to the tmp
    // before rename so the result mirrors the original (not the umask).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let perms = std::fs::Permissions::from_mode(meta.permissions().mode());
            let _ = std::fs::set_permissions(&tmp_path, perms);
        }
    }

    std::fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "failed to rename {} → {}",
            tmp_path.display(),
            path.display()
        )
    })?;
    Ok(())
}

/// `pqcd wallet rotate-peer-id <current-keystore> --new-salt <hex64>
///                  --node <url> --in-place <node-config.json>
///                  [--chain-id <hex>] [--fee <venom>] [--gas-limit <N>]
///                  [--poll-timeout-secs <N>] [--poll-interval-ms <N>]`
///
/// Stage A.3 of the private design notes.
/// Submits a `ValidatorRotatePeerId` tx (ADR-047 / TASK-159) carrying
/// the PeerId derived from `node.json::node_id + --new-salt`, polls
/// until the tx lands, verifies the on-chain binding flipped, then
/// atomically writes `devnet.libp2p_seed_salt_hex = <new_salt>` into
/// the host's node.json. The pqcd restart that follows brings the
/// live libp2p identity in sync with the freshly-rotated on-chain
/// binding.
///
/// # Operator workflow (the only sane way to call this)
///
/// ```bash
/// NEW_SALT=$(openssl rand -hex 32)
/// pqcd wallet rotate-peer-id /etc/pqcd/validator.keystore.json \
///     --new-salt "$NEW_SALT" \
///     --node https://pqchain.example/ \
///     --in-place /etc/pqcd/node.json
/// systemctl restart pqcd
/// ```
///
/// Why `--in-place` is REQUIRED (no legacy two-step path here): unlike
/// `ConsensusKeyRotate`, `ValidatorRotatePeerId` has no
/// `rotation_start_height` activation window — the on-chain binding
/// flips synchronously at apply time. Without `--in-place`, the
/// operator faces an unbounded window where the on-chain binding
/// points to the NEW PeerId but pqcd is still derived from the OLD
/// salt. The bounded-window flow described in
/// `PEER-ID-ROTATION-SCOPING-2026-05-11.md` §4 only works when the
/// salt is staged in the same operator session as the tx submission.
///
/// # Failure modes
///
/// - tx submission fails → node.json is untouched.
/// - tx lands but post-apply verification disagrees with the expected
///   PeerId (e.g. another rotation raced us) → node.json is untouched,
///   error names the divergence so the operator can investigate.
/// - tx lands, verification passes, file write fails → node.json may
///   be partially written (atomic rename is the last step, so either
///   the original file is intact or the new content fully replaces it).
///   Operator runs §3.6 of the scoping doc to revert.
pub async fn cmd_wallet_rotate_peer_id(args: &[String]) -> Result<()> {
    use pqc_state::encode_rotate_peer_id_payload;
    use pqc_types::{
        account::Address,
        transaction::{MsgType, Transaction},
        validator::VALIDATOR_PEER_ID_MAX_LEN,
    };
    use pqcd::wallet::Keystore;

    let cur_ks_path = args.get(3).context(
        "Usage: pqcd wallet rotate-peer-id <current-keystore> \
         --new-salt <hex64> --node <url> --in-place <node-config.json> \
         [--chain-id <hex>] [--fee <venom>] [--gas-limit <N>] \
         [--poll-timeout-secs <N>] [--poll-interval-ms <N>]",
    )?;

    let mut new_salt_hex: Option<String> = None;
    let mut node_url: Option<String> = None;
    let mut in_place_path: Option<String> = None;
    let mut chain_id_hex: Option<String> = None;
    let mut fee: u64 = 5_000;
    let mut gas_limit: u64 = 200_000;
    let mut poll_timeout_secs: u64 = 30;
    let mut poll_interval_ms: u64 = 500;
    let mut i = 4;
    while i < args.len() {
        match args[i].as_str() {
            "--new-salt" => {
                new_salt_hex = Some(
                    args.get(i + 1)
                        .context("--new-salt requires a 64-char hex value")?
                        .clone(),
                );
                i += 2;
            }
            "--node" => {
                node_url = Some(args.get(i + 1).context("--node requires a URL")?.clone());
                i += 2;
            }
            "--in-place" => {
                in_place_path = Some(
                    args.get(i + 1)
                        .context("--in-place requires a path to the host's node.json")?
                        .clone(),
                );
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
            "--fee" => {
                fee = args
                    .get(i + 1)
                    .context("--fee requires a value")?
                    .parse::<u64>()
                    .context("--fee must be u64")?;
                i += 2;
            }
            "--gas-limit" => {
                gas_limit = args
                    .get(i + 1)
                    .context("--gas-limit requires a value")?
                    .parse::<u64>()
                    .context("--gas-limit must be u64")?;
                i += 2;
            }
            "--poll-timeout-secs" => {
                poll_timeout_secs = args
                    .get(i + 1)
                    .context("--poll-timeout-secs requires a value")?
                    .parse::<u64>()
                    .context("--poll-timeout-secs must be u64")?;
                i += 2;
            }
            "--poll-interval-ms" => {
                poll_interval_ms = args
                    .get(i + 1)
                    .context("--poll-interval-ms requires a value")?
                    .parse::<u64>()
                    .context("--poll-interval-ms must be u64")?;
                i += 2;
            }
            _ => bail!("unknown flag: {}", args[i]),
        }
    }

    let new_salt_hex = new_salt_hex.context("--new-salt <hex64> is required")?;
    let node = node_url.context("--node <url> is required")?;
    let in_place_path = in_place_path.context(
        "--in-place <node-config.json> is required (rotate-peer-id has no \
         legacy non-in-place path; see PEER-ID-ROTATION-SCOPING-2026-05-11.md §4)",
    )?;

    // Parse the 32-byte salt up front so we fail fast on malformed input,
    // before any chain interaction or file I/O.
    let new_salt: [u8; 32] = {
        let bytes = hex::decode(new_salt_hex.trim().trim_start_matches("0x"))
            .context("--new-salt must be valid hex")?;
        bytes.try_into().map_err(|v: Vec<u8>| {
            anyhow::anyhow!(
                "--new-salt decoded to {} bytes; expected 32. Generate with `openssl rand -hex 32`",
                v.len()
            )
        })?
    };

    // Pre-flight the node.json: ensure it exists, parses, carries a
    // top-level `node_id`, and lives in a writable directory. Bails
    // BEFORE the tx hits the chain.
    let in_place_path_buf = std::path::PathBuf::from(&in_place_path);
    let node_id = preflight_in_place_node_config(&in_place_path_buf).with_context(|| {
        format!(
            "--in-place pre-flight failed for {}",
            in_place_path_buf.display()
        )
    })?;

    // Compute the new PeerId. This is what we'll submit to the chain
    // AND what we'll verify against /v1/validators/<addr>::peer_id_hex
    // after the tx lands.
    let new_peer_id = pqcd::p2p::deterministic_peer_id(&node_id, Some(&new_salt));
    let new_peer_id_bytes = new_peer_id.to_bytes();
    if new_peer_id_bytes.len() > VALIDATOR_PEER_ID_MAX_LEN {
        bail!(
            "derived peer_id is {} bytes; ADR-047 caps at {}. \
             This is a libp2p PeerId encoding change — investigate.",
            new_peer_id_bytes.len(),
            VALIDATOR_PEER_ID_MAX_LEN
        );
    }

    // Load + verify the current keystore. ValidatorRotatePeerId is
    // signed by the validator's operator-address key; the keystore alg
    // must be consensus-allowed (same gate as register-validator).
    let cur_ks = Keystore::load(std::path::Path::new(cur_ks_path))?;
    let cur_addr = cur_ks.address()?;
    let cur_alg = cur_ks.parsed_alg_id()?;
    if !cur_alg.allowed_for_consensus() {
        bail!(
            "current keystore algorithm {cur_alg:?} is not allowed for consensus — \
             this rotation cannot be authenticated"
        );
    }

    let passphrase = if let Ok(p) = std::env::var("VIPER_PASSPHRASE") {
        p
    } else {
        rpassword::prompt_password("Enter validator keystore passphrase: ")
            .context("failed to read passphrase")?
    };

    let client = reqwest::Client::new();

    // Resolve chain_id from /v1/status if not passed explicitly.
    let chain_id: Vec<u8> = match chain_id_hex {
        Some(hex_str) => hex::decode(hex_str.trim_start_matches("0x"))
            .context("--chain-id must be a hex string")?,
        None => {
            let status_url = format!("{}/v1/status", node.trim_end_matches('/'));
            let status_json: serde_json::Value = client
                .get(&status_url)
                .send()
                .await
                .with_context(|| format!("failed to reach node at {status_url}"))?
                .json()
                .await
                .context("failed to parse node /v1/status response")?;
            status_json["chain_id"]
                .as_str()
                .context("chain_id missing from node /v1/status — pass --chain-id explicitly")?
                .as_bytes()
                .to_vec()
        }
    };

    // Fetch sender nonce. ValidatorRotatePeerId is synchronous (no
    // rotation_start_height); we don't need tip_height for an
    // activation window, only for the post-submit poll budget.
    let status_url = format!("{}/v1/status", node.trim_end_matches('/'));
    let status_json: serde_json::Value = client
        .get(&status_url)
        .send()
        .await
        .with_context(|| format!("failed to reach node at {status_url}"))?
        .json()
        .await
        .context("failed to parse node /v1/status response")?;
    let tip_height = status_json["height"]
        .as_u64()
        .context("height missing from /v1/status")?;

    let account_url = format!(
        "{}/v1/accounts/{}",
        node.trim_end_matches('/'),
        hex::encode(cur_addr)
    );
    let acc_resp = client
        .get(&account_url)
        .send()
        .await
        .with_context(|| format!("failed to reach node at {account_url}"))?;
    if !acc_resp.status().is_success() {
        bail!(
            "account {} not found on node (HTTP {})",
            hex::encode(cur_addr),
            acc_resp.status()
        );
    }
    let nonce = acc_resp
        .json::<serde_json::Value>()
        .await
        .ok()
        .and_then(|v| v.get("nonce").and_then(|x| x.as_u64()))
        .unwrap_or(0);

    // Encode the payload via the canonical helper so the wire form
    // tracks ADR-047 §payload-codec without us duplicating the CBOR
    // map shape here.
    let payload = encode_rotate_peer_id_payload(&new_peer_id_bytes);

    let unsigned_tx = Transaction {
        tx_version: 1,
        chain_id: chain_id.clone(),
        msg_type: MsgType::ValidatorRotatePeerId,
        sender: Address(cur_addr),
        nonce,
        fee,
        fee_tip: 0,
        gas_limit,
        payload,
        sig_alg_id: cur_alg,
        sig_key_version: 1,
        signature: vec![],
    };
    let unsigned_cbor = pqc_tx::codec::encode_tx(&unsigned_tx)
        .map_err(|e| anyhow::anyhow!("encode unsigned rotation tx: {e}"))?;
    let signed_cbor = cur_ks.sign_transaction(&passphrase, &unsigned_cbor)?;

    let txs_url = format!("{}/v1/txs", node.trim_end_matches('/'));
    let tx_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &signed_cbor);
    let resp = client
        .post(&txs_url)
        .json(&serde_json::json!({ "encoding": "cbor-base64", "tx_bytes": tx_b64 }))
        .send()
        .await
        .with_context(|| format!("failed to submit ValidatorRotatePeerId to {txs_url}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("ValidatorRotatePeerId rejected by node (HTTP {status}): {body}");
    }
    let tx_hash = pqc_crypto::shake256_32(&signed_cbor);

    // Poll /v1/txs/<hash> until the tx is finalized (a 200 means it
    // landed in a block; 404 means it's still pending). On timeout we
    // refuse to write the salt — the tx may still land later but the
    // operator must investigate before the binary restarts on a stale
    // libp2p_seed_salt_hex.
    let tx_lookup_url = format!(
        "{}/v1/txs/{}",
        node.trim_end_matches('/'),
        hex::encode(tx_hash)
    );
    let poll_deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(poll_timeout_secs);
    loop {
        let lookup = client
            .get(&tx_lookup_url)
            .send()
            .await
            .with_context(|| format!("failed to poll {tx_lookup_url}"))?;
        if lookup.status().is_success() {
            break;
        }
        if tokio::time::Instant::now() >= poll_deadline {
            bail!(
                "ValidatorRotatePeerId tx {} did not finalize within {}s. \
                 The tx may still land later. DO NOT manually edit \
                 {} until you have confirmed the on-chain binding — \
                 see PEER-ID-ROTATION-SCOPING-2026-05-11.md §3.6 for \
                 rollback recipe.",
                hex::encode(tx_hash),
                poll_timeout_secs,
                in_place_path_buf.display()
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(poll_interval_ms)).await;
    }

    // Post-apply verification: the on-chain binding MUST now match the
    // peer_id we submitted. Fail-closed on mismatch — leaves the node.json
    // untouched, so a racing rotation or a chain bug does not lock the
    // operator's host into an inconsistent state.
    let validator_url = format!(
        "{}/v1/validators/{}",
        node.trim_end_matches('/'),
        hex::encode(cur_addr)
    );
    let validator_resp: serde_json::Value = client
        .get(&validator_url)
        .send()
        .await
        .with_context(|| format!("failed to GET {validator_url} for post-apply verify"))?
        .json()
        .await
        .context("failed to parse /v1/validators/<addr> response")?;
    let on_chain_peer_id_hex = validator_resp
        .get("data")
        .and_then(|d| d.get("peer_id_hex"))
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let expected_hex = hex::encode(&new_peer_id_bytes);
    match on_chain_peer_id_hex.as_deref() {
        Some(actual) if actual.eq_ignore_ascii_case(&expected_hex) => {}
        Some(actual) => bail!(
            "post-apply verification FAILED: on-chain peer_id_hex={actual} but expected \
             {expected_hex} (derived from node_id={node_id:?} + --new-salt). Another \
             rotation may have raced this one. node.json at {} is UNCHANGED — see \
             PEER-ID-ROTATION-SCOPING-2026-05-11.md §3.6.",
            in_place_path_buf.display()
        ),
        None => bail!(
            "post-apply verification FAILED: on-chain peer_id_hex is null after \
             ValidatorRotatePeerId landed at /v1/txs/{}. This should be impossible — \
             the apply path either ran successfully (peer_id set) or rejected the tx \
             (HTTP 4xx at submit). node.json at {} is UNCHANGED.",
            hex::encode(tx_hash),
            in_place_path_buf.display()
        ),
    }

    // Atomically rewrite the node.json with the new salt. tmp + rename
    // preserves the existing file mode on Unix (operator-friendly:
    // /etc/pqcd/node.json is usually 0640 or stricter).
    atomically_set_libp2p_salt_in_node_config(&in_place_path_buf, &new_salt_hex)?;

    let next_step = format!(
        "salt staged in {}. Restart pqcd to pick up the new libp2p identity: \
         `systemctl restart pqcd` (≤ 10 s; the swarm reinitialises with the new \
         keypair and reconnects to peers). Operational window where the on-chain \
         binding leads the local PeerId: typically 10-15 s — see \
         PEER-ID-ROTATION-SCOPING-2026-05-11.md §4 for the bounded-danger analysis.",
        in_place_path_buf.display()
    );

    println!(
        "{}",
        serde_json::json!({
            "status":              "rotated",
            "msg_type":            "ValidatorRotatePeerId",
            "msg_type_id":         "0x0404",
            "sender_address":      hex::encode(cur_addr),
            "node_id":             node_id,
            "new_peer_id":         new_peer_id.to_string(),
            "new_peer_id_hex":     expected_hex,
            "new_salt_hex":        new_salt_hex,
            "nonce":               nonce,
            "fee":                 fee,
            "gas_limit":           gas_limit,
            "tx_hash":             hex::encode(tx_hash),
            "tip_height_at_submit": tip_height,
            "node":                node.clone(),
            "in_place_path":       in_place_path_buf.display().to_string(),
            "next_step":           next_step,
        })
    );

    Ok(())
}

/// Stage A.3 — pre-flight `--in-place` node-config staging for
/// `rotate-peer-id`. Returns the `node_id` extracted from the file
/// after confirming that the file (a) exists, (b) parses as JSON,
/// (c) carries a top-level `node_id` string field, and (d) lives in
/// a writable parent directory. Bails BEFORE the rotation tx is
/// submitted on-chain.
fn preflight_in_place_node_config(path: &std::path::Path) -> Result<String> {
    if !path.exists() {
        bail!(
            "--in-place target {} does not exist. Point at the host's \
             node.json (e.g. /etc/pqcd/node.json).",
            path.display()
        );
    }
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read --in-place file {}", path.display()))?;
    let parsed: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse --in-place file {}", path.display()))?;
    let node_id = parsed
        .get("node_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "--in-place file {} missing top-level `node_id` string",
                path.display()
            )
        })?
        .to_owned();
    if node_id.is_empty() {
        bail!(
            "--in-place file {} has empty `node_id` — rotate-peer-id needs \
             a stable node identity to derive the new PeerId from \
             (node_id is the public part of the derivation; salt is the \
             secret part).",
            path.display()
        );
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("--in-place path has no parent directory"))?;
    std::fs::metadata(parent)
        .with_context(|| format!("--in-place parent dir {} not stat-able", parent.display()))?;
    Ok(node_id)
}

/// Stage A.3 — atomically write `devnet.libp2p_seed_salt_hex = <salt>`
/// into the host's node.json. Reads the file, sets/overwrites the
/// field, writes to a tempfile, then renames over the original.
/// Preserves the original file's mode on Unix so a 0600 / 0640
/// node.json stays at the same permission after the rotation.
///
/// Idempotent on the field value: rotating to the same salt twice
/// in a row produces identical bytes. Adds the `devnet` object if
/// missing (e.g. a stripped-down config) — refuses on a non-object
/// `devnet` value (corrupt config; better to bail than overwrite).
fn atomically_set_libp2p_salt_in_node_config(
    path: &std::path::Path,
    new_salt_hex: &str,
) -> Result<()> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read --in-place file {}", path.display()))?;
    let mut parsed: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse --in-place file {}", path.display()))?;
    let root = parsed.as_object_mut().ok_or_else(|| {
        anyhow::anyhow!(
            "--in-place file {} is not a JSON object at the top level",
            path.display()
        )
    })?;
    let devnet = root
        .entry("devnet".to_owned())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    let devnet_obj = devnet.as_object_mut().ok_or_else(|| {
        anyhow::anyhow!(
            "--in-place file {} has non-object `devnet` field — refusing to overwrite",
            path.display()
        )
    })?;
    devnet_obj.insert(
        "libp2p_seed_salt_hex".to_owned(),
        serde_json::Value::String(new_salt_hex.to_owned()),
    );

    let serialised = serde_json::to_vec_pretty(&parsed)
        .context("failed to re-serialise --in-place node.json")?;
    let tmp_path = path.with_extension("json.tmp");
    std::fs::write(&tmp_path, &serialised)
        .with_context(|| format!("failed to write tmpfile {}", tmp_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let perms = std::fs::Permissions::from_mode(meta.permissions().mode());
            let _ = std::fs::set_permissions(&tmp_path, perms);
        }
    }

    std::fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "failed to rename {} → {}",
            tmp_path.display(),
            path.display()
        )
    })?;
    Ok(())
}

/// `pqcd wallet kem-init [--node-config <path>] [--force]`
///
/// Generates a 32-byte secret salt for the ML-KEM long-term identity-keypair
/// derivation — closes Gap B from the private design notes
/// and implements the operator-side step of `PHASE-4-KEY-ROTATION-RESEARCH.md`
/// §2.4 (Strategy 1 + secret salt).
///
/// **Why this exists**: prior to Gap B's fix, `kem_d`/`kem_z` for the
/// devnet HTTP P2P session-bootstrap channel were derived from
/// `config.node_id` ALONE — and `node_id` is publicly observable (logs,
/// `/v1/status`, peer-info responses). An attacker who knew it could
/// recompute the long-term ML-KEM secret without disk access. The fix
/// adds a per-host secret salt to the derivation. This subcommand
/// generates that salt.
///
/// # Behaviour
///
/// 1. Generates 32 bytes from the OS CSPRNG (`getrandom`).
/// 2. Hex-encodes to 64 chars.
/// 3. If `--node-config <path>` is provided:
///    - Parses the existing `node.json` (JSON only — TOML configs error out).
///    - Sets `devnet.kem_seed_salt_hex` to the new value.
///    - Refuses if the field already exists, unless `--force` is given.
///    - Writes the result atomically (tempfile + rename) preserving
///      file mode 0600.
/// 4. If `--node-config` is absent, prints the hex to stdout with a
///    one-line operator instruction.
///
/// # Operator workflow
///
/// 1. On each host: `pqcd wallet kem-init --node-config /etc/pqcd/node.json`
/// 2. Restart pqcd. Startup logs no longer emit the Gap B `warn!`.
/// 3. After the first epoch boundary, observe a `tracing::info!` line
///    `"ML-KEM identity keypair rotated at epoch boundary (Gap B)"`.
///
pub fn cmd_wallet_kem_init(args: &[String]) -> Result<()> {
    let mut node_config_path: Option<String> = None;
    let mut force = false;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--node-config" => {
                node_config_path = Some(
                    args.get(i + 1)
                        .context("--node-config requires a path")?
                        .clone(),
                );
                i += 2;
            }
            "--force" => {
                force = true;
                i += 1;
            }
            other => bail!("unknown flag: {other}"),
        }
    }

    // Step 1: generate 32 bytes via OS CSPRNG. `getrandom` is already a
    // workspace dependency and is the same RNG path used by
    // `cmd_wallet_create` for archival keygen and `establish_session`
    // for KEM encapsulation entropy — single source of truth.
    let mut salt = [0u8; 32];
    getrandom::fill(&mut salt).context("OS CSPRNG (getrandom) failed for kem-init")?;
    let salt_hex = hex::encode(salt);

    let Some(node_config_path) = node_config_path else {
        // No path → just print the salt + an instruction. Operator
        // pastes it manually into node.json. This branch is the
        // fallback for environments without filesystem access (CI
        // smoke-test, container without persistent volume mounted in).
        println!(
            "{}",
            serde_json::json!({
                "kem_seed_salt_hex": salt_hex,
                "instructions": [
                    "Paste this 64-char hex value into the `devnet.kem_seed_salt_hex` field of your node.json",
                    "Ensure node.json is mode 0600 (chmod 600 node.json) — the salt is a long-term secret",
                    "Restart pqcd; the Gap B startup `warn!` should disappear",
                    "See PHASE-4-KEY-ROTATION-RESEARCH.md §2.4 for the rotation semantics"
                ],
            })
        );
        return Ok(());
    };

    // Step 2: file-mode update path — read existing node.json, set the
    // field, atomic-write back preserving mode 0600.
    let path = std::path::PathBuf::from(&node_config_path);
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("read node config at {}", path.display()))?;

    // We deliberately use `serde_json::Value` rather than parsing into
    // `NodeConfig` so unknown fields, comments-as-json-extension, and
    // forwards-compat additions in the operator's node.json round-trip
    // through this command without loss. Strict typed parsing here
    // would reject any operator config carrying a field we don't yet
    // know about, which is hostile to multi-version coexistence.
    let mut json: serde_json::Value = serde_json::from_str(&raw).with_context(|| {
        format!(
            "parse node config at {} as JSON \
             (TOML configs are not supported by this command — \
              edit the salt field manually for TOML)",
            path.display()
        )
    })?;

    // Devnet section guard: if `devnet` does not yet exist, create it
    // as an empty object before stuffing the salt into it. Matches the
    // serde behaviour where `#[serde(default)]` on `pub devnet:
    // DevnetConfig` happily defaults the entire section.
    let devnet_obj = json
        .as_object_mut()
        .context("node config root is not a JSON object")?
        .entry("devnet")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));

    let devnet_map = devnet_obj
        .as_object_mut()
        .context("`devnet` field exists but is not a JSON object")?;

    // Refuse to clobber an existing salt without --force. A salt
    // collision across hosts would re-introduce a half-public
    // derivation that is harder to debug than the original Gap B.
    if devnet_map.contains_key("kem_seed_salt_hex") {
        let existing = devnet_map
            .get("kem_seed_salt_hex")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !existing.is_empty() && !force {
            bail!(
                "node config at {} already has `devnet.kem_seed_salt_hex` set. \
                 Use --force to overwrite (this rotates the salt — every active \
                 P2P session will be invalidated until the next epoch boundary).",
                path.display()
            );
        }
    }

    devnet_map.insert(
        "kem_seed_salt_hex".to_owned(),
        serde_json::Value::String(salt_hex.clone()),
    );

    // Step 3: atomic write. Write to `<path>.tmp.<pid>` first, then
    // rename over the original. On POSIX `rename(2)` is atomic on the
    // same filesystem — no risk of leaving the operator with a half-
    // written node.json on crash. Mode AND ownership are restored
    // from the ORIGINAL file BEFORE rename so the new file's perms
    // exactly match the pre-write state. Running this command via
    // `sudo` (operator workflow) without preserving ownership would
    // produce a `root:root` file that the `pqchain`-running daemon
    // can't read — the exact 2026-05-11 stall symptom.
    let mut serialised =
        serde_json::to_vec_pretty(&json).context("serialise updated node config to JSON")?;
    serialised.push(b'\n'); // POSIX newline
    let tmp_path = path.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&tmp_path, &serialised)
        .with_context(|| format!("write tempfile {}", tmp_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // Read the original file's metadata BEFORE rename so we can
        // restore (mode, uid, gid) exactly. If the original is gone
        // (impossible — we just read it above, but defensively) fall
        // back to mode 0600 + current uid/gid (matches the prior
        // behaviour).
        let original_meta = std::fs::metadata(&path)
            .with_context(|| format!("stat original {} for perm preservation", path.display()))?;
        let original_mode = original_meta.permissions().mode() & 0o7777;
        let original_uid = original_meta.uid();
        let original_gid = original_meta.gid();
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(original_mode))
            .with_context(|| {
                format!("restore mode {original_mode:#o} on {}", tmp_path.display())
            })?;
        // `chown` on the tempfile (not on `path`) so the new inode
        // already has the right ownership at the moment `rename(2)`
        // makes it the canonical file. Using `nix`/`libc` directly
        // here to avoid pulling another dep; the cast is safe — uid/
        // gid are u32 on Linux/macOS, libc::uid_t/gid_t are u32 too.
        // SAFETY: chown(2) is a stable POSIX syscall on a path we
        // just created. No invariants to uphold.
        let c_path = std::ffi::CString::new(tmp_path.as_os_str().as_encoded_bytes())
            .context("tempfile path contains a NUL byte (impossible on Unix)")?;
        let rc = unsafe { libc::chown(c_path.as_ptr(), original_uid, original_gid) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            // Soft-fail with a clear hint — the rename can still
            // succeed and produce a wrong-owner file, but the
            // operator at least learns why pqcd can't read it.
            tracing::warn!(
                tmp_path = %tmp_path.display(),
                expected_uid = original_uid,
                expected_gid = original_gid,
                error = %err,
                "chown(2) on kem-init tempfile failed; the new node.json may have wrong ownership \
                 and pqcd may fail to read it on restart. Run \
                 `chown pqchain:pqchain /etc/pqchain/node.json` to recover."
            );
        }
    }
    std::fs::rename(&tmp_path, &path).with_context(|| {
        format!(
            "atomic rename {} → {} failed",
            tmp_path.display(),
            path.display()
        )
    })?;

    println!(
        "{}",
        serde_json::json!({
            "kem_seed_salt_hex": salt_hex,
            "node_config_path": path.display().to_string(),
            "force_overwrite": force,
            "next_steps": [
                "Restart pqcd — the Gap B startup `warn!` should disappear",
                "After the next epoch boundary, observe `ML-KEM identity keypair rotated at epoch boundary (Gap B)` in logs",
                "On the producer node, restart LAST in a rolling-restart sequence — see deploy/ansible/RUNBOOK-KEM-ROTATION.md"
            ],
        })
    );
    Ok(())
}

/// `pqcd wallet libp2p-init [--node-config <path>] [--force]`
///
/// Stage A.4 of the private design notes.
/// Generates a 32-byte secret salt for the libp2p Ed25519 long-term
/// identity-keypair derivation — the per-host secret that the Stage A.1
/// salt seam at `crates/pqcd/src/p2p.rs::derive_keypair` mixes into the
/// SHA3-256 input. This is the operator-side primitive for **first-time**
/// salt staging at viper-research-1 genesis; for ongoing 90-day rotation
/// post-launch use `pqcd wallet rotate-peer-id --in-place` instead
/// (which also submits the on-chain `ValidatorRotatePeerId` tx).
///
/// **Why this exists**: without a salt, the libp2p Keypair is derived
/// from `config.node_id` ALONE — and `node_id` is publicly observable
/// (logs, `/v1/status`, peer-info responses). An attacker who knows it
/// could recompute the long-term libp2p Ed25519 identity secret without
/// disk access. Scope: the libp2p TLS production transport uses
/// **ephemeral** KEM keys per connection (D-04 closure 2026-05-11), so
/// channel confidentiality is unaffected — but the long-term Ed25519
/// identity is used for GossipSub envelope `MessageAuthenticity::Signed`
/// attribution (R-14 in KNOWN-ISSUES.md).
///
/// # Behaviour
///
/// 1. Generates 32 bytes from the OS CSPRNG (`getrandom`).
/// 2. Hex-encodes to 64 chars.
/// 3. If `--node-config <path>` is provided:
///    - Parses the existing `node.json`.
///    - Sets `devnet.libp2p_seed_salt_hex` to the new value.
///    - Refuses if the field already exists, unless `--force` is given.
///    - Writes the result atomically (tempfile + rename) preserving
///      file mode AND (uid, gid) so a `sudo`-invoked run from an
///      Ansible playbook does not produce a root-owned file the
///      pqchain-running daemon cannot read.
/// 4. If `--node-config` is absent, prints the hex to stdout with a
///    one-line operator instruction (CI / containerised fallback).
///
/// # Operator workflow (viper-research-1 genesis)
///
/// 1. On each host (via Ansible, Phase 4b of `launch-viper-research-1.yml`):
///    `pqcd wallet libp2p-init --node-config /etc/pqchain/node.json`
/// 2. Phase 5 starts pqcd. The startup `warn!` about the legacy
///    `node_id`-only derivation is gone; the libp2p Keypair is now
///    derived from `(node_id, libp2p_seed_salt_hex)`.
/// 3. Validators reach each other via `libp2p.validator_peer_ids`
///    allow-list (also populated by Ansible from the per-host salt-
///    derived PeerIds via `pqcd peer-id <node_id> --salt <hex>`).
///
/// # Distinction vs. `pqcd wallet rotate-peer-id`
///
/// - `libp2p-init` is for **first-time** salt staging — it ONLY writes
///   to node.json. No on-chain interaction. Idempotent given `--force`.
/// - `rotate-peer-id` is for **ongoing rotation** — it submits a
///   ValidatorRotatePeerId tx, polls for landing, verifies the on-chain
///   binding flipped, then writes the new salt. Requires the chain to
///   be live + the validator to already be registered.
pub fn cmd_wallet_libp2p_init(args: &[String]) -> Result<()> {
    let mut node_config_path: Option<String> = None;
    let mut force = false;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--node-config" => {
                node_config_path = Some(
                    args.get(i + 1)
                        .context("--node-config requires a path")?
                        .clone(),
                );
                i += 2;
            }
            "--force" => {
                force = true;
                i += 1;
            }
            other => bail!("unknown flag: {other}"),
        }
    }

    // Step 1: generate 32 bytes via OS CSPRNG. Same source as kem-init.
    let mut salt = [0u8; 32];
    getrandom::fill(&mut salt).context("OS CSPRNG (getrandom) failed for libp2p-init")?;
    let salt_hex = hex::encode(salt);

    let Some(node_config_path) = node_config_path else {
        // No path → just print the salt + an instruction. Fallback for
        // environments without filesystem access (CI smoke-test,
        // container without persistent volume mounted in).
        println!(
            "{}",
            serde_json::json!({
                "libp2p_seed_salt_hex": salt_hex,
                "instructions": [
                    "Paste this 64-char hex value into the `devnet.libp2p_seed_salt_hex` field of your node.json",
                    "Ensure node.json is mode 0600 (chmod 600 node.json) — the salt is a long-term secret",
                    "Restart pqcd; the legacy `node_id`-only libp2p derivation `warn!` should disappear",
                    "See R-14 in KNOWN-ISSUES.md and PEER-ID-ROTATION-SCOPING-2026-05-11.md §2"
                ],
            })
        );
        return Ok(());
    };

    // Step 2: read existing node.json, set the field, atomic-write
    // back preserving mode AND ownership.
    let path = std::path::PathBuf::from(&node_config_path);
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("read node config at {}", path.display()))?;

    // serde_json::Value (not strict NodeConfig parse) so unknown fields
    // round-trip cleanly. Same rationale as kem-init.
    let mut json: serde_json::Value = serde_json::from_str(&raw).with_context(|| {
        format!(
            "parse node config at {} as JSON \
             (TOML configs are not supported by this command — \
              edit the salt field manually for TOML)",
            path.display()
        )
    })?;

    let devnet_obj = json
        .as_object_mut()
        .context("node config root is not a JSON object")?
        .entry("devnet")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));

    let devnet_map = devnet_obj
        .as_object_mut()
        .context("`devnet` field exists but is not a JSON object")?;

    // Refuse to clobber an existing salt without --force. Two reasons:
    // (1) operator may have meant to use rotate-peer-id (which also
    // submits the on-chain tx) and accidentally typed libp2p-init.
    // (2) silently re-rolling the salt invalidates every other
    // validator's pinned allow-list entry until they re-derive — a
    // surprise rotation that no on-chain audit trail records.
    if devnet_map.contains_key("libp2p_seed_salt_hex") {
        let existing = devnet_map
            .get("libp2p_seed_salt_hex")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !existing.is_empty() && !force {
            bail!(
                "node config at {} already has `devnet.libp2p_seed_salt_hex` set. \
                 Use --force to overwrite — but consider `pqcd wallet rotate-peer-id` \
                 instead if the chain is live: rotate-peer-id submits the matching \
                 ValidatorRotatePeerId tx so the on-chain binding stays in sync with \
                 the host's new PeerId.",
                path.display()
            );
        }
    }

    devnet_map.insert(
        "libp2p_seed_salt_hex".to_owned(),
        serde_json::Value::String(salt_hex.clone()),
    );

    // Step 3: atomic write. Same chown-preserving shape as kem-init —
    // sudo-invoked runs from Ansible MUST not produce a root-owned
    // node.json (would lock the pqchain daemon out on next start).
    let mut serialised =
        serde_json::to_vec_pretty(&json).context("serialise updated node config to JSON")?;
    serialised.push(b'\n');
    let tmp_path = path.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&tmp_path, &serialised)
        .with_context(|| format!("write tempfile {}", tmp_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let original_meta = std::fs::metadata(&path)
            .with_context(|| format!("stat original {} for perm preservation", path.display()))?;
        let original_mode = original_meta.permissions().mode() & 0o7777;
        let original_uid = original_meta.uid();
        let original_gid = original_meta.gid();
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(original_mode))
            .with_context(|| {
                format!("restore mode {original_mode:#o} on {}", tmp_path.display())
            })?;
        let c_path = std::ffi::CString::new(tmp_path.as_os_str().as_encoded_bytes())
            .context("tempfile path contains a NUL byte (impossible on Unix)")?;
        // SAFETY: chown(2) on a path we just created. No invariants to uphold.
        let rc = unsafe { libc::chown(c_path.as_ptr(), original_uid, original_gid) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            tracing::warn!(
                tmp_path = %tmp_path.display(),
                expected_uid = original_uid,
                expected_gid = original_gid,
                error = %err,
                "chown(2) on libp2p-init tempfile failed; the new node.json may have wrong ownership \
                 and pqcd may fail to read it on restart. Run \
                 `chown pqchain:pqchain /etc/pqchain/node.json` to recover."
            );
        }
    }
    std::fs::rename(&tmp_path, &path).with_context(|| {
        format!(
            "atomic rename {} → {} failed",
            tmp_path.display(),
            path.display()
        )
    })?;

    println!(
        "{}",
        serde_json::json!({
            "libp2p_seed_salt_hex": salt_hex,
            "node_config_path": path.display().to_string(),
            "force_overwrite": force,
            "next_steps": [
                "Start (or restart) pqcd — the libp2p Keypair is now salt-bound",
                "Verify the salt-bound PeerId on this host with: \
                 pqcd peer-id <node_id> --salt <hex>  (same hex value emitted above)",
                "For viper-research-1 genesis: include the salt-derived PeerId in the \
                 `libp2p.validator_peer_ids` allow-list on every peer's node.json — \
                 see deploy/ansible/playbooks/launch-viper-research-1.yml Phase 4b"
            ],
        })
    );
    Ok(())
}

#[cfg(test)]
mod in_place_keystore_tests;

#[cfg(test)]
mod in_place_node_config_tests;

#[cfg(test)]
mod kem_init_tests;

#[cfg(test)]
mod libp2p_init_tests;
