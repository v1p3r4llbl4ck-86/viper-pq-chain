// SPDX-License-Identifier: BUSL-1.1
//! viper-archival-sidecar — RFC 3161 TSA anchoring daemon entry point.
//!
//! SPEC-ARCHIVAL-001 §6, ADR-045, TASK-164 / M4.5.
//!
//! # CLI
//!
//! ```text
//! viper-archival-sidecar --config /etc/pqchain/sidecar.toml
//! ```
//!
//! # Environment
//!
//! - `VIPER_PASSPHRASE`               — keystore passphrase (if not in TOML)
//! - `VIPER_TSA_<NAME>_AUTH`          — per-TSA HTTP basic-auth (user:pw)
//! - `RUST_LOG`                       — standard tracing filter (default "info")

use std::{path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use pqc_crypto::AlgId;
use pqc_types::{
    account::Address,
    transaction::{MsgType, Transaction},
};
use reqwest::Client;
use sha2::{Digest, Sha256};
use tokio::time::{self, MissedTickBehavior};
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

use viper_archival_sidecar::rfc3161::shake256_external_hash;
use viper_archival_sidecar::{
    build_timestamp_request, load_config, post_timestamp_request, tsa_preimage, SidecarConfig,
};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let config_path = parse_config_path(&args)?;
    let cfg = load_config(&config_path)?;

    let passphrase = cfg.resolve_passphrase()?;
    let keystore = pqc_keystore::Keystore::load(std::path::Path::new(&cfg.keystore_path))
        .with_context(|| format!("load sidecar keystore: {}", cfg.keystore_path))?;
    let sender_addr_bytes = keystore
        .address()
        .context("decode sidecar keystore address")?;
    let sender = Address(sender_addr_bytes);
    let alg_id = keystore.parsed_alg_id().context("parse keystore alg_id")?;

    info!(
        node_url = %cfg.node_url,
        tsa_endpoints = cfg.tsa_endpoints.len(),
        poll_interval_secs = cfg.poll_interval_secs,
        required_anchors = cfg.required_anchors,
        sender = %hex::encode(sender.0),
        "viper-archival-sidecar starting"
    );

    let http = Client::builder()
        .user_agent("viper-archival-sidecar/0.1")
        .build()
        .context("build reqwest client")?;

    let mut last_epoch = cfg.starting_epoch;
    let mut ticker = time::interval(Duration::from_secs(cfg.poll_interval_secs.max(1)));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("sidecar shutdown requested (SIGINT)");
                break;
            }
            _ = ticker.tick() => {
                match tick(&http, &cfg, &keystore, &passphrase, &sender, alg_id, &mut last_epoch).await {
                    Ok(processed) => {
                        if processed > 0 {
                            info!(processed, last_epoch, "sidecar tick processed records");
                        } else {
                            debug!(last_epoch, "sidecar tick idle (no new records)");
                        }
                    }
                    Err(e) => warn!(error = %e, "sidecar tick failed (retry on next interval)"),
                }
            }
        }
    }

    Ok(())
}

fn parse_config_path(args: &[String]) -> Result<PathBuf> {
    match args.get(1).map(String::as_str) {
        Some("--config") => {
            let p = args.get(2).context("--config requires a path")?;
            Ok(PathBuf::from(p))
        }
        Some("--help") | Some("-h") => {
            println!(
                "Usage: viper-archival-sidecar --config <sidecar.toml>\n\n\
                 Poll a pqcd node's archival records and anchor them to RFC 3161 TSAs.\n\
                 Full docs: SPEC-ARCHIVAL-001 §6 / ADR-045 / TASK-164."
            );
            std::process::exit(0);
        }
        Some(other) => anyhow::bail!("unknown flag: {other}"),
        None => anyhow::bail!("Usage: viper-archival-sidecar --config <path/to/sidecar.toml>"),
    }
}

/// One poll iteration. Returns the number of records for which at least
/// one `AddAnchor` transaction was successfully submitted.
async fn tick(
    http: &Client,
    cfg: &SidecarConfig,
    keystore: &pqc_keystore::Keystore,
    passphrase: &str,
    sender: &Address,
    alg_id: AlgId,
    last_epoch: &mut u64,
) -> Result<usize> {
    // Step 1: fetch candidate records from the node.
    let records = fetch_records(http, &cfg.node_url, *last_epoch, cfg.batch_limit).await?;
    let mut processed = 0usize;

    // Step 2: figure out what to anchor.
    for rec in records {
        if rec.timestamp_anchors_count >= cfg.required_anchors {
            debug!(
                epoch = rec.epoch_number,
                "record already anchored, skipping"
            );
            *last_epoch = rec.epoch_number.saturating_add(1).max(*last_epoch);
            continue;
        }

        // Step 3: the TSA preimage is the chain's own §6.1 formula.
        let preimage = tsa_preimage(rec.epoch_number, &rec.epoch_root);
        let mut hasher = Sha256::new();
        hasher.update(&preimage);
        let digest: [u8; 32] = hasher.finalize().into();
        let req_der = build_timestamp_request(&digest);

        // Step 4: fan out to every configured TSA.
        let mut anchored_for_this_record = 0usize;
        for endpoint in &cfg.tsa_endpoints {
            let basic_auth = cfg.resolve_basic_auth(endpoint);
            match post_timestamp_request(http, endpoint, basic_auth, &req_der).await {
                Ok(tst_bytes) => {
                    info!(
                        tsa = %endpoint.name,
                        epoch = rec.epoch_number,
                        tst_len = tst_bytes.len(),
                        "TSA response received"
                    );
                    // Step 5: submit ArchivalRecordAddAnchor on-chain.
                    match submit_add_anchor(
                        http,
                        &cfg.node_url,
                        keystore,
                        passphrase,
                        sender,
                        alg_id,
                        rec.epoch_number,
                        &tst_bytes,
                    )
                    .await
                    {
                        Ok(_) => {
                            anchored_for_this_record += 1;
                        }
                        Err(e) => warn!(
                            tsa = %endpoint.name,
                            epoch = rec.epoch_number,
                            error = %e,
                            "AddAnchor submission failed (non-fatal, will retry on next tick)"
                        ),
                    }
                }
                Err(e) => warn!(
                    tsa = %endpoint.name,
                    epoch = rec.epoch_number,
                    error = %e,
                    "TSA POST failed (non-fatal, will retry on next tick)"
                ),
            }
            // Small delay between TSAs — spreads load, avoids a storm when
            // all endpoints share rate-limit buckets (sometimes true within
            // a provider family).
            time::sleep(Duration::from_millis(50)).await;
        }

        if anchored_for_this_record > 0 {
            processed += 1;
            *last_epoch = rec.epoch_number.saturating_add(1).max(*last_epoch);
        }
    }

    Ok(processed)
}

#[derive(Debug, Clone)]
struct RecordSummary {
    epoch_number: u64,
    epoch_root: [u8; 32],
    timestamp_anchors_count: usize,
}

async fn fetch_records(
    http: &Client,
    node_url: &str,
    since: u64,
    limit: usize,
) -> Result<Vec<RecordSummary>> {
    let url = format!(
        "{}/v1/archival/records?since={since}&limit={limit}",
        node_url.trim_end_matches('/')
    );
    let resp = http
        .get(&url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        anyhow::bail!(
            "node returned HTTP {} for GET /v1/archival/records",
            resp.status()
        );
    }
    let body: serde_json::Value = resp.json().await.context("parse records response")?;
    let arr = body
        .get("records")
        .and_then(|v| v.as_array())
        .context("records field missing from node response")?;
    let mut out = Vec::with_capacity(arr.len());
    for v in arr {
        let epoch_number = v
            .get("epoch_number")
            .and_then(|x| x.as_u64())
            .context("missing epoch_number")?;
        let epoch_root_hex = v
            .get("epoch_root")
            .and_then(|x| x.as_str())
            .context("missing epoch_root")?;
        let epoch_root_bytes = hex::decode(epoch_root_hex).context("invalid epoch_root hex")?;
        if epoch_root_bytes.len() != 32 {
            anyhow::bail!("epoch_root not 32 bytes");
        }
        let mut epoch_root = [0u8; 32];
        epoch_root.copy_from_slice(&epoch_root_bytes);
        let timestamp_anchors_count = v
            .get("timestamp_anchors_count")
            .and_then(|x| x.as_u64())
            .unwrap_or(0) as usize;
        out.push(RecordSummary {
            epoch_number,
            epoch_root,
            timestamp_anchors_count,
        });
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
async fn submit_add_anchor(
    http: &Client,
    node_url: &str,
    keystore: &pqc_keystore::Keystore,
    passphrase: &str,
    sender: &Address,
    alg_id: AlgId,
    epoch_number: u64,
    tst_bytes: &[u8],
) -> Result<()> {
    // Fetch sender nonce from the node.
    let account_url = format!(
        "{}/v1/accounts/{}",
        node_url.trim_end_matches('/'),
        hex::encode(sender.0)
    );
    let nonce_resp = http
        .get(&account_url)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .with_context(|| format!("GET {account_url}"))?;
    let nonce: u64 = if nonce_resp.status().is_success() {
        nonce_resp
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|v| v.get("nonce").and_then(|x| x.as_u64()))
            .unwrap_or(0)
    } else {
        0
    };

    // Fetch chain_id from /v1/status.
    let status_url = format!("{}/v1/status", node_url.trim_end_matches('/'));
    let chain_id = http
        .get(&status_url)
        .timeout(Duration::from_secs(5))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await
        .context("parse status for chain_id")?["chain_id"]
        .as_str()
        .context("chain_id missing from status")?
        .as_bytes()
        .to_vec();

    // Build AddAnchor payload.
    let external_hash = shake256_external_hash(tst_bytes);
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let payload = pqc_state::apply::archival::encode_archival_record_add_anchor_payload(
        epoch_number,
        pqc_types::archival::AnchorKind::Rfc3161Tsa.as_u8(),
        tst_bytes,
        &external_hash,
        now_unix,
    );

    // Build + sign transaction.
    let unsigned_tx = Transaction {
        tx_version: 1,
        chain_id,
        msg_type: MsgType::ArchivalRecordAddAnchor,
        sender: sender.clone(),
        nonce,
        fee: 30_000,
        fee_tip: 0,
        gas_limit: 5_000,
        payload,
        sig_alg_id: alg_id,
        sig_key_version: 1,
        signature: Vec::new(),
    };
    let unsigned_cbor = pqc_tx::codec::encode_tx(&unsigned_tx)
        .map_err(|e| anyhow::anyhow!("encode unsigned AddAnchor: {e}"))?;
    let signed_cbor = keystore.sign_transaction(passphrase, &unsigned_cbor)?;

    let txs_url = format!("{}/v1/txs", node_url.trim_end_matches('/'));
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &signed_cbor);
    let submit_resp = http
        .post(&txs_url)
        .json(&serde_json::json!({ "encoding": "cbor-base64", "tx_bytes": b64 }))
        .send()
        .await
        .context("POST /v1/txs")?;
    if !submit_resp.status().is_success() {
        let status = submit_resp.status();
        let body = submit_resp.text().await.unwrap_or_default();
        anyhow::bail!("AddAnchor rejected (HTTP {status}): {body}");
    }
    Ok(())
}
