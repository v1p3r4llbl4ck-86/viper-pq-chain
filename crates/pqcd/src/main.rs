// SPDX-License-Identifier: BUSL-1.1
//! pqcd — PQ Chain node binary.
//!
//! # Commands
//!
//! - `pqcd bootstrap <node-config.json>` — bootstrap node state from persisted history
//! - `pqcd status <node-config.json>`    — print chain status after bootstrap
//! - `pqcd api-serve <node-config.json> [addr]` — start read/status HTTP API (default: 0.0.0.0:26657)
//! - `pqcd devnet-serve <node-config.json>` — run the local multi-node devnet node runtime
//! - `pqcd snapshot-export <node-config.json> <output-file>` — export current checkpoint as snapshot file
//! - `pqcd snapshot-import <node-config.json> <snapshot-file>` — import snapshot file as trusted checkpoint
//! - `pqcd snapshot-prune <node-config.json> [--keep-tail-blocks N] [--force]` — TASK-187a follower disk reclamation
//! - `pqcd cold-storage-export <node-config.json> --cutoff-height N --output-dir DIR [--batch-size 10000] [--sign-with-operator <addr>] [--anchor-tsa <url>] [--tsa-best-effort] [--upload-to s3://...]` — TASK-188 / TASK-188b cold-storage rotation export
//! - `pqcd cold-storage-import <node-config.json> <input-dir> [--insecure-no-verify] [--require-tsa]` — TASK-188b §3 cold-storage rotation import (replay + verify)
//! - `pqcd ceremony [--chain-id S] [--validators N] [--block-time-ms M] [--output FILE] [--deploy-token user:pass@registry]` — TASK-233 chart ceremony tooling
//! - `pqcd migrate-store <node-config.json>` — migrate legacy DiskChainStore to RocksDB
//! - `pqcd validate-tx <hex>`           — validate a CBOR-encoded transaction (local testing)
//! - `pqcd peer-id <node_id>`           — print deterministic libp2p PeerId for a given node_id
//!   (for building bootstrap multiaddrs in ops configs)
//! - `pqcd keystore verify <keystore.json>` — operator pre-deploy sanity check:
//!   parses a keystore.json with the production loader, prints the per-entry
//!   summary, exits non-zero on parse failure or zero validators
//! - `pqcd version`                     — print version

use anyhow::{bail, Context, Result};
use pqcd::devnet::run_from_config_path;
use pqcd::node::{bootstrap_from_config_path, open_node_state, render_status};
use std::env;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

mod cli;
use cli::ceremony::*;
use cli::cold_storage::*;
use cli::keygen::*;
use cli::peer::*;
use cli::snapshot::*;
use cli::validate::*;
use cli::wallet::*;

/// Build the tracing subscriber stack used by every pqcd subcommand:
///
///   Registry
///     └─ EnvFilter (RUST_LOG, default INFO)
///         ├─ fmt layer       — human-readable to stderr / journald
///         ├─ LogMetricsLayer — increments pqchain_log_events_total{level}
///         └─ AuditLogLayer   — captures target=viper.audit to JSONL with hash chain
///
/// Layers compose: each event passes through every layer that survives
/// the EnvFilter at the registry root. Metrics see only events that
/// actually got emitted (matches the operator's intuition); audit captures
/// only target=viper.audit regardless of level (set RUST_LOG to include
/// info if you want them in stderr too).
fn setup_tracing() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer())
        .with(pqcd::log_metrics::LogMetricsLayer)
        .with(pqcd::audit_log::AuditLogLayer)
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    // PQ TLS activation — must run before any reqwest::Client or libp2p
    // swarm is built. Wired via the `hybrid-kem-tls` Cargo feature; the
    // no-feature path logs a warn so operators can see classical-X25519
    // posture in journalctl. See CHANGELOG.md, 2026-05-15 PQ coverage
    // remediation.
    pqcd::tls::init_pq_provider()?;

    setup_tracing();

    // Sentinel audit event: makes the post-restart hash-chain
    // discontinuity explicit instead of silent.
    pqcd::audit_log::emit_process_started(
        &std::env::var("VIPER_NODE_ID").unwrap_or_else(|_| "unknown".to_string()),
        env!("CARGO_PKG_VERSION"),
    );

    let args: Vec<String> = env::args().collect();

    match args.get(1).map(String::as_str) {
        Some("validate-tx") => {
            let hex_input = args.get(2).context("Usage: pqcd validate-tx <hex-encoded CBOR>")?;
            cmd_validate_tx(hex_input)
        }
        Some("bootstrap") => {
            let config_path = args.get(2).context("Usage: pqcd bootstrap <node-config.json>")?;
            cmd_bootstrap(config_path)
        }
        Some("status") => {
            let config_path = args.get(2).context("Usage: pqcd status <node-config.json>")?;
            cmd_status(config_path)
        }
        Some("api-serve") => {
            let config_path =
                args.get(2).context("Usage: pqcd api-serve <node-config.json> [addr]")?;
            let addr = args.get(3).map(String::as_str).unwrap_or("0.0.0.0:26657");
            cmd_api_serve(config_path, addr).await
        }
        Some("devnet-serve") => {
            let config_path =
                args.get(2).context("Usage: pqcd devnet-serve <node-config.json>")?;
            cmd_devnet_serve(config_path).await
        }
        Some("snapshot-export") => {
            let config_path = args
                .get(2)
                .context("Usage: pqcd snapshot-export <node-config.json> <output-file>")?;
            let output_path = args
                .get(3)
                .context("Usage: pqcd snapshot-export <node-config.json> <output-file>")?;
            cmd_snapshot_export(config_path, output_path)
        }
        Some("migrate-store") => {
            let config_path = args
                .get(2)
                .context("Usage: pqcd migrate-store <node-config.json>")?;
            cmd_migrate_store(config_path)
        }
        Some("snapshot-import") => {
            let config_path = args
                .get(2)
                .context("Usage: pqcd snapshot-import <node-config.json> <snapshot-file>")?;
            let snapshot_path = args
                .get(3)
                .context("Usage: pqcd snapshot-import <node-config.json> <snapshot-file>")?;
            cmd_snapshot_import(config_path, snapshot_path)
        }
        Some("snapshot-prune") => cmd_snapshot_prune(&args),
        Some("cold-storage-export") => cmd_cold_storage_export(&args),
        Some("cold-storage-import") => cmd_cold_storage_import(&args),
        Some("ceremony") => cmd_ceremony(&args),
        Some("keygen") => cmd_keygen(&args),
        Some("peer-id") => cmd_peer_id(&args),
        Some("keystore") => match args.get(2).map(String::as_str) {
            Some("verify") => cmd_keystore_verify(&args),
            _ => bail!("Usage: pqcd keystore verify <keystore.json>"),
        },
        Some("wallet") => {
            match args.get(2).map(String::as_str) {
                Some("create") => cmd_wallet_create(&args),
                Some("import-mnemonic") => cmd_wallet_import_mnemonic(&args),
                Some("import-seed") => cmd_wallet_import_seed(&args),
                Some("address") => cmd_wallet_address(&args),
                Some("public-key") => cmd_wallet_public_key(&args),
                Some("sign") => cmd_wallet_sign(&args),
                Some("send") => cmd_wallet_send(&args).await,
                Some("export-seed") => cmd_wallet_export_seed(&args),
                Some("vault-create") => cmd_wallet_vault_create(&args).await,
                Some("archival-keygen") => cmd_wallet_archival_keygen(&args),
                Some("archival-register") => cmd_wallet_archival_register(&args).await,
                Some("register-validator") => cmd_wallet_register_validator(&args).await,
                Some("rotate-consensus-key") => cmd_wallet_rotate_consensus_key(&args).await,
                Some("rotate-peer-id") => cmd_wallet_rotate_peer_id(&args).await,
                Some("kem-init") => cmd_wallet_kem_init(&args),
                Some("libp2p-init") => cmd_wallet_libp2p_init(&args),
                _ => bail!("Usage: pqcd wallet <create|import-mnemonic|import-seed|address|public-key|sign|send|export-seed|vault-create|archival-keygen|archival-register|register-validator|rotate-consensus-key|rotate-peer-id|kem-init|libp2p-init>"),
            }
        }
        Some("version") | None => {
            println!("pqcd {}", env!("CARGO_PKG_VERSION"));
            println!(
                "Viper PQ Chain node (pqcd)"
            );
            Ok(())
        }
        Some(cmd) => bail!(
            "unknown command: {cmd}. Available: api-serve, bootstrap, ceremony, cold-storage-export, cold-storage-import, devnet-serve, keygen, keystore, migrate-store, peer-id, snapshot-export, snapshot-import, snapshot-prune, status, validate-tx, version, wallet"
        ),
    }
}

/// Resolve the `chain_id` bytes for a wallet CLI command.
///
/// Precedence: `--chain-id <hex>` flag > `VIPER_CHAIN_ID` env var (hex) >
/// default `b"viper-pq-1"` (viper-pq-1 placeholder per ADR-053 §T1.3).
///
/// ADR-053 §T1.3 binds every derived address to the host chain; this helper
/// gives all wallet CLI commands a single resolution path so the generated
/// keystore is labelled consistently.
pub(crate) fn resolve_chain_id_flag(flag: Option<String>) -> Result<Vec<u8>> {
    if let Some(hex_str) = flag {
        return hex::decode(hex_str.trim()).context("--chain-id must be a valid hex string");
    }
    if let Ok(env_val) = std::env::var("VIPER_CHAIN_ID") {
        return hex::decode(env_val.trim()).context("VIPER_CHAIN_ID must be a valid hex string");
    }
    Ok(b"viper-pq-1".to_vec())
}

fn cmd_bootstrap(config_path: &str) -> Result<()> {
    let report = bootstrap_from_config_path(config_path.as_ref())?;
    println!("BOOTSTRAP_OK");
    println!("{}", render_status(&report));
    Ok(())
}

fn cmd_status(config_path: &str) -> Result<()> {
    let report = bootstrap_from_config_path(config_path.as_ref())?;
    println!("{}", render_status(&report));
    Ok(())
}

async fn cmd_api_serve(config_path: &str, addr: &str) -> Result<()> {
    let state = open_node_state(config_path.as_ref())?;
    let app = pqcd::api::router(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind to {addr}"))?;

    pqcd::devnet::print_demo_chain_banner();
    println!("API listening on http://{addr}");
    axum::serve(listener, app)
        .await
        .context("API server error")?;
    Ok(())
}

async fn cmd_devnet_serve(config_path: &str) -> Result<()> {
    run_from_config_path(config_path.as_ref()).await
}
