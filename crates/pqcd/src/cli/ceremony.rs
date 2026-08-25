// SPDX-License-Identifier: BUSL-1.1
//! `pqcd ceremony` CLI handler — TASK-233 chart ceremony tooling.
//!
//! Extracted from `main.rs` 2026-05-10. Generates a Helm values JSON
//! plus a per-validator secrets manifest, both consumable by
//! `helm install`.

use anyhow::{bail, Context, Result};

/// TASK-233 — `pqcd ceremony` subcommand.
///
/// Usage:
///     pqcd ceremony [--chain-id S] [--validators N] [--block-time-ms M]
///                   [--genesis-balance B] [--image-repository R]
///                   [--image-tag T] [--namespace NS] [--release-name R]
///                   [--deploy-token user:pass@registry] [--output FILE]
///                   [--secrets-output FILE]
///
/// Defaults:
///     --chain-id           viper-pq-kind-test
///     --validators         3
///     --block-time-ms      500
///     --genesis-balance    1000000000
///     --image-repository   ghcr.io/v1p3r4llbl4ck-86
///     --image-tag          main
///     --output             values-ceremony.json (- for stdout)
///
/// Emits a Helm values JSON consumable by
///     helm install ./charts/viper-pq-chain -f values-ceremony.json
/// The validator cohort (addresses + commit_seed_hex + public_key_hex)
/// is also printed to stderr in a paste-friendly form for the operator's
/// runbook record.
pub fn cmd_ceremony(args: &[String]) -> Result<()> {
    use pqcd::ceremony::{
        build_secrets_manifest, generate_ceremony_values, CeremonyConfig, DeployToken,
        ServiceAccount,
    };

    let mut chain_id = "viper-pq-kind-test".to_string();
    let mut validators: u32 = 3;
    let mut block_time_ms: u64 = 500;
    let mut genesis_balance: u128 = 1_000_000_000;
    let mut image_repository = "ghcr.io/v1p3r4llbl4ck-86".to_string();
    let mut image_tag = "main".to_string();
    let mut output_path: Option<String> = None;
    let mut secrets_output_path: Option<String> = None;
    let mut namespace = "viper".to_string();
    let mut release_name = "viper-test".to_string();
    let mut deploy_token: Option<DeployToken> = None;
    let mut service_accounts: Vec<ServiceAccount> = Vec::new();

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--chain-id" => {
                chain_id = args
                    .get(i + 1)
                    .context("--chain-id requires a value (e.g. viper-pq-kind-test)")?
                    .clone();
                i += 2;
            }
            "--validators" => {
                let v = args
                    .get(i + 1)
                    .context("--validators requires a value (>=1)")?;
                validators = v
                    .parse::<u32>()
                    .with_context(|| format!("--validators expected u32, got '{v}'"))?;
                i += 2;
            }
            "--block-time-ms" => {
                let v = args
                    .get(i + 1)
                    .context("--block-time-ms requires a value")?;
                block_time_ms = v
                    .parse::<u64>()
                    .with_context(|| format!("--block-time-ms expected u64, got '{v}'"))?;
                i += 2;
            }
            "--genesis-balance" => {
                let v = args
                    .get(i + 1)
                    .context("--genesis-balance requires a value")?;
                genesis_balance = v
                    .parse::<u128>()
                    .with_context(|| format!("--genesis-balance expected u128, got '{v}'"))?;
                i += 2;
            }
            "--image-repository" => {
                image_repository = args
                    .get(i + 1)
                    .context("--image-repository requires a value")?
                    .clone();
                i += 2;
            }
            "--image-tag" => {
                image_tag = args
                    .get(i + 1)
                    .context("--image-tag requires a value")?
                    .clone();
                i += 2;
            }
            "--output" => {
                output_path = Some(
                    args.get(i + 1)
                        .context("--output requires a path or '-' for stdout")?
                        .clone(),
                );
                i += 2;
            }
            "--secrets-output" => {
                secrets_output_path = Some(
                    args.get(i + 1)
                        .context("--secrets-output requires a path")?
                        .clone(),
                );
                i += 2;
            }
            "--namespace" => {
                namespace = args
                    .get(i + 1)
                    .context("--namespace requires a value (default: viper)")?
                    .clone();
                i += 2;
            }
            "--release-name" => {
                // Helm release name the operator will pass to `helm install`.
                // Used in the libp2p bootstrap_peers DNS multiaddr; mismatched
                // value → followers can't dial the validator → height-0 islands
                // (the gap caught by the 2026-05-05 kind smoke).
                release_name = args
                    .get(i + 1)
                    .context("--release-name requires a value (default: viper-test)")?
                    .clone();
                i += 2;
            }
            "--deploy-token" => {
                let raw = args.get(i + 1).context(
                    "--deploy-token requires user:pass@registry (e.g. \
                     user:token@ghcr.io)",
                )?;
                let (creds, registry) = raw.rsplit_once('@').context(
                    "--deploy-token must end with '@<registry>' (e.g. \
                     user:token@ghcr.io)",
                )?;
                let (user, pass) = creds.split_once(':').context(
                    "--deploy-token credentials must be 'user:pass' before the @<registry>",
                )?;
                deploy_token = Some(DeployToken {
                    registry: registry.to_string(),
                    username: user.to_string(),
                    password: pass.to_string(),
                });
                i += 2;
            }
            "--service-account" => {
                // <label>:<ml-dsa-65 public key hex> — a funded genesis account
                // for an operator service (repeatable). Get the key with
                // `pqcd wallet public-key <keystore>`.
                let raw = args
                    .get(i + 1)
                    .context("--service-account requires <label>:<public-key-hex>")?;
                let (label, pk) = raw.split_once(':').context(
                    "--service-account must be <label>:<public-key-hex> (e.g. notary:abcd…)",
                )?;
                if label.is_empty() || pk.is_empty() {
                    bail!("--service-account: label and public key must both be non-empty");
                }
                service_accounts.push(ServiceAccount {
                    label: label.to_string(),
                    public_key_hex: pk.to_string(),
                });
                i += 2;
            }
            other => bail!(
                "unknown flag '{other}'. Run `pqcd ceremony --help` (or read the \
                 module doc at crates/pqcd/src/ceremony.rs) for the full flag list."
            ),
        }
    }

    let cfg = CeremonyConfig {
        chain_id,
        validators,
        block_time_ms,
        genesis_balance,
        image_repository,
        image_tag,
        release_name: release_name.clone(),
        namespace: namespace.clone(),
        deploy_token,
        service_accounts,
    };
    let (values, validator_entries, identity_salts) =
        generate_ceremony_values(&cfg).context("ceremony generation failed")?;
    let json_str = serde_json::to_string_pretty(&values)
        .context("failed to serialise ceremony values to JSON")?;
    let secrets_yaml =
        build_secrets_manifest(&cfg, &namespace, &validator_entries, &identity_salts)
            .context("failed to build secrets manifest")?;

    // Operator-facing summary on stderr — even when stdout is piped to
    // a file the operator still sees the cohort manifest.
    eprintln!(
        "# pqcd ceremony — chain_id={} validators={} namespace={}",
        cfg.chain_id, cfg.validators, namespace
    );
    eprintln!("# Validator cohort (paste into your operator runbook):");
    for v in &validator_entries {
        eprintln!(
            "#   {}  address={} pk_hex_first16={}…",
            v.node_id,
            v.address_hex,
            &v.public_key_hex[..32.min(v.public_key_hex.len())],
        );
    }

    if let Some(accounts) = values.get("_service_accounts").and_then(|v| v.as_array()) {
        if !accounts.is_empty() {
            eprintln!("# Service accounts (funded at genesis, no governance rights):");
            for a in accounts {
                eprintln!(
                    "#   {}  address={}",
                    a["label"].as_str().unwrap_or("?"),
                    a["address_hex"].as_str().unwrap_or("?")
                );
            }
        }
    }

    let values_file = output_path.as_deref().unwrap_or("values-ceremony.json");
    let secrets_file = secrets_output_path
        .as_deref()
        .unwrap_or("secrets-ceremony.yaml");

    if values_file == "-" {
        print!("{json_str}");
        eprintln!("# (Values JSON streamed to stdout; --secrets-output bypassed.)");
    } else {
        std::fs::write(values_file, &json_str)
            .with_context(|| format!("failed to write {values_file}"))?;
        std::fs::write(secrets_file, &secrets_yaml)
            .with_context(|| format!("failed to write {secrets_file}"))?;
        // Tighten perms on the secrets file — it carries the consensus
        // seed in stringData. Best-effort: chmod 600 so a casual `cat`
        // by a non-owner returns EACCES.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(secrets_file, std::fs::Permissions::from_mode(0o600));
        }
        eprintln!(
            "# Wrote {values_file} ({} bytes)\n\
             # Wrote {secrets_file} ({} bytes, mode 0600)\n\
             # Next steps:\n\
             #   kubectl create namespace {namespace} 2>/dev/null || true\n\
             #   kubectl apply -n {namespace} -f {secrets_file}\n\
             #   helm install viper-test ./charts/viper-pq-chain -n {namespace} \\\n\
             #       --create-namespace -f {values_file}",
            json_str.len(),
            secrets_yaml.len(),
        );
    }
    Ok(())
}
