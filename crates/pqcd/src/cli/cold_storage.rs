// SPDX-License-Identifier: BUSL-1.1
//! `pqcd cold-storage-export` and `pqcd cold-storage-import` CLI handlers.
//!
//! Extracted from `main.rs` 2026-05-10. Self-contained — both fns
//! parse argv, build a config struct, and call into
//! `pqcd::cold_storage`. No state held here.

use anyhow::{bail, Context, Result};
use pqcd::node::{cold_storage_export, cold_storage_import};

/// TASK-188 / TASK-188b — `pqcd cold-storage-export` subcommand.
///
/// Usage:
///     pqcd cold-storage-export <node-config.json> \
///         --cutoff-height N --output-dir DIR \
///         [--batch-size 10000] \
///         [--sign-with-operator <addr_hex>] \
///         [--anchor-tsa <url>] [--tsa-best-effort] \
///         [--upload-to s3://<bucket>/<prefix>/]
///
/// Defaults:
///     --batch-size 10000  (matches the SPEC-ARCHIVAL-001 batch
///                          convention; smaller batches inflate
///                          per-batch metadata overhead)
///
/// Pre-conditions: pqcd MUST be stopped — the chain store is opened
/// no_wal but the underlying RocksDB still acquires an exclusive
/// lock. Use the wrapper Ansible service or `systemctl stop pqcd`.
///
/// Output: `<output-dir>/blocks-<low>-<high>.zst` per batch +
/// `<output-dir>/manifest.json`. With `--sign-with-operator` the
/// manifest carries an SLH-DSA-SHAKE-256s signature (TASK-188b §1);
/// with `--anchor-tsa` it also carries an RFC 3161 TSA token
/// (TASK-188b §2). With `--upload-to` the directory is pushed to S3
/// in-band (requires `--features s3-upload`); otherwise the operator
/// runs `aws s3 sync` externally.
pub fn cmd_cold_storage_export(args: &[String]) -> Result<()> {
    use pqcd::cold_storage::ExportOptions;

    let config_path = args.get(2).context(
        "Usage: pqcd cold-storage-export <node-config.json> \
         --cutoff-height N --output-dir DIR [--batch-size 10000] \
         [--sign-with-operator <addr_hex>] [--anchor-tsa <url>] \
         [--tsa-best-effort] [--upload-to s3://...]",
    )?;

    let mut cutoff_height: Option<u64> = None;
    let mut output_dir: Option<String> = None;
    let mut batch_size: u64 = 10_000;
    let mut sign_with_operator: Option<String> = None;
    let mut anchor_tsa: Option<String> = None;
    let mut tsa_best_effort = false;
    let mut upload_to: Option<String> = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--cutoff-height" => {
                let v = args
                    .get(i + 1)
                    .context("--cutoff-height requires a value")?;
                cutoff_height = Some(
                    v.parse::<u64>()
                        .with_context(|| format!("--cutoff-height expected u64, got '{v}'"))?,
                );
                i += 2;
            }
            "--output-dir" => {
                output_dir = Some(
                    args.get(i + 1)
                        .context("--output-dir requires a path")?
                        .clone(),
                );
                i += 2;
            }
            "--batch-size" => {
                let v = args.get(i + 1).context("--batch-size requires a value")?;
                batch_size = v
                    .parse::<u64>()
                    .with_context(|| format!("--batch-size expected u64, got '{v}'"))?;
                i += 2;
            }
            "--sign-with-operator" => {
                sign_with_operator = Some(
                    args.get(i + 1)
                        .context("--sign-with-operator requires a 32-byte hex address")?
                        .clone(),
                );
                i += 2;
            }
            "--anchor-tsa" => {
                anchor_tsa = Some(
                    args.get(i + 1)
                        .context("--anchor-tsa requires an HTTP URL")?
                        .clone(),
                );
                i += 2;
            }
            "--tsa-best-effort" => {
                tsa_best_effort = true;
                i += 1;
            }
            "--upload-to" => {
                upload_to = Some(
                    args.get(i + 1)
                        .context("--upload-to requires an s3:// URI")?
                        .clone(),
                );
                i += 2;
            }
            other => bail!(
                "unknown flag '{other}'. Usage: pqcd cold-storage-export <node-config.json> \
                 --cutoff-height N --output-dir DIR [--batch-size 10000] \
                 [--sign-with-operator <addr_hex>] [--anchor-tsa <url>] \
                 [--tsa-best-effort] [--upload-to s3://...]"
            ),
        }
    }
    let cutoff = cutoff_height.context("--cutoff-height is required (no implicit default)")?;
    let output_dir = output_dir.context("--output-dir is required (no implicit default)")?;

    let opts = ExportOptions {
        sign_with_operator_hex: sign_with_operator,
        anchor_tsa_url: anchor_tsa,
        tsa_best_effort,
    };

    let manifest = cold_storage_export(
        config_path.as_ref(),
        cutoff,
        batch_size,
        std::path::Path::new(&output_dir),
        &opts,
    )
    .context("cold-storage-export failed")?;

    if let Some(s3_uri) = upload_to.as_deref() {
        pqcd::cold_storage::upload_to_s3(std::path::Path::new(&output_dir), s3_uri)
            .context("cold-storage-export S3 upload failed")?;
    }

    println!(
        "cold_storage_export_completed: chain_id_hex={} low_height={} high_height={} \
         batch_count={} signed={} anchored={} uploaded={} output_dir={output_dir}",
        manifest.chain_id_hex,
        manifest.low_height,
        manifest.high_height,
        manifest.batch_count,
        manifest.signature.is_some(),
        manifest.tsa_token.is_some(),
        upload_to.is_some(),
    );
    if upload_to.is_none() {
        eprintln!(
            "# Wrote {} batch(es) + manifest.json to {output_dir}\n\
             # Next step (operator-side, out-of-band):\n\
             #   aws s3 sync {output_dir}/ s3://<bucket>/<prefix>/",
            manifest.batch_count,
        );
    }
    Ok(())
}

/// TASK-188b §3 — `pqcd cold-storage-import` subcommand.
///
/// Usage:
///     pqcd cold-storage-import <node-config.json> <input-dir> \
///         [--insecure-no-verify] [--require-tsa]
///
/// Pre-conditions: target node MUST be empty (height = 0); pqcd MUST
/// be stopped (RocksDB exclusive lock). The manifest signature is
/// verified by default; pass `--insecure-no-verify` only for v1
/// (unsigned) manifests OR for operator-trusted-source restores
/// where the chain of custody is established out-of-band.
pub fn cmd_cold_storage_import(args: &[String]) -> Result<()> {
    use pqcd::cold_storage::ImportOptions;

    let config_path = args.get(2).context(
        "Usage: pqcd cold-storage-import <node-config.json> <input-dir> \
         [--insecure-no-verify] [--require-tsa]",
    )?;
    let input_dir = args.get(3).context(
        "Usage: pqcd cold-storage-import <node-config.json> <input-dir> \
         [--insecure-no-verify] [--require-tsa]",
    )?;

    let mut insecure_no_verify = false;
    let mut require_tsa = false;
    let mut i = 4;
    while i < args.len() {
        match args[i].as_str() {
            "--insecure-no-verify" => {
                insecure_no_verify = true;
                i += 1;
            }
            "--require-tsa" => {
                require_tsa = true;
                i += 1;
            }
            other => bail!(
                "unknown flag '{other}'. Usage: pqcd cold-storage-import <node-config.json> \
                 <input-dir> [--insecure-no-verify] [--require-tsa]"
            ),
        }
    }

    let opts = ImportOptions {
        insecure_no_verify,
        require_tsa,
    };
    let summary = cold_storage_import(config_path.as_ref(), std::path::Path::new(input_dir), &opts)
        .context("cold-storage-import failed")?;

    println!(
        "cold_storage_import_completed: schema={} chain_id_hex={} low_height={} high_height={} \
         batches={} blocks={} signature_verified={} tsa_token_present={} final_tip_hash={}",
        summary.schema_version,
        summary.chain_id_hex,
        summary.low_height,
        summary.high_height,
        summary.batches_replayed,
        summary.blocks_replayed,
        summary.signature_verified,
        summary.tsa_token_present,
        summary.final_tip_hash_hex,
    );
    Ok(())
}
