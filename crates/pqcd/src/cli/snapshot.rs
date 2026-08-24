// SPDX-License-Identifier: BUSL-1.1
//! Snapshot + RocksDB migrate CLI handlers.
//!
//! Extracted from `main.rs` 2026-05-10. Four subcommands that touch
//! the chain store: snapshot-export / snapshot-import (portable
//! checkpoint round-trip), migrate-store (one-shot legacy chain-store
//! migration to RocksDB), and snapshot-prune (TASK-187a follower
//! disk reclamation).

use anyhow::{bail, Context, Result};
use pqcd::node::{migrate_store, snapshot_export, snapshot_import, snapshot_prune};

/// Export the current trusted checkpoint as a portable snapshot file.
///
/// The node must have a committed checkpoint. Fresh nodes with no checkpoint report an error.
/// The exported file can be transferred to a new follower and imported with `pqcd snapshot-import`.
pub fn cmd_snapshot_export(config_path: &str, output_path: &str) -> Result<()> {
    let (height, bytes) =
        snapshot_export(config_path.as_ref()).context("snapshot export failed")?;
    std::fs::write(output_path, &bytes)
        .with_context(|| format!("failed to write snapshot to {output_path}"))?;
    println!(
        "snapshot_exported: height={height} bytes={} path={output_path}",
        bytes.len()
    );
    Ok(())
}

/// Import a snapshot file as the trusted checkpoint for a node data directory.
///
/// The node must be stopped. On next start, the node recovers from the snapshot height
/// and tail-syncs from peers. Trust boundary: you must trust the snapshot source.
pub fn cmd_snapshot_import(config_path: &str, snapshot_path: &str) -> Result<()> {
    let bytes = std::fs::read(snapshot_path)
        .with_context(|| format!("failed to read snapshot file {snapshot_path}"))?;
    let metadata =
        snapshot_import(config_path.as_ref(), &bytes).context("snapshot import failed")?;
    println!(
        "snapshot_imported: height={} tip_hash={} state_root={}",
        metadata.height,
        hex::encode(metadata.tip_hash.0),
        hex::encode(metadata.state_root.0),
    );
    Ok(())
}

/// Migrate a legacy DiskChainStore to RocksDB (ADR-032 / TASK-103).
///
/// Reads all blocks from the flat-file store in `config.data_dir` and writes them
/// to `config.data_dir/rocksdb`.  The legacy files are preserved; remove them
/// manually after verifying the migration with `pqcd status`.
pub fn cmd_migrate_store(config_path: &str) -> Result<()> {
    migrate_store(config_path.as_ref()).context("migrate-store failed")
}

/// TASK-187a — `pqcd snapshot-prune` subcommand.
///
/// Usage:
///     pqcd snapshot-prune <node-config.json> [--keep-tail-blocks N] [--force]
///
/// Defaults: `--keep-tail-blocks 1209600` (≈ 7 days at 500 ms block time —
/// the value also pinned in the Ansible `pqcd-prune.service` unit). The
/// node MUST be stopped before invocation; the subcommand opens RocksDB
/// exclusively. On success prints a single-line `prune_completed:` summary
/// suitable for grepping out of `prune.log`.
pub fn cmd_snapshot_prune(args: &[String]) -> Result<()> {
    const DEFAULT_KEEP_TAIL_BLOCKS: u64 = 1_209_600;

    let config_path = args.get(2).context(
        "Usage: pqcd snapshot-prune <node-config.json> [--keep-tail-blocks N] [--force]",
    )?;

    let mut keep_tail_blocks: u64 = DEFAULT_KEEP_TAIL_BLOCKS;
    let mut force = false;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--keep-tail-blocks" => {
                let v = args.get(i + 1).context(
                    "--keep-tail-blocks requires a value (number of blocks to retain)",
                )?;
                keep_tail_blocks = v.parse::<u64>().with_context(|| {
                    format!("--keep-tail-blocks expected a positive integer, got '{v}'")
                })?;
                i += 2;
            }
            "--force" => {
                force = true;
                i += 1;
            }
            other => bail!(
                "unknown flag '{other}'. Usage: pqcd snapshot-prune <node-config.json> [--keep-tail-blocks N] [--force]"
            ),
        }
    }

    let stats = snapshot_prune(config_path.as_ref(), keep_tail_blocks, force)
        .context("snapshot-prune failed")?;

    println!(
        "prune_completed: blocks_deleted={} hash_index_deleted={} tx_index_deleted={} \
         siblings_deleted={} checkpoints_deleted={} checkpoints_kept={} keep_tail_blocks={}",
        stats.blocks_deleted,
        stats.hash_index_deleted,
        stats.tx_index_deleted,
        stats.siblings_deleted,
        stats.checkpoints_deleted,
        stats.checkpoints_kept,
        keep_tail_blocks,
    );
    Ok(())
}
