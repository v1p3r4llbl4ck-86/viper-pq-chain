// SPDX-License-Identifier: BUSL-1.1
//! `pqcd peer-id <node_id> [--salt <hex>]` — derive the deterministic
//! libp2p PeerId for a node identity, optionally bound to a 32-byte
//! `libp2p_seed_salt_hex` (per the rotation guardrail scoped in
//! the private design notes).
//!
//! Two forms:
//!
//! - `pqcd peer-id validator-1` — legacy `node_id`-only path. Reproduces
//!   the PeerId of a peer running with no `devnet.libp2p_seed_salt_hex`
//!   in its `node.json` (the pre-Stage-A.1 deployment state).
//!
//! - `pqcd peer-id validator-1 --salt <64-hex-chars>` — salted path.
//!   Reproduces the PeerId of a peer running with the matching salt set
//!   in its `node.json`. Used by the rotation cron to compute the
//!   `new_peer_id` field of a `ValidatorRotatePeerId` tx BEFORE
//!   restarting pqcd, so the on-chain binding and the live identity
//!   agree the moment the swarm reinit completes.

use anyhow::{bail, Context, Result};

pub fn cmd_peer_id(args: &[String]) -> Result<()> {
    let node_id = args
        .get(2)
        .context("Usage: pqcd peer-id <node_id> [--salt <hex64>]")?;

    let mut salt_hex: Option<String> = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--salt" => {
                salt_hex = Some(
                    args.get(i + 1)
                        .context("--salt requires a 64-char hex value")?
                        .clone(),
                );
                i += 2;
            }
            _ => bail!("unknown flag: {}", args[i]),
        }
    }

    let salt: Option<[u8; 32]> = match salt_hex {
        Some(s) => {
            let bytes = hex::decode(s.trim()).context("--salt is not valid hex")?;
            let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
                anyhow::anyhow!("--salt decoded to {} bytes; expected 32", v.len())
            })?;
            Some(arr)
        }
        None => None,
    };

    println!(
        "{}",
        pqcd::p2p::deterministic_peer_id(node_id, salt.as_ref())
    );
    Ok(())
}
