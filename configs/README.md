# configs/

Node configuration files for PQ Chain.

All keys, seeds, and addresses here are real deterministic values derived from the same
constants used in the integration tests (`crates/pqcd/tests/multi_node_devnet.rs`).
They are safe for local devnet use; **never use these key material values on any
externally-facing network**.

---

## Files

| File | Purpose | `devnet.role` |
|------|---------|--------------|
| `example-node.json` | Annotated template with placeholders | — |
| `single-node.json` | Single-node bootstrap/status/API (no P2P) | `single_node` |
| `producer.json` | Local devnet block producer (127.0.0.1:26656) | `validator` |
| `follower-a.json` | Local devnet follower A (127.0.0.1:26666) | `full` |
| `follower-b.json` | Local devnet follower B (127.0.0.1:26676) | `full` |
| `roles/<role>.json` | Reference example per deployment role (ADR-069): `validator`, `sentry`, `full`, `rpc`, `archive`, `bootnode` — libp2p on, `<placeholders>` to fill from genesis | one each |

`devnet.role` vocabulary (ADR-069): `single_node`, `validator`, `sentry`, `full`, `rpc`, `archive`, `bootnode`. The pre-ADR-069 names `producer` and `follower` are still read (as `validator` / `full`) but no longer written. The examples under `roles/` are what `pqcd ceremony` emits for the Helm chart, minus the chain-specific values; `crates/pqcd/src/node/tests.rs::configs_roles_examples_match_their_role` keeps them honest.

---

## Shared constants across all runnable configs

| Parameter | Value |
|-----------|-------|
| `chain_id_hex` | `7071636861696e2d6465766e65742d3031` ("pqchain-devnet-01") |
| `anchor_prev_hash_hex` | `1111...11` (32 bytes, matches integration test constant) |
| `fee_params.base_fee` | `500` |
| `fee_params.byte_fee` | `2` |
| `fee_params.sigverify_fee_v_a` | `8800` |
| `fee_params.sigverify_fee_v_b` | `14000` |
| `fee_params.sigverify_fee_v_c` | `810000` |
| `fee_params.exec_fee_per_gas` | `43` |
| Genesis account address | `2ce8e8b8ae95ccd2dc258e8f310af5de4c058bf544041b9460afc7e96b583f7d` |
| Genesis account public key | ML-DSA-65 key derived from seed `[0x11; 32]` (validator-1 seed) |
| `proposer_address_hex` | `9999...99` (producer only, matches test constant) |

Fee values are calibrated from Linux reference node benchmarks (TASK-042, 2026-04-11).
`exec_fee_per_gas = 43` matches the 43.3 units/µs calibration rate used for sigverify fees.
Per-operation gas costs are in `pqc-state::gas_schedule` (TASK-007).

---

## Validator set (devnet only)

The producer and follower configs share a static 3-validator commit set.
Commit quorum = 2 out of 3 (default ⌈2/3⌉ + 1 of 3).

| Validator | `address_hex` | `sig_alg_id` | Seed (producer only) | Derived address |
|-----------|--------------|-------------|----------------------|----------------|
| validator-1 | `a1a1...a1` | 2 (ML-DSA-65) | `1111...11` | `2ce8e8b8...` |
| validator-2 | `a2a2...a2` | 2 (ML-DSA-65) | `2222...22` | `2539a88d...` |
| validator-3 | `a3a3...a3` | 2 (ML-DSA-65) | `3333...33` | `9e57adc8...` |

`commit_seed_hex` is only present in `producer.json`.
Followers carry `public_key_hex` for signature verification but no seeds.

All nodes in a devnet cluster MUST use the same `fee_params`. Replay, block import,
and `state_root` derivation depend on fee accounting, so mismatched fee configs will
cause follower rejection or bootstrap mismatch.

---

## Quick-start commands (from repo root after `cargo build --release`)

### Single-node bootstrap + API

```sh
# Create data directory and install config (first time)
scripts/setup_single_node.sh

# Bootstrap + status
./target/release/pqcd bootstrap /etc/pqchain/single-node.json
./target/release/pqcd status    /etc/pqchain/single-node.json

# Start read API on 0.0.0.0:26657
scripts/run_single_node_api.sh

# Check API
scripts/check_api.sh
```

### Local 3-node devnet

```sh
# Create data directories and install configs (first time)
scripts/setup_local_devnet.sh

# Start producer + two followers in background
scripts/run_local_devnet.sh

# Wait ~3 seconds, then verify convergence
scripts/check_devnet_convergence.sh

# Stop all nodes
scripts/stop_local_devnet.sh
```

---

## Using configs from a non-default install location

All scripts respect environment variables:

```sh
PQCHAIN_DATA_DIR=/data/pqchain/single-node \
PQCHAIN_CONFIG_DIR=/opt/pqchain/config \
PQCD=/opt/pqchain/bin/pqcd \
  scripts/setup_single_node.sh
```

---

## System paths (default VM install)

| Path | Purpose |
|------|---------|
| `/usr/local/bin/pqcd` | Node binary (installed by `scripts/install_vm.sh`) |
| `/etc/pqchain/*.json` | Config files (installed by setup scripts) |
| `/var/lib/pqchain/<node>/` | Per-node chain data (blocks, checkpoints, indexes) |
| `/tmp/pqchain-<node>.log` | Log file when started via `run_local_devnet.sh` |
| `/tmp/pqchain-<node>.pid` | PID file for background processes |

---

## External operator — public testnet

The shipped configs (`single-node.json`, `producer.json`, `follower-*.json`) are **local devnet configs** derived from public test seeds. **Never use these key material values on any externally-facing network.**

### Fields that MUST be changed for a real testnet

| Field | Local devnet value | What to set instead |
|-------|--------------------|---------------------|
| `chain_id_hex` | `7071636861696e2d6465766e65742d3031` ("pqchain-devnet-01") | A unique hex-encoded name for your network, e.g. `python3 -c "print('mynet-01'.encode().hex())"`. All nodes in the same cluster must use the same value. |
| `anchor_prev_hash_hex` | `1111...11` | `0000...00` (64 hex zeros) for a fresh genesis. |
| `data_dir` | relative test path | Absolute path on the VM, e.g. `/var/lib/pqchain/producer`. |
| `genesis_accounts[].address_hex` | Test address derived from seed `[0x11;32]` | Your real SHAKE-256(pk_bytes, 32) address from a secure ML-DSA-65 keypair. |
| `genesis_accounts[].public_key_hex` | Test public key derived from `[0x11;32]` | Your real ML-DSA-65 public key bytes (hex). |
| `devnet.proposer_address_hex` | `9999...99` (producer only) | Your real proposer address (hex). |
| `devnet.validators[].address_hex` | `a1a1...a1`, `a2a2...a2`, `a3a3...a3` | Real validator addresses. |
| `devnet.validators[].public_key_hex` | Test public keys derived from `[0x11;32]`, `[0x22;32]`, `[0x33;32]` | Real ML-DSA-65 public keys (hex). |
| `devnet.validators[].commit_seed_hex` | Public test seeds (producer.json only) | Real 32-byte secret seeds. **Keep these confidential; do not commit to git.** |

### Fields that are safe to keep

| Field | Reason |
|-------|--------|
| `fee_params.*` | Calibrated from Linux 6.8 reference benchmarks (TASK-042). Re-benchmark only if your hardware differs significantly from the reference. |
| `devnet.block_time_ms` | 500 ms is appropriate for testnet. |
| `devnet.sync_interval_ms` | 100 ms is appropriate for LAN; increase to 500–1000 ms for WAN followers. |

### Mandatory uniformity across all cluster nodes

The following fields **must be byte-for-byte identical** across all nodes in a cluster. A mismatch causes state root divergence and block rejection:

- `chain_id_hex`
- `anchor_prev_hash_hex`
- `genesis_accounts` (the entire array, same order)
- `fee_params` (all six fields)
- `devnet.validators` (same set, same order; producer adds `commit_seed_hex`, followers do not)

### Snapshot cold-start for follower nodes

To cold-start a follower from a peer's checkpoint instead of replaying from genesis, add `"snapshot_source"` to the follower's `devnet` section:

```json
"devnet": {
  "role": "full",
  "snapshot_source": "10.0.0.1:26656",
  ...
}
```

On first start with an empty `data_dir`, the follower downloads the source peer's checkpoint and tail blocks via the ML-KEM-768 authenticated P2P endpoint, then continues normal tail-sync. After the first successful start, the local checkpoint exists and `snapshot_source` is ignored on subsequent restarts.

**Trust boundary**: you must trust the `snapshot_source` operator. The node validates the snapshot's internal CBOR structure and state_root consistency but does not re-execute all pre-snapshot blocks.

Operator manual path: `pqcd snapshot-export <config> <output-file>` and `pqcd snapshot-import <config> <snapshot-file>`. See `docs/operators/RUNBOOK.md` §14 for the full guide.

### Known provisional behaviors (Phase 3)

- **Fee distribution**: 100% of collected fees go to the block proposer. Validator pool split is deferred (ADR-019). See `specs/token-utility.md §5` for the formal Phase 3 exception.
- **Validator lifecycle**: static config only; no on-chain staking or bonding.
- **`pqcd validate-tx`**: debug diagnostic tool; uses stub verifier. Not a production admission check.

See `docs/operators/RUNBOOK.md` §11 for the full external operator bootstrap guide.
