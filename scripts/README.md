# scripts/

Shell scripts for local node operation and multi-VM devnet automation.

## Status (2026-04-10)

All scripts are implemented and tested. The node binary (`pqcd`) exposes:

- `pqcd bootstrap <node.json>` — recover chain state, print tip
- `pqcd status <node.json>` — print local chain status
- `pqcd api-serve <node.json> [addr]` — start read API (default `0.0.0.0:26657`)
- `pqcd devnet-serve <node.json>` — run devnet node (validator or full node)

Real runnable configs live in `configs/` (see `configs/README.md`).

---

## Scripts

| Script | Purpose |
|--------|---------|
| `install_vm.sh` | Install apt deps, Rust toolchain, build pqcd release binary, copy to `/usr/local/bin` |
| `setup_single_node.sh` | Create data dir, install config to `/etc/pqchain/single-node.json` |
| `setup_local_devnet.sh` | Create data dirs, install validator/full-node configs to `/etc/pqchain/` |
| `run_single_node_api.sh` | Run `pqcd bootstrap` then `pqcd api-serve` (foreground) |
| `run_local_devnet.sh` | Start validator + follower-a + follower-b in background; logs to `/tmp/` |
| `stop_local_devnet.sh` | Stop background devnet nodes via PID files |
| `check_api.sh` | Curl all four `/v1/*` endpoints and report pass/fail |
| `check_devnet_convergence.sh` | Poll `/internal/p2p/status` on all three nodes; wait for tip convergence |

All scripts use `set -euo pipefail` and are safe to run more than once.

---

## Quick-start — cold start on fresh VM

```sh
# 1. Install deps + build
scripts/install_vm.sh

# 2a. Single-node path
scripts/setup_single_node.sh
pqcd bootstrap /etc/pqchain/single-node.json
scripts/run_single_node_api.sh            # foreground
scripts/check_api.sh

# 2b. Local devnet path (3 nodes)
scripts/setup_local_devnet.sh
scripts/run_local_devnet.sh               # background
sleep 3
scripts/check_devnet_convergence.sh
scripts/stop_local_devnet.sh
```

---

## Environment variable overrides

All scripts respect these variables (defaults shown):

| Variable | Default | Purpose |
|----------|---------|---------|
| `PQCD` | `pqcd` | Path to pqcd binary (e.g. `./target/release/pqcd`) |
| `PQCHAIN_DATA_DIR` | `/var/lib/pqchain/<node>` | Data directory (single-node) |
| `PQCHAIN_BASE_DATA` | `/var/lib/pqchain` | Base data directory (devnet) |
| `PQCHAIN_CONFIG_DIR` | `/etc/pqchain` | Config install directory |
| `PQCHAIN_LOG_DIR` | `/tmp` | Background log/PID file directory |
| `RUST_LOG` | `info` | Log level for devnet nodes |
| `TIMEOUT` | `30` | Seconds for convergence check |
| `MIN_HEIGHT` | `1` | Minimum height for convergence check |

Example — run entirely from repo without system install:

```sh
PQCD=./target/release/pqcd \
PQCHAIN_DATA_DIR=/tmp/pqchain/single-node \
PQCHAIN_CONFIG_DIR=/tmp/pqchain/configs \
  scripts/setup_single_node.sh

PQCD=./target/release/pqcd \
PQCHAIN_CONFIG_DIR=/tmp/pqchain/configs \
  scripts/run_single_node_api.sh
```

---

## Port model

| Port | Protocol | Purpose | Exposure |
|------|----------|---------|---------|
| 26656 | TCP | Validator P2P (`/internal/p2p/*`) | validator-to-validator only |
| 26657 | TCP | Read/status API (`/v1/*`) | internal or restricted public |
| 26660 | TCP | Metrics (reserved — not yet implemented) | operator/monitoring only |
| 26661 | TCP | Admin/operator API (reserved — not yet implemented) | localhost or VPN only |

---

## On-disk layout (per node)

```
/var/lib/pqchain/<node>/
  blocks/          # persisted block records (one CBOR file per height)
  hashes/          # hash → height index files
  staging/         # atomic write staging (must be empty at startup)
  checkpoints/     # trusted-checkpoint.cbor (latest trusted snapshot)
```

Config:   `/etc/pqchain/<node>.json` (see `configs/`)
Binary:   `/usr/local/bin/pqcd`
Logs:     via systemd journal or `/tmp/pqchain-<node>.log` (background mode)
Service:  `pqchain` Unix user (dedicated, no login shell, created by `install_vm.sh`)

---

## systemd unit (template)

```ini
[Unit]
Description=PQ Chain Node
After=network.target
Wants=network.target

[Service]
Type=simple
User=pqchain
Group=pqchain
ExecStart=/usr/local/bin/pqcd devnet-serve /etc/pqchain/producer.json
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
```

Repeat for `follower-a` and `follower-b`, changing `ExecStart` config path.

---

## Planned (not yet written)

| Script | Purpose |
|--------|---------|
| `checkpoint-backup.sh` | Copy latest trusted checkpoint to dated backup |
| `restore-checkpoint.sh` | Restore a backup checkpoint into active data dir |
| `healthcheck.sh` | Run `pqcd status` and exit non-zero if not ready |
| `ansible/roles/pqchain-node/` | Ansible role for repeatable multi-VM provisioning |
| `ansible/inventory/devnet.yml` | Devnet inventory (validator hosts, variables) |
