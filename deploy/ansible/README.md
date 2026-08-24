# Ansible Devnet Deployment — Viper PQ Chain

Provisions and deploys a 3-node Viper PQ Chain devnet (1 validator + 2 full nodes) on Ubuntu 22.04 VMs using a single command.

---

## §1 — Prerequisites

**On your local machine:**
```bash
pip install ansible        # Ansible 2.14+
ansible --version          # verify
```

**Three Ubuntu 22.04+ VMs:**
- Root SSH access from your local machine
- VMs can reach each other on port 26656 (P2P)
- Validator VM must be reachable from outside on port 26657 (API) if you want external tx submission
- Minimum specs per VM: 2 vCPU, 4 GB RAM, 40 GB disk (build is RAM-heavy)

---

## §2 — Quick Start

```bash
cd deploy/ansible

# 1. Create your inventory from the template
cp inventory/hosts.yml.example inventory/hosts.yml     # or: cp inventory/hosts.ini.example inventory/hosts.ini

# 2. Edit hosts.yml — fill in real IP addresses and repo URL
nano inventory/hosts.yml

# 3. Validate inventory syntax
make check-inventory

# 4. Deploy (first run: ~15 min due to cargo build)
make deploy

# 5. Check cluster health
make health
```

---

## §3 — What the Playbook Does

`make deploy` runs `playbooks/site.yml` which orchestrates 6 roles in order:

| Step | Role | What happens |
|------|------|-------------|
| 1 | `common` | `apt update`, installs build-essential / pkg-config / libssl-dev / git / ufw; creates `pqchain` system user; creates data and config directories |
| 2 | `rust` | Checks for Rust; installs via `rustup` if absent; adds `/root/.cargo/bin` to PATH via `/etc/profile.d/cargo.sh` |
| 3 | `build` | `git clone` (or pull) the repo to `/opt/viper-pq-chain`; `cargo build --release -p pqcd`; copies binary to `/usr/local/bin/pqcd` |
| 4 | `configure` | Computes `chain_id_hex` (UTF-8 hex of chain ID string); templates `node.json` and `pqcd.service` per role |
| 5 | `firewall` | UFW: allow SSH + P2P on all nodes; allow API port on validator only; default-deny inbound |
| 6 | `deploy` | `systemctl enable --now pqcd`; waits for validator API `/v1/status` to return 200; waits for full node P2P port to open |

---

## §4 — Verify the Cluster

```bash
# Chain status (replace with real validator IP)
curl -s http://VALIDATOR_IP:26657/v1/status | jq .

# Expected output:
# {
#   "height": 5,
#   "chain_id": "viper-devnet-1",
#   "tip_hash": "...",
#   "state_root": "..."
# }

# Prometheus metrics
curl -s http://VALIDATOR_IP:26657/v1/metrics | grep pqchain_blocks_produced

# Check logs on a node
ssh root@VALIDATOR_IP journalctl -u pqcd -f
```

---

## §5 — Commands

| Command | Description |
|---------|-------------|
| `make deploy` | Full provisioning (first-time or after code change) |
| `make deploy-only` | Config update + restart (skip build) |
| `make health` | Non-destructive cluster probe |
| `make teardown` | Stop nodes and delete all chain data |
| `make check-inventory` | Validate inventory YAML without SSH |
| `make ssh-validator` | SSH into the validator node |

---

## §6 — Configuration Reference

All variables are in `group_vars/all/defaults.yml` (shared) and `group_vars/validators.yml` / `group_vars/full_nodes.yml` (role-specific). Per-host overrides go in `inventory/hosts.yml` under each host.

| Variable | Default | Description |
|----------|---------|-------------|
| `viper_chain_id` | `viper-devnet-1` | Human-readable chain ID (hex is derived automatically) |
| `viper_repo_url` | *(set in hosts.yml)* | Git repo URL |
| `viper_repo_branch` | `main` | Branch to build from |
| `viper_data_dir` | `/var/lib/pqchain` | Root of chain data |
| `viper_config_dir` | `/etc/pqchain` | Config directory |
| `viper_binary_path` | `/usr/local/bin/pqcd` | Installed binary location |
| `viper_block_time_ms` | `500` | Target block interval in ms |
| `viper_sync_interval_ms` | `100` | Full node sync poll interval |
| `viper_p2p_port` | per-host | P2P port (26656 validator, 26666/26676 full nodes) |
| `viper_api_port` | `26657` | Public API port (validator only) |
| `viper_fee_params.*` | calibrated values | Fee model (TASK-042 Linux calibration) |

---

## §7 — Security

**WARNING — Devnet keypairs are not secret:**

The validator `commit_seed_hex` values in `group_vars/all/defaults.yml` (`1111...`, `2222...`, `3333...`) are the same seeds used in the test suite. They are public knowledge. Use them only for testing.

For a real deployment:
1. Generate keypairs offline on an air-gapped machine using `pqcd keygen`
2. Store seeds in a secrets manager (HashiCorp Vault, AWS Secrets Manager, etc.)
3. Inject seeds at deploy time via `ansible-vault` or an external secrets backend
4. Never commit seed material to git

---

## §8 — Troubleshooting

**Build fails with "linker error" or "pkg-config not found":**
```bash
# Run common role manually to ensure deps are installed
ansible-playbook playbooks/site.yml --tags common
```

**Full nodes don't sync (stuck at height 0):**
```bash
# Verify validator P2P is reachable from full node VM
ssh root@FULL_NODE_IP telnet VALIDATOR_IP 26656
# Check full node logs
ssh root@FULL_NODE_IP journalctl -u pqcd -n 50
```

**API returns 502 or times out:**
```bash
# Check if validator is actually running
ssh root@VALIDATOR_IP systemctl status pqcd
# Check for port conflicts
ssh root@VALIDATOR_IP ss -tlnp | grep 26657
```

**`make deploy` fails at the inventory validation step:**
```
# You forgot to set viper_repo_url in hosts.yml.
# Replace the example URL with your actual repo.
```

**Rust version too old (< 1.75):**
```bash
ssh root@VM rustup update stable
```

---

## §9 — Updating the Node Binary

After a code change:
```bash
# Full rebuild and redeploy
make deploy

# Or if only config changed (no code change):
make deploy-only
```

The build role uses `cargo build --release` which is incremental — unchanged crates are not recompiled.

---

## §10 — viper-pq-1 launch ceremony (TASK-205, ADR-053)

`viper-pq-1` is the permanent development chain that materialises every Tier-1 / Tier-2 / Tier-3 commitment of ADR-053 in genesis state. It supersedes the prior `viper-devnet-*` lineage and the rc1 cutover framing of TASK-168 — see DECISIONS.md ADR-053 §Consequences. From its launch onwards, breaking changes ship as ADRs with explicit activation heights (Policy P-COMPAT-001 / AGENTS.md "viper-pq-1 mainnet discipline"); there is **no reset path**.

**Files**

| Path | Role |
|------|------|
| `playbooks/launch-viper-pq-1.yml` | One-time launch ceremony (Phase 0 prereqs → Phase 6 bootstrap-peer publish). |
| `files/genesis-viper-pq-1.json` | Genesis artefact. Mirrors the ADR-053 Tier-1/2/3 state and lists every implementation commit under `_audit_provenance`. |
| `viper-pq-1-roster.json.example` | Operator roster template (`scripts/generate-bootstrap-peers.py` consumer). |

**Run the launch (after prerequisites are satisfied)**

```bash
# From the repo root:
make ansible-launch-viper-pq-1
# Or directly:
cd deploy/ansible && make launch-viper-pq-1
```

The playbook header documents every prerequisite (binary SHA-256 pin in `docs/operators/RUNBOOK.md`, key-ceremony pubkeys substituted into `genesis-viper-pq-1.json`, time-sync healthy, roster present at `/etc/pqchain/viper-pq-1-roster.json`).

**Historical note** — the `cutover-devnet-3.yml` / `rollback-devnet-3.yml` playbooks of the 2026-04-24 incident (KNOWN-ISSUES R-09) were removed from the tree on 2026-08-24; they remain in the private repository history and are not invokable from the Makefile.
