# Viper PQ Chain — Operator Runbook

How to build, configure, run, join and troubleshoot a `pqcd` node.

Licensed CC BY 4.0 (see `LICENSE.md`). The node binary is source-available under
BUSL-1.1; the verification-path crates are Apache-2.0. Host names in examples are
placeholders (`<host>`, `203.0.113.x`).

There is no live public network at the time of writing. The public chain
`viper-testnet-2` is created with `pqcd ceremony` after the public release; the
endpoints named in §11 exist at genesis, not before. Everything else in this
runbook works today on a laptop.

## Contents

- [1. Prerequisites and build](#1-prerequisites-and-build)
- [2. Node roles and reference configurations](#2-node-roles-and-reference-configurations)
- [3. Configuration reference (`node.json`)](#3-configuration-reference-nodejson)
- [4. Quick start: single node](#4-quick-start-single-node)
- [5. Local devnet: one validator + two full nodes](#5-local-devnet-one-validator--two-full-nodes)
- [6. Verify the read API](#6-verify-the-read-api)
- [7. Logging](#7-logging)
- [8. Shutdown and restart](#8-shutdown-and-restart)
- [9. On-disk layout](#9-on-disk-layout)
- [10. Running as a service](#10-running-as-a-service)
- [11. Joining a network as an external operator](#11-joining-a-network-as-an-external-operator)
- [12. Starting your own network](#12-starting-your-own-network)
- [13. Metrics and basic alerting](#13-metrics-and-basic-alerting)
- [14. State sync: snapshot export, import and cold start](#14-state-sync-snapshot-export-import-and-cold-start)
- [15. Pruning and cold storage](#15-pruning-and-cold-storage)
- [16. Consensus-key rotation](#16-consensus-key-rotation)
- [17. Troubleshooting](#17-troubleshooting)
- [18. Ports and firewall summary](#18-ports-and-firewall-summary)
- [19. Useful cargo commands](#19-useful-cargo-commands)
- [Appendix A. `pqcd` command reference](#appendix-a-pqcd-command-reference)

---

## 1. Prerequisites and build

Hardware for a local devnet or a full node: 2 CPU cores, 4 GiB RAM (the build is
RAM-hungry), 40 GiB disk. A validator on a real network needs far more disk: at
500 ms block time every block carries ~3.3 KB of ML-DSA-65 commit signature per
validator, so even an empty chain grows by several GB a day. Size validator and
archive storage for indefinite retention; full and rpc nodes prune (§15).

Toolchain: Rust as pinned in `rust-toolchain.toml` (1.92.0); `rustup` selects it
on the first `cargo` invocation inside the repository.

```sh
# Debian / Ubuntu build dependencies (RocksDB is compiled from source)
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev clang cmake git curl python3 jq

git clone <repo-url> viper-pq-chain
cd viper-pq-chain
cargo build --release -p pqcd --bin pqcd        # release build — use it for every real run
./target/release/pqcd version                   # "pqcd <version>"
sudo install -m 0755 target/release/pqcd /usr/local/bin/pqcd
```

`scripts/install_vm.sh` does the same on a fresh Ubuntu host (packages, rustup,
release build, copy to `/usr/local/bin/pqcd`, `pqchain` system user).

Reproducibility: a release is a git tag; rebuild from the tag with the pinned
toolchain and compare `sha256sum target/release/pqcd` with the value in the
release notes before deploying a binary you did not build.

Quality gates: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets
--all-features -- -D warnings`, `cargo test --workspace --all-features` (add
`-- --test-threads=1` on small machines: the multi-node tests are load-sensitive),
`cargo deny check`, `scripts/check-licenses.sh`.

---

## 2. Node roles and reference configurations

A node's role is the `devnet.role` string in `node.json`. The same words are used
by the Helm chart and by `pqcd ceremony` (ADR-069).

| Role | What it does | API | libp2p listen key | Dials |
|---|---|---|---|---|
| `single_node` | Local quick start: one process is the whole chain. No validator set, no transport. | optional | — | nobody |
| `validator` | Signs and proposes blocks; holds the consensus key in `devnet.keystore_path`. API private by contract. | private | `validator_listen` | nobody (sentries dial it) |
| `sentry` | Bridge between the validator and the public network: dials the validator, relays gossip, never signs. | public | `vfn_listen` | the validator |
| `full` | Validates everything, signs nothing, serves the read API. | public | `public_listen` | sentries / bootnode |
| `rpc` | A full node whose only job is the public read API; scale horizontally. | public | `public_listen` | sentries / bootnode |
| `archive` | Full node that keeps the whole history and feeds `viper-archival-sidecar`; `snapshot-prune` refuses it. | public | `public_listen` | sentries / bootnode |
| `bootnode` | DNS-stable seed peer: public P2P only, private API. | private | `public_listen` | sentries |

The pre-ADR-069 names `producer` and `follower` are still read (as `validator`
and `full`) but never written.

| File | Purpose |
|---|---|
| `configs/roles/<role>.json` | One annotated example per role, libp2p on, `<placeholders>` to fill from genesis. What `pqcd ceremony` emits for the chart, minus the chain-specific values. |
| `configs/single-node.json` | Single node, no P2P (§4). |
| `configs/producer.json` | Local devnet validator (`role: validator`, `127.0.0.1:26656`). |
| `configs/follower-a.json`, `configs/follower-b.json` | Local devnet full nodes (`role: full`, ports 26666 / 26676). |
| `configs/example-node.json` | Field-by-field annotated template. |

The local devnet files carry public, deterministic test seeds. Never reuse their
key material on a reachable network.

Two P2P transports exist. The local devnet (§5) uses the legacy HTTP transport
(`p2p_listen_addr` + `peers[]`, `/internal/p2p/*`, ML-KEM-768 sessions). Every
real deployment uses libp2p (`libp2p.enable: true`): TCP with TLS 1.3 (hybrid
X25519MLKEM768 when built with `hybrid-kem-tls`), GossipSub for blocks, votes and
transactions, request/response for block fetch and snapshots. With libp2p on,
`p2p_listen_addr` may be `null`.

---

## 3. Configuration reference (`node.json`)

Top level:

| Key | Meaning |
|---|---|
| `node_id` | Unique name of this node. Feeds the deterministic libp2p PeerId (`pqcd peer-id <node_id>`). `$VIPER_NODE_ID` overrides it at start-up (the chart sets it from the pod name). |
| `chain_id_hex` | Hex of the chain id string, e.g. `python3 -c "print('viper-testnet-2'.encode().hex())"`. Identical on every node; every transaction must carry it. |
| `anchor_prev_hash_hex` | 32-byte genesis anchor. `0000…0000` for a fresh genesis; identical on every node. |
| `data_dir` | Absolute path; the RocksDB store lives in `<data_dir>/rocksdb`. Distinct per node on a shared host. |
| `fee_params` | `base_fee`, `byte_fee`, `sigverify_fee_v_a/_b/_c`, `exec_fee_per_gas`. Byte-for-byte identical on every node or `state_root` diverges at the first block. |
| `genesis_accounts[]` | Initial account state: `address_hex`, `balance`, `nonce`, `keys[]` (`alg_id`, `pk_hex`, `key_version`, `valid_from_height`, `status`, `allowed_tx_types`). Identical on every node. |
| `api_listen_addr` | `"0.0.0.0:26657"` to serve the HTTP API; absent = no API server. Validators and bootnodes bind `127.0.0.1:26657`. |
| `p2p_listen_addr`, `peers[]` | Legacy HTTP transport (local devnet only). `peers[].node_id` must equal the peer's top-level `node_id`. |
| `rate_limit` | Per-IP limit on `POST /v1/txs`: `max_requests_per_window` (100), `window_secs` (60). `0` disables. |
| `sender_budget` | Per-sender admission budget: `max_txs_per_window` (50), `window_secs` (60). `0` disables. |
| `api.public_tx_submission` | Register `POST /v1/txs`. Default true; `false` on validators and bootnodes (a start-up warning names a mismatch). |
| `api.expose_token_state` | Register `/v1/accounts/*` and `/v1/fee-market`. `false` on a tokenless chain. |
| `api.expose_notary_routes` | Register the `/api/credentials/*` and `/api/proofs/*` overlay. |

`devnet` object:

| Key | Meaning |
|---|---|
| `role` | One of the seven roles in §2. |
| `block_time_ms` | Block interval; 500 ms in every shipped config. |
| `sync_interval_ms` | Catch-up poll interval for non-validators; 100 ms on a LAN, 500–1000 ms across the internet. |
| `proposer_address_hex` | Fee recipient / proposer identity. |
| `validators[]` | Static validator set: `node_id`, `address_hex`, `sig_alg_id` (2 = ML-DSA-65), `public_key_hex`, optional `commit_seed_hex` (local devnet validator only) and `archival_sk_hex`. Same set and order on every node. |
| `quorum_threshold` | Commit quorum; defaults to ⌈2N/3⌉ + 1. Do not lower it. |
| `keystore_path` | Validator only: JSON file with the operator's own signing seed (§11.4). Re-read once per block (mtime-gated), so entries can be added without a restart. |
| `distributed_signing` | `true` on every validator of a multi-operator network: each node signs precommits only with its own seed and the proposer waits `distributed_signing_quorum_wait_ms` (default 1500 = 3 × block time) for a quorum. All validators must agree on this flag. `pqcd ceremony` sets it. |
| `epoch_duration`, `unbonding_period` | In blocks (60 / 120 in the examples). |
| `snapshot_source` | Legacy-transport cold start: `"host:port"` of a peer to download a checkpoint from (§14). |
| `libp2p_seed_salt_hex` | 32-byte secret (`openssl rand -hex 32`) mixed into the libp2p identity derivation. Without it the PeerId is recoverable from the public `node_id`; the node starts but warns. Set it on every real node. |
| `kem_seed_salt_hex` | Same idea for the legacy transport's ML-KEM identity (`pqcd wallet kem-init --node-config <path>`). |
| `signer_kind`, `signer_config` | Signing backend; default `LocalKeystore`. SoftHSM/HSM backends live in `pqc-hsm`; the two fields must agree. |

`libp2p` object:

| Key | Meaning |
|---|---|
| `enable` | Master switch. |
| `validator_listen` / `vfn_listen` / `public_listen` | `"ip:port"` for the network this role joins (§2 table). Only the field matching the role is read; the listener is announced as `/ip4/<ip>/tcp/<port>`. |
| `bootstrap_peers[]` | Multiaddrs **with** the `/p2p/<PeerId>` suffix, e.g. `/dns4/<host>/tcp/26656/p2p/12D3Koo…`. Redialed every 15 s while disconnected. |
| `quic_enabled`, `tcp_tls_fallback` | Transport selection; the reference configs run TCP only (`quic_enabled: false`). |
| `max_peers_per_asn` | Anti-eclipse diversity limit (3). |
| `gossip_mesh_n`, `_low`, `_high` | GossipSub mesh size; leave the defaults. |
| `validator_peer_ids[]` | Base58 PeerIds whose transaction gossip is admissible on the validator network. Empty = check off (§17.7). |

Must be byte-for-byte identical across a network: `chain_id_hex`,
`anchor_prev_hash_hex`, `fee_params`, `genesis_accounts`, `devnet.validators`
(minus the private seed fields), `devnet.block_time_ms`, `devnet.epoch_duration`,
`devnet.unbonding_period`.

Secrets in `node.json` (`commit_seed_hex`, `archival_sk_hex`, the salts): mode
`0600`, owned by the service user, never committed.

Environment: `VIPER_NODE_ID` (overrides `node_id`), `VIPER_PASSPHRASE` (keystore
passphrase for `wallet`/`keygen`), `VIPER_CHAIN_ID` (hex chain id for wallet
commands), `VIPER_AUDIT_LOG_DIR` (default `/var/log/pqchain/audit`), `RUST_LOG`.

---

## 4. Quick start: single node

```sh
scripts/setup_single_node.sh          # data dir /var/lib/pqchain/single-node + /etc/pqchain/single-node.json

pqcd bootstrap /etc/pqchain/single-node.json     # recover state (genesis on first run), print the tip
# BOOTSTRAP_OK
# status:          ready
# config:          /etc/pqchain/single-node.json
# data_dir:        /var/lib/pqchain/single-node
# chain_height:    0
# tip_hash:        …
# state_root:      …
# accounts:        1
# recovery_source: full_replay
# checkpoint:      none

pqcd status /etc/pqchain/single-node.json        # same report without BOOTSTRAP_OK
pqcd api-serve /etc/pqchain/single-node.json     # read-only API, foreground, default 0.0.0.0:26657
pqcd api-serve /etc/pqchain/single-node.json 127.0.0.1:8080
scripts/run_single_node_api.sh                   # bootstrap + api-serve
```

The scripts honour `PQCD`, `PQCHAIN_DATA_DIR`, `PQCHAIN_BASE_DATA`,
`PQCHAIN_CONFIG_DIR`, `PQCHAIN_LOG_DIR` and `RUST_LOG` (`scripts/README.md`), so
nothing has to be installed under `/etc` or `/var`.

`api-serve` is a read-only server over a stopped node's store. A running
`devnet-serve` node serves the same API itself when `api_listen_addr` is set.

---

## 5. Local devnet: one validator + two full nodes

`configs/producer.json` (role `validator`) produces blocks; `follower-a.json` and
`follower-b.json` (role `full`) import them over the legacy HTTP transport.

```sh
scripts/setup_local_devnet.sh          # data dirs + configs under /etc/pqchain
scripts/run_local_devnet.sh            # background; logs in /tmp/pqchain-{producer,follower-a,follower-b}.log
sleep 3
scripts/check_devnet_convergence.sh    # waits until all three report the same tip
scripts/stop_local_devnet.sh
# manual start, one terminal each:
RUST_LOG=info pqcd devnet-serve /etc/pqchain/producer.json      # then follower-a.json, follower-b.json
```

Convergence check by hand (26656 / 26666 / 26676 are the three legacy P2P
listeners):

```sh
for PORT in 26656 26666 26676; do
  printf 'port %s -> ' "$PORT"
  curl -sf "http://127.0.0.1:$PORT/internal/p2p/status" \
    | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["node_id"], "h=%d" % d["height"], "tip=%s…" % d["tip_hash"][:16])'
done
# port 26656 -> producer h=42 tip=3f9a…
# port 26666 -> follower-a h=42 tip=3f9a…
# port 26676 -> follower-b h=42 tip=3f9a…
```

Identical tip hashes = converged. `curl -s http://127.0.0.1:26656/internal/p2p/blocks/1`
returns block 1 as CBOR.

The producer config carries all three validator seeds, so it signs the whole
quorum itself. That is the single-operator devnet shortcut; a real network uses
`distributed_signing` and one seed per operator.

---

## 6. Verify the read API

```sh
BASE=http://127.0.0.1:26657
scripts/check_api.sh                                  # or by hand:
curl -s $BASE/v1/status | jq .
# { "height": 128, "chain_id": "pqchain-devnet-01", "state_root": "…", "tip_hash": "…",
#   "node_id": "producer", "syncing": false, "base_fee": 500, "epoch_number": 2, "epoch_length_blocks": 60 }
curl -s $BASE/v1/network | jq .
curl -s $BASE/v1/blocks/latest | jq .
curl -s $BASE/v1/txs/$(printf '%064d' 0)            # 404 for an unknown hash
curl -s $BASE/v1/validators | jq .
curl -s $BASE/v1/accounts/2ce8e8b8ae95ccd2dc258e8f310af5de4c058bf544041b9460afc7e96b583f7d | jq .
#   ^ genesis account of the local devnet configs (only when api.expose_token_state is on)
curl -s $BASE/api/health ; curl -s $BASE/openapi.yaml | head    # human docs at $BASE/docs
```

Submitting a transaction (nodes with `api.public_tx_submission: true`):

```sh
curl -s -X POST $BASE/v1/txs -H 'Content-Type: application/json' \
  -d '{"encoding":"cbor-base64","tx_bytes":"<base64url of the signed canonical CBOR>"}'
# admitted:  {"data":{"tx_hash":"<hex>","status":"pending","min_fee_used":"…"}}
# rejected:  {"error":{"code":"INSUFFICIENT_FEE","message":"…","details":{…}}}
```

Poll `GET /v1/txs/{hash}` until `"status":"finalized"`. `API.md` lists endpoints
and error codes; `pqcd wallet send` builds and submits a transfer. `pqcd
validate-tx <hex>` only decodes an envelope — a diagnostic, not an admission check.

---

## 7. Logging

`pqcd` logs through `tracing`; the level comes from `RUST_LOG` (default `info`):
`RUST_LOG=debug`, `RUST_LOG=info,pqcd::p2p=trace`, `RUST_LOG=off`. Targets:
`pqcd::devnet` (consensus loop), `pqcd::p2p` (gossip, block fetch, snapshot
fetch), `pqcd::api`, `pqcd::keystore`, `pqc_consensus::*`, `viper.audit`.

| Line | Meaning |
|---|---|
| `bootstrap complete` … `recovery_source=` | Start-up summary (`full_replay` or `trusted_checkpoint`). |
| `block persisted` | A block was committed (`height=`, `tip_hash=`, `included=`). |
| `block imported from peer` | A non-validator applied a peer's block. |
| `listening on /ip4/…/tcp/26656` | libp2p listener bound. |
| `libp2p peer connected` / `libp2p peer disconnected` | Mesh membership changes (`peers_connected=`). |
| `bootstrap peer redial (periodic)` | The 15 s redial loop is trying a disconnected bootstrap peer. |
| `libp2p cold-start failed — falling back to genesis replay` | No peer served a snapshot; genesis replay instead (§14). |
| `peer sync failed` | Legacy-transport catch-up error (`peer=`, `error=`). |
| `node_id overridden by $VIPER_NODE_ID` | The environment took precedence over `node.json`. |
| `role does not serve public transaction submission but api.public_tx_submission is true` | Start-up lint: front this node with a sentry or an rpc node. |
| `three-network lint: validator-class role with a publicly-bound libp2p.public_listen` | Start-up lint: a validator binds `validator_listen` only (§11.3). |

`block_hash=<hex>` is the correlation id: grep it to follow one block through
proposal, gossip, precommits and commit on every host. Under systemd:
`journalctl -u pqcd -f`, `journalctl -u pqcd -n 200 --no-pager`,
`journalctl -u pqcd -p warning --since "10 min ago"`, `journalctl -u pqcd -o json`.

A hash-chained audit log (`audit-YYYYMMDD.jsonl`) is written to
`/var/log/pqchain/audit` (`VIPER_AUDIT_LOG_DIR`); the directory must be writable
by the service user. `docs/observability.md` covers logs, metrics, audit log and
local alerts in depth.

---

## 8. Shutdown and restart

- Foreground: Ctrl-C (SIGINT). Background: `kill -TERM $(pgrep pqcd)` or
  `scripts/stop_local_devnet.sh` (PID files in `/tmp`). Both are graceful.
- systemd: `sudo systemctl restart pqcd`. State is on disk; a restart replays from
  the last checkpoint plus the tail and rejoins the mesh. Peers redial a restarted
  bootstrap peer within ~15 s; a restarted validator is back in quorum after its
  first precommit.
- `kill -KILL` is safe for the RocksDB store (WAL) but means a longer replay. If
  the node then refuses to start, see §17.2.
- Rolling restarts across a validator set: one node at a time; wait for
  `pqchain_p2p_peers_connected` to recover and the height to advance before the
  next one.

---

## 9. On-disk layout

```
<data_dir>/rocksdb/        # chain store: blocks, hash index, tx index, checkpoints, tip metadata
/var/log/pqchain/audit/    # audit-YYYYMMDD.jsonl (hash-chained)
/etc/pqchain/node.json     # configuration (mode 0600 if it carries secrets)
/etc/pqchain/keystore.json # validator signing seed(s), mode 0600 (§11.4)
```

The trusted checkpoint is written inside the store after commits; it is a local
acceleration only. Deleting `rocksdb/` on a non-validator forces a snapshot cold
start or a full replay from genesis — safe, only slow.

Stores created by very old binaries used a file-per-block layout (`blocks/`,
`hashes/`, `checkpoints/`, `staging/`, `tip.cbor`); `pqcd migrate-store <node.json>`
converts one to `rocksdb/` (verify with `pqcd status`, then remove the old files).

`snapshot-export/import/prune`, `cold-storage-export/import`, `migrate-store`,
`bootstrap`, `status` and `api-serve` open the store exclusively: stop the node first.

---

## 10. Running as a service

### 10.1 systemd (Linux hosts)

`/etc/systemd/system/pqcd.service`, one unit per node:

```ini
[Unit]
Description=Viper PQ Chain node (full-1)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=pqchain
Group=pqchain
ExecStart=/usr/local/bin/pqcd devnet-serve /etc/pqchain/node.json
Restart=on-failure
RestartSec=5
LimitNOFILE=65535
MemoryMax=4G
OOMPolicy=stop
Environment=RUST_LOG=info
Environment=VIPER_NODE_ID=full-1
StandardOutput=journal
StandardError=journal
ReadWritePaths=/var/lib/pqchain /etc/pqchain /var/log/pqchain/audit
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

```sh
sudo useradd --system --home /var/lib/pqchain --shell /usr/sbin/nologin pqchain
sudo mkdir -p /var/lib/pqchain /etc/pqchain /var/log/pqchain/audit
sudo chown -R pqchain:pqchain /var/lib/pqchain /var/log/pqchain
sudo systemctl daemon-reload && sudo systemctl enable --now pqcd
journalctl -u pqcd -f
```

The Ansible tree under `deploy/ansible` installs exactly this — packages, Rust,
build, `node.json` from the role template, the unit above, a UFW policy, timers
for weekly pruning and monthly cold-storage export. `make deploy` runs
`playbooks/site.yml` against your inventory, `make health` the non-destructive
check. The shipped inventories are examples only.

### 10.2 Kubernetes (Helm chart)

`charts/viper-pq-chain` (0.3.0) templates one StatefulSet per enabled role. A
new chain is created with `pqcd ceremony`, which generates genesis, validator
secrets and one `node.json` per role into a values file:

```sh
pqcd ceremony --chain-id viper-testnet-2 --validators 3 --block-time-ms 500 \
  --namespace viper --release-name viper \
  --image-repository <your-registry>/pqcd --image-tag <tag> \
  --output values-ceremony.json --secrets-output secrets-ceremony.yaml
kubectl create namespace viper
kubectl apply -n viper -f secrets-ceremony.yaml
helm install viper ./charts/viper-pq-chain -n viper -f values-ceremony.json
kubectl get pods,svc -n viper -l app.kubernetes.io/instance=viper
helm test viper -n viper
```

Every pod runs with `VIPER_NODE_ID` = its pod name, so replicas of one role have
distinct identities and `pqcd peer-id <pod-name>` gives their PeerIds. The chart
refuses values generated for another release name or namespace (the bootstrap
multiaddrs embed both). PVCs survive `helm uninstall`. Details:
`charts/viper-pq-chain/README.md`.

### 10.3 Docker

`docker/pqcd.Dockerfile` builds a non-root image; run it as
`pqcd devnet-serve /etc/pqchain/node.json` with `node.json` and a data volume
mounted (`docker/README.md`).

---

## 11. Joining a network as an external operator

This section describes joining `viper-testnet-2`, the public network to be created
at genesis after the public release. Until then the endpoints below do not
resolve; the procedure is the same for any chain started per §12.

| Purpose | Address (at genesis) |
|---|---|
| Explorer / status | `https://pqchain.agwswebconsulting.it` |
| Read API | `pqchain.agwswebconsulting.it/v1/…` (port 26657, `/v1/*`) |
| P2P seed (bootnode) | `boot1.pqchain.agwswebconsulting.it:26656` |

### 11.1 Choose a role

Start as `full` (or `rpc` to serve reads only, `archive` for the whole history
plus the RFC 3161 sidecar). Validators are admitted by the operators of the
network (proof of authority, operator-run validator set): run a full node first,
then ask.

### 11.2 Prepare and start the node

```sh
sudo install -d -m 0750 -o pqchain -g pqchain /var/lib/pqchain /etc/pqchain
cp configs/roles/full.json /etc/pqchain/node.json
```

Fill in, from the network's published genesis bundle:

- `chain_id_hex`, `anchor_prev_hash_hex`, `fee_params`, `genesis_accounts`,
  `devnet.validators`, `devnet.block_time_ms`, `devnet.epoch_duration`,
  `devnet.unbonding_period` — copy verbatim.
- `node_id` — your own label (`full-<org>-1`).
- `devnet.libp2p_seed_salt_hex` — `openssl rand -hex 32`.
- `libp2p.public_listen` — `"0.0.0.0:26656"`.
- `libp2p.bootstrap_peers` — the seed(s) published with the genesis, e.g.
  `/dns4/boot1.pqchain.agwswebconsulting.it/tcp/26656/p2p/<bootnode-peer-id>`.
  A multiaddr without the `/p2p/<PeerId>` suffix is rejected at start-up.
- `api_listen_addr` — `"0.0.0.0:26657"` if you serve reads, `"127.0.0.1:26657"`
  otherwise.

```sh
pqcd bootstrap /etc/pqchain/node.json          # BOOTSTRAP_OK, chain_height 0
sudo systemctl enable --now pqcd               # §10.1
journalctl -u pqcd -f
```

Expected within a minute: `listening on /ip4/0.0.0.0/tcp/26656`, `libp2p peer
connected … peers_connected=1`, then a snapshot cold start (§14) or `block
imported from peer` lines, and `pqchain_chain_height` climbing to the network tip:

```sh
curl -s http://127.0.0.1:26657/v1/status | jq '.height, .chain_id'
curl -s http://127.0.0.1:26657/v1/metrics | grep -E '^pqchain_(chain_height|p2p_peers_connected) '
```

Open inbound TCP 26656 to the world (so other nodes can dial you) and 26657 only
to whoever should read your API; put TLS in front of 26657 (nginx, caddy) if you
expose it publicly.

### 11.3 Validator topology

A validator never binds a public address:

```
public internet ──► sentry (vfn_listen, no keys) ──► validator (validator_listen, keys)
                    sentry ──────────────────────────┘
full / rpc / archive / bootnode dial the sentries (public_listen)
```

- Validator: `configs/roles/validator.json`; `libp2p.validator_listen` on the
  private subnet, `bootstrap_peers` empty (sentries dial it), `api_listen_addr`
  on loopback, `api.public_tx_submission: false`.
- Sentries (at least two, on different providers and ASNs):
  `configs/roles/sentry.json`; `vfn_listen` public, `bootstrap_peers` = the
  validator's multiaddr on the private network.
- Everything else points at the sentries.

`pqcd` warns at start-up if a validator-class role has a publicly bound
`public_listen` (§7); binding it to `127.0.0.1` is the explicit opt-in for one
test host. Verify with `ss -tnlp | grep -E ':2665[67]'`: a validator shows only
its private P2P bind and `127.0.0.1:26657`.

### 11.4 Validator keys and keystore

```sh
VIPER_PASSPHRASE='<strong passphrase>' \
  pqcd wallet create --alg ml-dsa-65 --chain-id <chain_id_hex> --output /etc/pqchain/operator-keystore.json
# prints the mnemonic once, the address (hex + bech32m) and the public key
pqcd wallet address     /etc/pqchain/operator-keystore.json
pqcd wallet public-key  /etc/pqchain/operator-keystore.json
pqcd wallet export-seed /etc/pqchain/operator-keystore.json     # Seed (hex): 64 hex chars
```

`pqcd keygen --alg ml-dsa-65 --chain-id <hex> --output <file>` is the
non-interactive equivalent; `pqcd keystore verify <file>` parses a keystore with
the production loader. The node reads its signing seed from `devnet.keystore_path`:

```json
{ "validators": [ {
    "address_hex": "<your operator address>",
    "sig_alg_id": 2,
    "commit_seed_hex": "<32-byte seed from export-seed>",
    "archival_sk_hex": "<optional SLH-DSA-SHAKE-256s sk from pqcd wallet archival-keygen>"
} ] }
```

`chmod 0600`, owned by the service user. At load the derived public key is
checked against the validator's entry; a mismatch fails start-up with
`commit_seed_hex does not match public_key_hex`.

Give the network's operators your `address_hex`, `public_key_hex` and, for the
allow-list (§17.7), your PeerId: `pqcd peer-id <node_id> --salt <libp2p_seed_salt_hex>`.
The on-chain registration (`pqcd wallet register-validator`) and the optional
archival key (`pqcd wallet archival-keygen`, `archival-register`) are described in
`docs/validator-onboarding.md`. The validator becomes active at the next epoch
boundary; check `GET /v1/validators`.

---

## 12. Starting your own network

Kubernetes: `pqcd ceremony` (§10.2) does the whole job — keys, genesis, one
`node.json` per role, secrets — and prints the validator cohort to stderr for
your records. Bare hosts: build the same artefacts by hand.

1. One keystore per validator (§11.4); collect `address_hex` and `public_key_hex`.
2. `chain_id_hex` = hex of your chain name; `anchor_prev_hash_hex` = 64 zeros.
3. `devnet.validators[]` = the cohort (public fields only), identical on every
   node; `devnet.distributed_signing: true` and `keystore_path` on each validator.
4. `genesis_accounts[]` as your chain requires (a tokenless chain still needs the
   operator accounts with their keys).
5. `fee_params` — keep the values from `configs/roles/*.json` unless you have
   re-benchmarked (`specs/fee-model.md`).
6. One `configs/roles/<role>.json`-derived `node.json` per host, a
   `libp2p_seed_salt_hex` per node; sentries' `bootstrap_peers` = validators,
   everything else = sentries / bootnode.
7. Bring up validators, then sentries, then the public roles. Verify `/v1/status`
   on every API-serving node (same `tip_hash` at the same height) and
   `pqchain_p2p_peers_connected` ≥ 1 everywhere.

Keep a signed record of the genesis bundle (the identical fields of §3) and of
the binary SHA-256 you deployed; new operators verify against it.

---

## 13. Metrics and basic alerting

Every node with `api_listen_addr` serves Prometheus text exposition at
`GET /v1/metrics`; legacy-transport nodes also serve `/internal/metrics` on their
P2P port. No authentication — restrict at the firewall.

```sh
curl -s http://127.0.0.1:26657/v1/metrics | grep -E '^pqchain_' | head -40
```

Metric names are stable (a rename is a breaking change):

| Metric | Type | Meaning |
|---|---|---|
| `pqchain_chain_height` | gauge | Tip height. Flat for more than a few block times = not advancing. |
| `pqchain_blocks_produced_total` | counter | Blocks committed by this proposer. |
| `pqchain_blocks_imported_total`, `pqchain_p2p_blocks_imported_total` | counter | Blocks applied from peers. |
| `pqchain_txs_admitted_total`, `pqchain_txs_rejected_total`, `pqchain_txs_rejected_by_reason_total` | counter | Mempool admission. |
| `pqchain_mempool_depth` | gauge | Pending transactions. |
| `pqchain_p2p_peers_connected` | gauge | libp2p peers. 0 on a non-validator = partitioned or stale bootstrap list. |
| `pqchain_p2p_gossip_peers_healthy`, `_graylisted`, `_below_gossip`, `_below_publish`, `pqchain_p2p_gossip_peer_score_*` | gauge | GossipSub peer scoring. |
| `pqchain_p2p_block_fetch_{requests_sent,requests_received,responses_received,failures}_total`, `pqchain_p2p_block_gap_total` | counter | Block fetch protocol. |
| `pqchain_p2p_snapshot_{requests_sent,requests_received,responses_received,failures}_total` | counter | Snapshot cold start (§14). |
| `pqchain_p2p_tx_rejected_unbound_peer_total` | counter | Transactions dropped by the validator PeerId allow-list (§17.7). |
| `pqchain_p2p_envelope_mismatch_total` | counter | Gossip envelopes for another chain id. |
| `pqchain_peer_sync_errors_total` | counter | Legacy-transport sync failures. Monotonic: alert on `rate()`, not on the value. |
| `pqchain_chain_data_bytes`, `pqchain_chain_growth_rate_bytes_per_hour` | gauge | Store size and growth — plan pruning (§15). |
| `pqchain_current_epoch`, `pqchain_epoch_length_blocks`, `pqchain_recovery_source` (0 replay / 1 checkpoint), `pqchain_node_start_unix_secs`, `pqchain_log_events_total` | gauge / counter | Epoch, last recovery mode, start time, log lines by level. |

```yaml
scrape_configs:
  - job_name: pqchain
    metrics_path: /v1/metrics
    static_configs:
      - targets: ['203.0.113.10:26657', '203.0.113.11:26657', '203.0.113.12:26657']
```

| Alert | Expression |
|---|---|
| Chain stalled | `increase(pqchain_chain_height[1m]) == 0` for 2 min |
| Node isolated | `pqchain_p2p_peers_connected < 1` for 60 s (a planned restart recovers in ~15 s and does not fire) |
| Legacy sync failing | `rate(pqchain_peer_sync_errors_total[1m]) > 5` |
| Disk | free space on `data_dir` < 20 % (prune within a day), < 5 % (stop and prune now) |
| Growth anomaly | `pqchain_chain_growth_rate_bytes_per_hour` > 2 × your empty-chain baseline — find the cause before pruning |
| Allow-list violations | `rate(pqchain_p2p_tx_rejected_unbound_peer_total[5m]) > 0` |
| Restart | `changes(pqchain_node_start_unix_secs[10m]) > 0` |

`scripts/p2p-health.sh` prints `node role peers status` for every host of an
Ansible inventory and exits non-zero on `UNREACHABLE` / `DEGRADED`
(`--watch 30`, `--min 2`).

---

## 14. State sync: snapshot export, import and cold start

A snapshot is the node's trusted checkpoint (state at height H). A fresh node
that imports one starts at H and fetches only the tail. The node validates the
snapshot's structure and `state_root` but does not re-execute the blocks before H:
import only from an operator you trust, and only into an empty `data_dir`.

Manual flow (both nodes stopped while the store is open):

```sh
pqcd snapshot-export /etc/pqchain/node.json /var/tmp/snapshot-<height>.cbor      # source node
pqcd snapshot-import /etc/pqchain/node.json /var/tmp/snapshot-<height>.cbor      # new node, empty store
sudo chown -R pqchain:pqchain /var/lib/pqchain      # if you ran the import as root
sudo systemctl start pqcd
# log: bootstrap complete … recovery_source=trusted_checkpoint, then tail import
```

Automatic cold start over libp2p: a node with `libp2p.enable: true`, at least one
`bootstrap_peers` entry and an empty store asks its bootstrap peers for a snapshot
(`/viper/<chain>/snapshot/1.0.0`) before recovery. If nobody serves one it logs
`libp2p cold-start failed — falling back to genesis replay`. Metrics:
`pqchain_p2p_snapshot_*`.

Legacy transport: set `devnet.snapshot_source: "203.0.113.10:26656"` on the
joining node; on first start with an empty store it downloads the checkpoint via
`GET /internal/p2p/snapshot` (ML-KEM-768 session) and the tail, then continues
normally; ignored once a local checkpoint exists. With libp2p enabled
`snapshot_source` is not consulted — the two paths never run together.

---

## 15. Pruning and cold storage

`validator`, `single_node` and `archive` keep everything (`snapshot-prune` refuses
them without `--force`); `sentry`, `full`, `rpc` and `bootnode` prune.

```sh
sudo systemctl stop pqcd
pqcd snapshot-prune /etc/pqchain/node.json --keep-tail-blocks 1209600   # ≈ 7 days at 500 ms (default)
# prune_completed: blocks_deleted=N hash_index_deleted=N tx_index_deleted=N siblings_deleted=N checkpoints_deleted=N checkpoints_kept=1 keep_tail_blocks=1209600
sudo systemctl start pqcd
```

Refused with `INVALID_PRUNE_CUTOFF` unless cutoff > 0, cutoff ≤ tip and a trusted
checkpoint exists at or above the cutoff (catch up first otherwise). The Ansible
role installs `pqcd-prune.timer` (Sunday 03:00 UTC, stop → prune → start, log in
`/var/log/pqchain/prune.log`; off-schedule: `systemctl start pqcd-prune.service`).
If the disk is too full for RocksDB compaction, fall back to `snapshot-export` →
wipe `rocksdb/` → `snapshot-import` (§14).

Cold storage moves blocks below a cutoff into signed, batched archives that an
auditor or a fresh node can restore from (`SPEC-COLD-STORAGE-001`):

```sh
sudo systemctl stop pqcd
pqcd cold-storage-export /etc/pqchain/node.json \
    --cutoff-height <H> --output-dir /var/cache/pqchain/cold/$(date -u +%Y-%m) --batch-size 10000 \
    --sign-with-operator <operator_address_hex> --anchor-tsa http://<tsa-host>/ --tsa-best-effort
sudo systemctl start pqcd
# output: blocks-<low>-<high>.zst per batch + manifest.json (signed, optionally RFC 3161 anchored);
# upload out of band, or --upload-to s3://… with a binary built with --features s3-upload
pqcd cold-storage-import /etc/pqchain/node.json /var/cache/pqchain/cold/<month>/ [--require-tsa] [--insecure-no-verify]   # EMPTY store only
```

`--insecure-no-verify` is only for unsigned v1 manifests whose chain of custody
you established elsewhere. `SHA-256 mismatch` on import = a corrupted or partially
synced batch: re-sync and check the bucket's object versions. The Ansible role
also ships a monthly `pqcd-cold-rotate` timer.

---

## 16. Consensus-key rotation

A validator rotates its consensus key without leaving the set: submit a
`ConsensusKeyRotate` transaction signed with the current key, wait for the
activation height, swap the keystore at that height.

```sh
VIPER_PASSPHRASE=… pqcd wallet create --alg ml-dsa-65 --output /etc/pqchain/validator.new.keystore.json
TIP=$(curl -s http://127.0.0.1:26657/v1/status | jq -r .height)
VIPER_PASSPHRASE=… pqcd wallet rotate-consensus-key /etc/pqchain/operator-keystore.json \
    --new-keystore /etc/pqchain/validator.new.keystore.json \
    --node http://127.0.0.1:26657 --rotation-start-height $((TIP + 200))
# receipt: rotation_start_height, blocks_until_activation
curl -s http://127.0.0.1:26657/v1/validators/<operator_address_hex> | jq '.consensus_alg_id, .consensus_pk_hex'
```

When the record flips (at `rotation_start_height`): `systemctl stop pqcd`, put the
new seed into `keystore.json`, `systemctl start pqcd` — a few seconds of downtime.
`rotation_start_height` must be at least 100 blocks ahead of the tip (`… is below
the apply guard` otherwise); a second rotation transaction overwrites a pending
one. `deploy/ansible/RUNBOOK-CONSENSUS-KEY-ROTATION.md` and the sibling KEM /
peer-id rotation runbooks give the systemd step-by-step versions.

---

## 17. Troubleshooting

### 17.1 Start-up and configuration

| Signature | Cause / fix |
|---|---|
| `Usage: pqcd …` / `unknown command` | Argument order is `pqcd <command> <node.json> …`; see Appendix A. |
| `parse libp2p.validator_listen` (or `vfn_listen` / `public_listen`) | The value must be `ip:port`; the field read is the one for the role (§2). |
| `bootstrap peer … has no /p2p/ component` / `invalid bootstrap peer` | Multiaddr must end in `/p2p/<PeerId>`. Get the PeerId from the peer's `listening on` log line or `pqcd peer-id <its node_id> [--salt …]`. |
| `role does not serve public transaction submission but api.public_tx_submission is true` | Set `api.public_tx_submission: false` on validators/bootnodes. |
| `three-network lint: validator-class role with a publicly-bound libp2p.public_listen` | A validator binds `validator_listen` only; §11.3. |
| warning about a missing `libp2p_seed_salt_hex` / `kem_seed_salt_hex` | Add the salts (§3). |
| `commit_seed_hex does not match public_key_hex` | The seed in `keystore.json` (or `devnet.validators[].commit_seed_hex`) does not derive the listed public key; re-export it (`pqcd wallet export-seed`). |
| `INSUFFICIENT_COMMIT_QUORUM` | Validator sets differ between nodes, or too few seeds/precommits reach the proposer. Diff `devnet.validators` (address, key, `sig_alg_id`, order) and `quorum_threshold`; with `distributed_signing` check every validator is up and signing. |
| `INVALID_COMMIT_SIGNATURE` | A seed does not match the public key it signs for; same fix. |
| `signer_config.kind` disagrees with `signer_kind` | Align the two HSM fields or remove both for the local keystore. |

### 17.2 Store and recovery

| Signature | Cause / fix |
|---|---|
| `devnet bootstrap height mismatch: recovered N, chain store M` | The store's tail is ahead of what replays cleanly (unclean shutdown). Non-validator: stop, delete `<data_dir>/rocksdb`, restart (snapshot cold start or genesis replay). Validator: restore your latest `snapshot-export`, or copy the store from a trusted full-history node. |
| `TIP_HEIGHT_MISMATCH`, `TIP_HASH_MISMATCH`, `HASH_INDEX_MISMATCH` | Corrupt tip / index metadata. Same recovery. |
| `falling back to full replay` | The checkpoint failed validation; safe, the node re-derives state from the blocks. A new checkpoint is written after the next commit. |
| `CHAIN_ID_MISMATCH (P-COMPAT-001): on-disk chain_id=… but binary is configured for …` | The store belongs to another chain. Move the data directory aside or run the binary/config for the on-disk chain. |
| `ROCKSDB_ERROR: … lock` | Another `pqcd` (service or CLI) has the store open. Stop it. |
| `state_root` differs from the network at the same height | Config divergence: `fee_params`, `genesis_accounts`, `devnet.validators` or `anchor_prev_hash_hex` differ from the network's. Fix the config, wipe the store, cold-start from a trusted snapshot (§14). If the configs are identical this is a determinism bug: keep the store and report it (`SECURITY.md`). |
| RocksDB `Permission denied` after a manual import/prune | You ran the CLI as root: `chown -R pqchain:pqchain <data_dir>`. |
| `INCOMPLETE_WRITE_DETECTED`, `UNEXPECTED_BLOCK_FILE`, `MISSING_BLOCK_FILE` | Legacy file store: run `pqcd migrate-store`; for `INCOMPLETE_WRITE_DETECTED` empty `<data_dir>/staging/` first. |

Full wipe of a non-validator is always safe: `systemctl stop pqcd && rm -rf
<data_dir>/rocksdb && systemctl start pqcd`. Never wipe a validator's store on a
live network without a snapshot export first — it is the full-history source for
everyone else. Local devnet: `scripts/stop_local_devnet.sh`,
`rm -rf /var/lib/pqchain/{producer,follower-a,follower-b}/*`, `scripts/run_local_devnet.sh`.

### 17.3 Validator produces no blocks

`pqchain_blocks_produced_total` and `pqchain_chain_height` flat.

1. `df -h <data_dir>` — a full disk stops commits. Free space, restart.
2. `journalctl -u pqcd -n 200 | grep -Ei 'keystore|sign|quorum|precommit'` — an
   unreadable keystore (fix owner/mode; picked up on the next block) or precommits
   below threshold (§17.4).
3. Clock skew between validators drops precommits: `chronyc tracking` on every
   validator, offsets under 100 ms, NTP/NTS everywhere.
4. Panic loop: the unit restarts the process; read the first panic in the journal.

### 17.4 Quorum halt (distributed signing)

The height stops on every node; the proposer logs precommit shortfalls. More than
N/3 validators are unreachable, not signing, or skewed in time.

```sh
for h in 203.0.113.10 203.0.113.11 203.0.113.12; do
  printf '%s ' "$h"; curl -sf --max-time 5 "http://$h:26657/v1/status" | jq -c '{height,node_id}' || echo UNREACHABLE
done
curl -s http://127.0.0.1:26657/v1/metrics | grep -E '^pqchain_p2p_peers_connected '
```

A validator with 0 peers is partitioned (firewall, stale `bootstrap_peers` on its
sentries, ASN limit). Restore the missing validators; the chain resumes within two
block times once ⌈2N/3⌉ + 1 sign again. Do not edit the validator set by hand to
"fix" a halt; if validators are permanently lost, the remaining operators
coordinate a governance action (`SECURITY.md`).

### 17.5 Non-validator is behind or stuck

- `pqchain_p2p_peers_connected` = 0 → §17.6.
- Peers > 0 but height frozen: `pqchain_p2p_block_fetch_failures_total` climbing
  means the peers you dial do not serve blocks — add a bootstrap peer that is in sync.
- Hours behind: stop, wipe `rocksdb/`, restart to cold-start from a snapshot (§14).
- Legacy transport: `peer sync failed` lines and a rising `pqchain_peer_sync_errors_total`;
  check `peers[].p2p_addr` and that the producer's P2P port is reachable.

### 17.6 libp2p: peers = 0

Probe: `curl -s http://127.0.0.1:26657/v1/metrics | grep pqchain_p2p_peers_connected`
or `scripts/p2p-health.sh --watch 5`.

- Stale bootstrap multiaddr: `bootstrap peer redial (periodic)` repeats with dial
  errors. The PeerId is deterministic from `node_id` (+ salt): compare the
  `/p2p/…` suffix in `bootstrap_peers` with the peer's `listening on` line or
  `pqcd peer-id <node_id> --salt <its salt>`. A changed `node_id`, `VIPER_NODE_ID`
  or salt on the peer changes its PeerId. Fix the multiaddr, restart.
- Transport blocked: TCP 26656 must be open inbound on the dialed side. If you
  enabled QUIC and a middlebox drops UDP, set `quic_enabled: false` (TCP + TLS 1.3
  on the same port number) or open UDP.
- `max_peers_per_asn` reached: all your bootstrap peers sit in one ASN; diversify.
- Wrong chain: `pqchain_p2p_envelope_mismatch_total` climbing — the peer runs a
  different `chain_id_hex`.

### 17.7 Validator PeerId allow-list (`libp2p.validator_peer_ids`)

Empty list: any peer's transaction gossip is admissible on the validator network.
Populated: only envelopes whose signed source is in the list are admitted; the
rest increment `pqchain_p2p_tx_rejected_unbound_peer_total` and log `unbound peer`.
To enable: collect every validator's PeerId (`pqcd peer-id <node_id> --salt <salt>`),
set the same list on every validator, restart (no hot reload). A non-zero
rejection rate afterwards means a validator rotated its identity (`pqcd wallet
rotate-peer-id`, new salt or `node_id`) without the list being updated, or a rogue
publisher.

### 17.8 API problems

| Symptom | Fix |
|---|---|
| `connection refused` on 26657 | `api_listen_addr` absent, or the firewall. `ss -tnlp \| grep 26657`. |
| 404 on `/v1/accounts/*` or `/v1/fee-market` | `api.expose_token_state: false` (tokenless chain). |
| 404/405 on `POST /v1/txs` | `api.public_tx_submission: false`; submit through a full/rpc node. |
| 429 `RATE_LIMITED` | Per-IP `rate_limit` exceeded (100/60 s). Raise it, or back off client-side. |
| 429 `SENDER_RATE_LIMITED` | Per-sender `sender_budget` exceeded (50/60 s). |
| `INSUFFICIENT_FEE` | Fee below the node's minimum for the fee class (`specs/fee-model.md`, `/v1/fee-market`). |
| `CHAIN_ID_MISMATCH` on submit | The envelope's chain id is not the node's (`--chain-id` on wallet commands, `VIPER_CHAIN_ID`). |
| Mempool grows without bound | Load above capacity, or stale-nonce transactions (evicted at block assembly; a restart clears them). SLH-DSA transactions are capped per block by design and wait. |

---

## 18. Ports and firewall summary

| Port | Proto | Role | Purpose | Open to |
|---|---|---|---|---|
| 26656 | TCP | validator | `libp2p.validator_listen` | sentries only (private subnet / VPN) |
| 26656 | TCP | sentry | `libp2p.vfn_listen` | the validator and public peers |
| 26656 | TCP | full / rpc / archive / bootnode | `libp2p.public_listen` | anyone |
| 26657 | TCP | any node with `api_listen_addr` | HTTP API `/v1/*`, `/api/*`, `/v1/metrics` | clients and scrapers; loopback on validators and bootnodes |
| 26656 / 26666 / 26676 | TCP | local devnet | legacy HTTP P2P `/internal/p2p/*`, `/internal/metrics` | loopback / cluster only — never the internet |

When several roles share one host, use 26656 (validator), 26666 (sentry) and
26676 (public) by convention. The API is plain HTTP: terminate TLS in a reverse
proxy for public exposure and never expose `/internal/*`.

---

## 19. Useful cargo commands

```sh
cargo build --release -p pqcd --bin pqcd                    # the node
cargo check --workspace                                     # fast compile check
cargo test -p pqc-consensus                                 # one crate
cargo test -p pqcd --test multi_node_devnet -- --test-threads=1
RUST_LOG=debug cargo test -p pqcd --test scenario_runner -- --nocapture
cargo test -p pqcd --test malicious_node --features attack-modes
cargo bench -p pqc-consensus                                # fee calibration (fuzz targets: fuzz/)
```

---

## Appendix A. `pqcd` command reference

| Command | Purpose |
|---|---|
| `pqcd version` | Print the version. |
| `pqcd bootstrap <node.json>` | Recover state from the store (genesis on first run), print `BOOTSTRAP_OK` and the status report. |
| `pqcd status <node.json>` | Status report of a stopped node's store. |
| `pqcd api-serve <node.json> [addr]` | Read-only HTTP API over a stopped node's store (default `0.0.0.0:26657`). |
| `pqcd devnet-serve <node.json>` | Run the node (every role). |
| `pqcd snapshot-export <node.json> <file>` | Write the trusted checkpoint to a file. |
| `pqcd snapshot-import <node.json> <file>` | Load a checkpoint into an empty store. |
| `pqcd snapshot-prune <node.json> [--keep-tail-blocks N] [--force]` | Drop blocks below tip − N (default 1 209 600). |
| `pqcd cold-storage-export <node.json> --cutoff-height N --output-dir DIR [--batch-size 10000] [--sign-with-operator <hex>] [--anchor-tsa <url>] [--tsa-best-effort] [--upload-to s3://…]` | Archive blocks 1..N as signed batches. |
| `pqcd cold-storage-import <node.json> <dir> [--insecure-no-verify] [--require-tsa]` | Restore an archive into an empty store. |
| `pqcd migrate-store <node.json>` | Convert a legacy file store to RocksDB. |
| `pqcd ceremony [--chain-id S] [--validators N] [--block-time-ms M] [--genesis-balance B] [--image-repository R] [--image-tag T] [--namespace NS] [--release-name R] [--deploy-token user:pass@registry] [--output FILE] [--secrets-output FILE]` | Generate genesis, keys, per-role `node.json` and Helm values for a new chain. |
| `pqcd peer-id <node_id> [--salt <hex64>]` | Deterministic libp2p PeerId of a node identity. |
| `pqcd keygen [--alg ml-dsa-65] [--seed <hex>] [--passphrase …] [--chain-id <hex>] [--output FILE]` | Create a keystore non-interactively. |
| `pqcd keystore verify <keystore.json>` | Parse a keystore with the production loader. |
| `pqcd validate-tx <hex>` | Decode and pretty-print a transaction envelope (diagnostic only). |
| `pqcd wallet create \| import-mnemonic \| import-seed \| address \| public-key \| sign \| send \| export-seed \| vault-create \| archival-keygen \| archival-register \| register-validator \| rotate-consensus-key \| rotate-peer-id \| kem-init \| libp2p-init` | Wallet and operator transactions; `--node <url>` selects the API to submit through, `--chain-id <hex>` / `VIPER_CHAIN_ID` the chain. |

Every command that opens the store needs the node stopped. Passphrases come from
`VIPER_PASSPHRASE` or a prompt.

Related: `docs/validator-onboarding.md` (joining as a validator),
`docs/observability.md` (logs, metrics, audit log), `configs/README.md`,
`charts/viper-pq-chain/README.md`, `deploy/ansible/README.md`, `docker/README.md`,
`API.md`, `SECURITY.md` (`security@agwswebconsulting.it`).
