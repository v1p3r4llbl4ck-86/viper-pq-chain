# Node and Validator Onboarding — `viper-testnet-1`

**Audience.** Operators who want to run a node of the public chain
`viper-testnet-1`, and operators who want to be admitted as validators.
**Status.** Accepted for the public release. `viper-testnet-1` is created
after the release with `pqcd ceremony`; the endpoints named below are
published with the genesis and are not live until then.
**Companion documents.** `docs/operators/RUNBOOK.md` (day-two
operations), `docs/observability.md` (logs, metrics, audit log),
`configs/README.md` (config field reference), `specs/consensus.md` and
`specs/validator-staking.md` (protocol rules), ADR-069 in `DECISIONS.md`
(node roles).

---

## 1. Who can run what

`viper-testnet-1` is a proof-of-authority network with **no native
token**: nothing is staked, nothing is earned, nothing is bought. The
`token_economics` feature is compiled out of the public binary and its
specifications are `Reserved`.

| Role (`devnet.role`) | Who | What it does |
|---|---|---|
| `full` | anyone | Validates every block, keeps recent history, serves the read API and accepts transactions. |
| `rpc` | anyone | A `full` node dedicated to the public HTTP API; scale it out behind a load balancer. |
| `archive` | anyone | A `full` node that keeps the whole history and feeds the archival sidecar; `snapshot-prune` refuses it. |
| `sentry` | validator operators | Dials the validator, relays gossip for it, never signs. Fronts the validator's private API. |
| `bootnode` | the chain operator (others may run their own) | DNS-stable seed, public P2P only, private API. |
| `validator` | operators admitted to the validator set | Signs votes and proposes blocks. Private API; sentries front it. |
| `single_node` | local development only | One-process chain, no P2P. Never use it on the public network. |

The validator set is **operator-run**: the author runs the first
validator, its sentries and the bootnode, and admits external
validators as described in §7. Anyone can run `full`, `rpc` and
`archive` nodes without asking. The old role names `producer` and
`follower` are still read as aliases of `validator` and `full` but are
never written; do not use them in new configs.

## 2. Prerequisites

- **Linux** x86-64 (systemd deployment via `deploy/ansible`, or the
  container image via the Helm chart `charts/viper-pq-chain`).
- **Rust 1.92.0** (pinned in `rust-toolchain.toml`) if you build from
  source; otherwise the published container image. The node crates are
  source-available under BUSL-1.1; running a node of a Viper PQ Chain
  network is within the Additional Use Grant (see `LICENSE.md`).
- **Ports**: `26656/tcp` P2P (libp2p; QUIC is optional and off in the
  reference configs) and `26657/tcp` HTTP API. Open `26656` to the
  internet on `full`, `rpc`, `archive`, `bootnode`; open `26657` only on
  nodes that are meant to serve the public API (`full`, `rpc`,
  `archive`). A validator binds its API to `127.0.0.1` and its P2P
  listener to a network reachable only by its sentries.
- **Hardware**: 4 vCPU, 8 GB RAM, 100 GB SSD for a `full`/`rpc`/`sentry`
  node; `archive` nodes grow without bound; validators on a dedicated
  machine with a disciplined clock (NTP or chrony).
- The node stores its state in `<data_dir>/rocksdb`; the `chain_id_hex`
  is written into the store on first open and enforced on every later
  open, so a data directory can never be reused for another chain.

Build from source:

```bash
git clone https://github.com/v1p3r4llbl4ck-86/viper-pq-chain.git
cd viper-pq-chain
cargo build --release -p pqcd
install -m 0755 target/release/pqcd /usr/local/bin/pqcd
pqcd version
```

## 3. Join flow (every role)

1. **Pick your role file.** Copy `configs/roles/<role>.json` to
   `/etc/pqchain/node.json`. Each file already carries the right
   `devnet.role`, listen field (`validator_listen`, `vfn_listen` or
   `public_listen`), API binding and `api.public_tx_submission` default
   for that role; the test
   `crates/pqcd/src/node/tests.rs::configs_roles_examples_match_their_role`
   keeps them consistent with the binary.
2. **Fill the chain constants from the published genesis.** The genesis
   publication for `viper-testnet-1` gives you `chain_id_hex`
   (`76697065722d746573746e65742d31`, the hex of the ASCII chain id),
   `anchor_prev_hash_hex`, `fee_params`, `devnet.block_time_ms`,
   `devnet.epoch_duration`, `devnet.unbonding_period` and the
   `devnet.validators[]` list (the genesis validator set: `node_id`,
   `address_hex`, `sig_alg_id`, `public_key_hex` — never a seed). Every
   non-`single_node` role needs `devnet.validators` filled: the node
   refuses to start without a validator set to verify commits against.
3. **Set your identity.** Choose a `node_id` (or export `VIPER_NODE_ID`,
   which overrides the file; the Helm chart sets it from the pod name)
   and generate the libp2p seed salt:

   ```bash
   pqcd wallet libp2p-init --node-config /etc/pqchain/node.json
   pqcd peer-id <node_id> --salt <devnet.libp2p_seed_salt_hex>
   ```

   The PeerId is deterministic from `node_id` and the salt. Without a
   salt it would be recomputable from the public `node_id`, so the salt
   is mandatory on the public network. Optionally run
   `pqcd wallet kem-init --node-config /etc/pqchain/node.json` to pin
   the ML-KEM-768 session seed as well.
4. **Bootstrap.** Put the published seed in `libp2p.bootstrap_peers`:

   ```json
   "bootstrap_peers": [
     "/dns4/boot1.pqchain.agwswebconsulting.it/tcp/26656/p2p/<bootnode PeerId>"
   ]
   ```

   The bootnode's PeerId is part of the genesis publication. Add other
   operators' `rpc`/`full` nodes as you learn them (the P2P layer wants
   8–16 diverse bootstrap peers and re-dials missing ones). Sentries
   dial their validator instead; the validator keeps `bootstrap_peers`
   empty and lets its sentries dial in.
5. **Start.**

   ```bash
   pqcd bootstrap /etc/pqchain/node.json     # one-shot: opens the store, prints BOOTSTRAP_OK + status
   pqcd devnet-serve /etc/pqchain/node.json  # the node runtime (systemd unit in deploy/ansible)
   ```

   `devnet-serve` is the runtime for every role despite its name.

## 4. Keys and keystores

Two different files are involved; do not confuse them.

**Operator wallet keystore** (`pqcd wallet`, crate `pqc-keystore`,
Apache-2.0). Every operator needs one; it holds an ML-DSA key pair and
derives your operator address. The consensus key of a validator is
this key.

```bash
mkdir -p /etc/pqchain && chmod 0750 /etc/pqchain
VIPER_PASSPHRASE='<strong passphrase>' \
  pqcd wallet create --alg ml-dsa-65 \
    --chain-id 76697065722d746573746e65742d31 \
    --output /etc/pqchain/operator-keystore.json
pqcd wallet address    /etc/pqchain/operator-keystore.json   # hex + bech32m (vpt1… on testnets)
pqcd wallet public-key /etc/pqchain/operator-keystore.json
pqcd keystore verify   /etc/pqchain/operator-keystore.json
```

`wallet create` prints a 24-word mnemonic once; write it down offline.
`import-mnemonic` and `import-seed <hex>` recreate the same keystore.
The file is encrypted (Argon2id + XChaCha20-Poly1305) and written with
mode `0600`. Without `--output` it lands in `$HOME/.viper/keystore/`.
ML-DSA-65 is the default and the only algorithm accepted for consensus
signatures; ML-DSA-44 is allowed for transactions only.

**Node signing keystore** (`devnet.keystore_path`, default
`/var/lib/pqchain/keystore.json` in `configs/roles/validator.json`).
Only validators have it. Format (`crates/pqcd/src/keystore.rs`):

```json
{
  "validators": [
    {
      "address_hex": "<your operator address>",
      "sig_alg_id": 2,
      "commit_seed_hex": "<32-byte seed from: pqcd wallet export-seed /etc/pqchain/operator-keystore.json>",
      "archival_sk_hex": "<optional, 128-byte SLH-DSA-SHAKE-256s sk from: pqcd wallet archival-keygen>"
    }
  ]
}
```

The node re-reads this file when its mtime changes and cross-checks the
public key derived from `commit_seed_hex` against your on-chain
`consensus_pk`; a mismatch fails startup. The seed *is* the consensus
private key: `chmod 0600`, owned by the service user, never in a
config-management repository. `VIPER_KEYSTORE_PATH` overrides the path
at runtime so systemd `LoadCredentialEncrypted=` can supply it. Staged
key rotation (`pqcd wallet rotate-consensus-key`) adds a second entry
with `key_version: 2`; the PeerId rotates with
`pqcd wallet rotate-peer-id ... --in-place /etc/pqchain/node.json`.

## 5. First sync

On first start a node with libp2p enabled and non-empty
`bootstrap_peers` fetches a snapshot from a peer and tail-syncs from
there (`cold_start_from_libp2p_snapshot`). If that fails it falls back
to a full replay from genesis, which is slow but needs no trust in any
peer. A third path, `devnet.snapshot_source` (`host:port` of a node
serving the HTTP snapshot), is fatal on failure and meant for
controlled deployments.

You can also seed the store by hand from a snapshot you trust:

```bash
pqcd snapshot-export /etc/pqchain/node.json /var/tmp/viper-testnet-1.snap   # on a synced node
pqcd snapshot-import /etc/pqchain/node.json /var/tmp/viper-testnet-1.snap   # on the new node, stopped
```

Importing means trusting the snapshot source. Before recovery the node
runs the ADR-054 integrity audit on its store and refuses to start if
it fails ("recover via snapshot-import"). Expect the height to climb in
the journal (`journalctl -u pqcd -f`, events carry `block_hash=` and
`height=`); block finalisation appears in the audit log
(`/var/log/pqchain/audit/`, see `docs/observability.md`).

## 6. Verify you are in sync

```bash
curl -s http://127.0.0.1:26657/v1/status | jq
```

returns `height`, `chain_id`, `state_root`, `tip_hash`, `node_id`,
`base_fee`, `epoch_number` and `epoch_length_blocks`. Compare `height`
and `tip_hash` with the public read API
(`https://pqchain.agwswebconsulting.it/v1/status`, published at
genesis) or with any other operator's `rpc` node: you are in sync when
your height stays within a block or two of theirs and the `tip_hash`
at a common height matches. Note that the `syncing` field is a
placeholder and is always `false`; use the height comparison, not that
flag. `GET /v1/network` on the same node returns the same identity
fields plus `recovery_source`. `GET /v1/validators` lists the validator
set with its `status`, and `/v1/metrics` exposes Prometheus counters.

Run `pqcd status /etc/pqchain/node.json` when the node is stopped to
read the store directly.

## 7. Becoming a validator

What the code implements today (`crates/pqc-state/src/apply/validator.rs`,
`crates/pqc-state/src/store.rs`, `specs/validator-staking.md`):

- The validator set lives in state, seeded at genesis from
  `devnet.validators[]` (status `Active`, `self_bond` 0) and read by
  consensus at every block. Membership changes take effect only at
  **epoch boundaries** (`height % epoch_duration == 0`).
- A `ValidatorRegister` transaction (`pqcd wallet register-validator
  <operator-keystore> --node <url> --node-id <name> --self-bond <n>
  [--peer-id <hex|@file>] [--archival-pk <hex|@file>]`) enters the
  candidate with status `Candidate`. At the next epoch boundary
  candidates are activated in registration order, subject to the churn
  limit, and appear as `Active` in `GET /v1/validators`. The active set
  is capped at `VALIDATOR_MAX_ACTIVE_SET_SIZE = 24`.
- `ValidatorRegister` is not feature-gated, but it requires
  `--self-bond` greater than zero and debits that amount from the
  operator account. On a tokenless chain there is no transfer, so the
  account must have been provisioned at genesis (`pqcd ceremony
  --genesis-balance`). Nothing about this bond is economic: it is an
  accounting number with no market, no reward and no slashing.
- Governance proposals (`specs/governance-module.md`) cannot change the
  validator set; the emergency `Reconfig` transaction described in
  `specs/consensus.md` is not implemented. Jailing and slashing are
  reachable only through equivocation evidence, which is compiled out
  with `token_economics`.

In practice, therefore, **admission is the chain operator's decision,
executed by the operator**: you send the operator your `node_id`, your
operator address, your consensus public key (`pqcd wallet public-key`)
and your validator's PeerId; the operator either includes you in the
genesis validator set at a ceremony, or provisions your operator account
and has you submit `register-validator`, and you become `Active` at the
next epoch boundary. Until the operator has published the concrete
admission procedure with the genesis, run a `full` or `rpc` node first:
it is the same binary, and the operator will want to see it in sync
before admitting you.

Once admitted:

1. Switch to `configs/roles/validator.json`, keep `bootstrap_peers`
   empty, set `devnet.keystore_path` and `proposer_address_hex` (your
   operator address).
2. Run at least two `sentry` nodes on separate machines and networks;
   the validator's P2P listener must be reachable only by them. `pqcd`
   warns at boot if a validator role binds a public listener or enables
   `api.public_tx_submission`.
3. Confirm your status with `GET /v1/validators/<address>` and check
   that your `block_proposed` events appear in the audit log when you
   are the proposer.

## 8. Leaving

- `full`, `rpc`, `archive`, `bootnode`, `sentry`: stop the process. No
  on-chain action is needed. Keep the data directory if you may come
  back; delete it otherwise. A `bootnode` listed in the genesis
  publication should be announced before it goes away.
- `validator`: tell the operator first, because a missing validator
  degrades liveness until the set is changed. The protocol transaction
  is `ValidatorExit` (`MsgType 0x0401`, empty payload; there is no
  dedicated wallet subcommand yet, the transaction is assembled with
  `pqcd wallet sign`). It moves you to `Unbonding` immediately and to
  `Exited` after `VALIDATOR_UNBONDING_PERIOD` blocks (120, a compile-time
  constant; the `devnet.unbonding_period` field is not consulted). The
  transaction is rejected if it would empty the active set. Only after
  you are `Exited` should you stop signing and destroy the node
  keystore; until then keep the validator online so it does not miss
  its turns as proposer.

## 9. Troubleshooting

| Symptom | Cause / action |
|---|---|
| Node starts as a one-process chain | `devnet.role` missing: it defaults to `single_node`. Set it. |
| `role requires a validator set` at start | `devnet.validators` empty on a non-`single_node` role. Fill it from the genesis publication. |
| `chain_id` mismatch on open | Data directory belongs to another chain. Use a fresh `data_dir`. |
| No peers, height stuck at 0 | `bootstrap_peers` empty or without `/p2p/<PeerId>`; port `26656` closed; `/dns4` name not resolving. |
| `commit_seed_hex does not match public_key_hex` | Wrong seed in the node keystore for that `address_hex`. Re-export from the operator keystore. |
| Registered but still `Candidate` | Wait for the next epoch boundary; if the churn limit is full you activate at the following one. |
| `TokenEconomicsDisabled` in a response | You sent a transfer or evidence transaction: those do not exist on this chain. |
