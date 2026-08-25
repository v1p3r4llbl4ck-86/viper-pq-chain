# Viper PQ Chain

A post-quantum-native layer-1 for long-lived proofs: attestations, notarisation anchors and
key-rotation records that must still verify decades from now. Every signature in a critical
path is a NIST FIPS 203/204/205 primitive, every signed object is deterministic CBOR with an
explicit algorithm identifier, and the fee model prices bytes and verification cost — so the
chain can retire an algorithm without retiring its accounts.

- **Verification path — open source (Apache-2.0).** Types, transaction envelope, verifiers,
  light client, keystore, SDKs: everything an external party needs to check the chain
  without running a node.
- **Node — source-available (BUSL-1.1).** Consensus, state, mempool, P2P, the `pqcd` daemon
  and the deployment tooling. Running nodes of a Viper PQ Chain network is granted; each
  version becomes Apache-2.0 four years after its release. See [LICENSE.md](LICENSE.md).
- **No native token.** The validator set is operator-run (proof of authority). The token
  economics that exist in the design are compiled out (`token_economics` feature) and kept
  as a reserve; nothing here is offered for sale.

## Status

**`viper-testnet-2` is live since 2026-08-25** (genesis digest in [genesis/](genesis/README.md)).
Before it the code ran three private chains — `viper-pq-1` (2026-04 → 2026-05), `viper-research-1`
(2026-05 → 2026-08) and an internal single-validator lab — all retired; what they taught is
in [KNOWN-ISSUES.md](KNOWN-ISSUES.md) and [ROADMAP.md](ROADMAP.md).

The author runs the first validator, two sentries and a full node, and publishes:

| What | Where |
|---|---|
| explorer and chain status | `https://pqchain.agwswebconsulting.it` |
| public read API | `https://pqchain.agwswebconsulting.it/v1/status` |
| P2P seed for your node | `boot1.pqchain.agwswebconsulting.it:26656` |

Bootstrap multiaddrs (with PeerIds) are in [genesis/README.md](genesis/README.md).

Anyone can run a full, rpc or archive node; validators are admitted by the existing set.
[docs/validator-onboarding.md](docs/validator-onboarding.md) is the join guide.

## What is in the repository

| Path | What | Licence |
|---|---|---|
| `crates/pqc-crypto` | FIPS 203/204/205 primitives, algorithm registry, verifiers | Apache-2.0 |
| `crates/pqc-types`, `pqc-tx` | protocol types, transaction envelope, deterministic CBOR, validation | Apache-2.0 |
| `crates/pqc-light-client` | sync-committee light client (SPEC-LIGHT-CLIENT-001) — verify headers without a node | Apache-2.0 |
| `crates/pqc-keystore`, `pqc-tsa` | wallet keystore (SPEC-WALLET-001); RFC 3161 DER encoder | Apache-2.0 |
| `crates/pqc-consensus`, `pqc-state`, `pqc-mempool`, `pqc-p2p` | BFT consensus, Merkle state, admission, libp2p transport with ML-KEM-768 sessions | BUSL-1.1 |
| `crates/pqcd` | the node binary: `devnet-serve`, `ceremony`, snapshots, cold storage, wallet | BUSL-1.1 |
| `crates/pqc-hsm`, `viper-archival-sidecar` | signer backends (SoftHSM); RFC 3161 archival overlay | BUSL-1.1 |
| `specs/` | the normative protocol contract (28 specifications) | CC BY 4.0 |
| `charts/viper-pq-chain`, `deploy/ansible`, `docker/` | Kubernetes chart (one StatefulSet per role), systemd path, images | BUSL-1.1 |
| `configs/` | reference `node.json` per role and the local devnet set | BUSL-1.1 |
| `sdk/typescript`, `sdk/python` | client SDKs (0.2.0 published on npm / PyPI; the tree is at 0.3.0, to be re-aligned to `viper-testnet-2` before republishing) | Apache-2.0 |
| `tests/acvp`, `fuzz/` | ACVP conformance vectors; cargo-fuzz targets | Apache-2.0 / BUSL-1.1 |
| `vendor/` | patched `libp2p-tls`, `libp2p-quic` (post-quantum handshake), `slh-dsa` | upstream |

## Cryptography

| Use | Algorithm | Notes |
|---|---|---|
| transactions, consensus | ML-DSA-65 (default), ML-DSA-87 | ML-DSA-44 allowed for transactions only (ADR-046) |
| consensus fallback, archival overlay | SLH-DSA-SHAKE-192s, -256s | hash-based; priced ~60× higher per verification |
| P2P transport | ML-KEM-768 sessions; X25519MLKEM768 hybrid TLS on libp2p (`hybrid-kem-tls`) | the GossipSub envelope is still Ed25519 (R-14) |
| hashing | SHA3 / SHAKE with a hash registry | upgradable through governance, never by reset |
| encoding | deterministic CBOR (RFC 8949) | `alg_id` and `key_version` are part of every signed object |

Fee classes, verification rates and commit sizes are in [ARCHITECTURE.md](ARCHITECTURE.md).

## Quick start

Rust 1.92.0 is pinned in `rust-toolchain.toml`; `rustup` picks it up.

```sh
cargo build --release -p pqcd

# a whole chain in one process (local quick-start, role single_node)
./target/release/pqcd bootstrap configs/single-node.json
./target/release/pqcd api-serve configs/single-node.json 127.0.0.1:26657
curl -s http://127.0.0.1:26657/v1/network      # read-only API; `devnet-serve` adds /v1/status and POST /v1/txs

# a local network: one validator + two full nodes on loopback
scripts/setup_local_devnet.sh          # installs configs/{producer,follower-a,follower-b}.json
scripts/run_local_devnet.sh            # three `pqcd devnet-serve` processes
```

Node roles (ADR-069): `validator`, `sentry`, `full`, `rpc`, `archive`, `bootnode`, `single_node` —
one word in `node.json`, in the Helm chart and in `pqcd ceremony`. `configs/roles/<role>.json`
are the reference configurations; [docs/operators/RUNBOOK.md](docs/operators/RUNBOOK.md) is the
operator playbook (build, configure, join, troubleshoot), and
[charts/viper-pq-chain/README.md](charts/viper-pq-chain/README.md) the Kubernetes path
(`pqcd ceremony` generates genesis, keys and per-role configuration; the chart deploys one
StatefulSet per role).

Verify without a node: `pqc-light-client` checks headers against the sync committee with
`pqc-crypto` alone — it never links the node core (ADR-068).

## Quality gates

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo deny check
cargo test --workspace --all-features        # 935 passed, 8 ignored (2026-08-24)
scripts/check-licenses.sh
```

Multi-node integration tests are timing-sensitive on small machines: add `-- --test-threads=1`.
The malicious-node scenarios need `--features attack-modes`. [TESTING.md](TESTING.md) has the
test map, load-test baselines and fuzz harnesses.

## Documentation

| Read this | For |
|---|---|
| [WHITEPAPER.md](WHITEPAPER.md) | thesis, threat model, cryptographic architecture, consensus, fees, governance |
| [ARCHITECTURE.md](ARCHITECTURE.md) | as-built layers, roles, data objects, fee classes, consensus posture |
| [specs/](specs/) | the normative contract; status vocabulary in [CONVENTIONS.md](CONVENTIONS.md) |
| [API.md](API.md) | HTTP read API, transaction submission, service endpoints |
| [DECISIONS.md](DECISIONS.md) | every architecture decision (ADR-001 …), superseded ones marked |
| [docs/operators/RUNBOOK.md](docs/operators/RUNBOOK.md), [docs/validator-onboarding.md](docs/validator-onboarding.md) | run and join |
| [KNOWN-ISSUES.md](KNOWN-ISSUES.md), [ROADMAP.md](ROADMAP.md), [TASKS.md](TASKS.md) | what is open, what is next |
| [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md), [AGENTS.md](AGENTS.md) | disclosure, contributions, repository rules |
| [docs/INDEX.md](docs/INDEX.md) | the full map of `docs/` |

## Security

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md) and
[.well-known/security.txt](.well-known/security.txt). No external cryptographic audit has been
completed yet (TASK-115); the accepted risks are listed in [KNOWN-ISSUES.md](KNOWN-ISSUES.md).

## License

Three licences, by what a file is for — [LICENSE.md](LICENSE.md) has the map and the BUSL-1.1
parameters: **Apache-2.0** on the verification path and the SDKs, **BUSL-1.1** on the node and the
deployment tooling, **CC BY 4.0** on specifications and documents. Vendored code keeps its upstream
licence ([NOTICE](NOTICE)).

Copyright © 2026 Alberto Galassi.
