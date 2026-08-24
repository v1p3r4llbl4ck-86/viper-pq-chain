# Roadmap

Viper PQ Chain is a post-quantum trust layer: a BFT chain whose every
signature, key exchange and hash is a NIST post-quantum primitive, built
for attestations and proof anchoring rather than for payments. This
roadmap has three horizons: what was built and proven on the retired
chains, what this public release is, and what the first public network
needs. Dates appear only where they are facts; there is no token and
nothing for sale.

`TASK-nnn` and `ADR-nnn` refer to `TASKS.md` and `DECISIONS.md`.

---

## History — Phases 0 to 8.5 (closed)

Nine phases ran between the first specification and the retirement of
the last private chain. Each line is what the phase left behind in this
repository.

| Phase | Delivered |
|---|---|
| 0 — Foundations | Positioning, first ADR set, the decision to write specifications before code. |
| 1 — Protocol specification | Canonical transaction envelope in deterministic CBOR (SPEC-TX-001), account and keyset model, algorithm registry with lifecycle rules, fee classes by signature cost, validator model, attestation and vault operations. |
| 2 — Prototype node | `pqcd`: signature verification pipeline, mempool admission, deterministic block assembly, disk persistence with checkpoint-aware replay, first end-to-end attestation and key-management slices, Criterion benchmarks (ADR-018). |
| 3 — Controlled devnet | Real ML-DSA-65 verification in admission, ML-KEM-768 authenticated peer sessions, snapshot state sync (`snapshot-export/import`), Prometheus metrics, per-IP and per-sender admission budgets, algorithm deprecation drill, cross-algorithm key rotation drill, fault-injection and load tests (ADR-021). |
| 4 — Hardening | Threat model, audit scope, security scan with fixes, multi-algorithm verifier (ML-DSA-44/65/87, SLH-DSA), on-chain validator lifecycle, throughput tuning to the ≥ 100 TPS target (ADR-023). |
| 4b — BFT consensus | Tendermint-style Prevote → Precommit → Commit engine with post-quantum vote signatures, proposer rotation, equivocation detection, three-node convergence tests (SPEC-CONSENSUS-001, ADR-027). |
| 5 — Genesis preparation | Genesis specification with a deterministic hash formula, validator onboarding and rehearsal procedures (ADR-025). The token economics designed here are now *Reserved* (see below). |
| 6 — First multi-host chain | Three validators on separate hosts under Ansible, encrypted keystore (Argon2id + XChaCha20-Poly1305), first incident-response drill (ADR-040). |
| 7 — Product layer | TypeScript and Python SDKs, block explorer, `pqcd wallet` with mnemonic and keystore (ADR-033, SPEC-WALLET-001), notary service specification. |
| 8 — P2P, agility, archival | libp2p transport with GossipSub v1.2 and peer scoring (ADR-041); dynamic validator set with epoch churn and pluggable slashing registry (ADR-042, ADR-050); SLH-DSA-SHAKE-192s as second signature family (ADR-043); TLV envelope and on-chain verifier registry (ADR-044, ADR-049); archival overlay with SLH-DSA-SHAKE-256s epoch roots and RFC 3161 anchoring via the sidecar (ADR-045); distributed commit signing (ADR-051). |
| 8.5 — Mainnet discipline | Forward-compatible state evolution policy P-COMPAT-001 with the always-on cold-sync replay gate (ADR-052, TASK-198); genesis architecture with versioned block header, ForkDigest signing domains, chain-bound addresses, hash registry, binary Merkle state tree, light-client scaffolding (ADR-053); BFT-correct block reception (ADR-054); HSM signer abstraction (`pqc-hsm`); on-disk prune and cold-storage rotation (ADR-057, ADR-058, ADR-060); hybrid X25519MLKEM768 TLS on the wire (feature `hybrid-kem-tls`); ceremony tooling (ADR-056); malicious-node test modes; fuzz targets and sanitiser jobs. |

Two chains carried this work. `viper-pq-1` (2026-04-25 to 2026-05-12,
archived at height 33,976) was the first no-reset chain.
`viper-research-1` (2026-05 to 2026-08) was tokenless, three validators,
and the first to run post-quantum TLS end to end. Both are retired; the
incidents they produced are summarised in `KNOWN-ISSUES.md` §5 and the
decisions they forced are in `DECISIONS.md`.

---

## Now — public release

This repository is the public release of the code base. The work of the
release itself:

- **Licence map** (ADR-070): the verification path (`pqc-crypto`,
  `pqc-types`, `pqc-tx`, `pqc-tsa`, `pqc-light-client`, `pqc-keystore`,
  the SDKs, the ACVP vectors) is open source under Apache-2.0; the node
  core (`pqc-consensus`, `pqc-state`, `pqc-mempool`, `pqc-p2p`,
  `pqc-hsm`, `pqcd`, the archival sidecar, charts, deploy, docker,
  scripts) is source-available under BUSL-1.1 with a four-year change
  date to Apache-2.0; specifications and documents are CC BY 4.0.
  `LICENSE.md` is the map; `scripts/check-licenses.sh` keeps it true.
- **Crate boundary** (ADR-068): a verifier of a 2026 attestation must be
  buildable in 2046 without the node. The light client and the keystore
  became their own crates; no verification-path crate links the node
  core.
- **One vocabulary for node roles** (ADR-069): `validator`, `sentry`,
  `full`, `rpc`, `archive`, `bootnode`, `single_node` in the binary, the
  ceremony and the chart, with reference configs under `configs/roles/`.
  The remaining producer/follower wording in Ansible and scripts is
  TASK-243.
- **Repository hygiene**: internal run books, planning notes, host
  identifiers and the private notary product removed; SPDX headers on
  every source file; `SECURITY.md` with a private reporting channel.
- **Continuous integration on GitHub** (set up at cut-over, replacing
  the private pipeline): format, `clippy -D warnings`, `cargo deny`,
  licence check, the full test suite with the cold-sync replay gate on
  every pull request; fuzz and sanitiser jobs on a schedule
  (`TESTING.md`).
- **Documents that describe the tree as it is**: `ARCHITECTURE.md`,
  `API.md`, `TESTING.md`, `KNOWN-ISSUES.md`, this file.

---

## Next — `viper-testnet-1`

The first public network. It is a tokenless proof-of-authority chain
with an operator-run validator set; external participants join as
non-validating nodes first and can be admitted as validators.

**Genesis**

- Run `pqcd ceremony` for the public chain id, publish the genesis file
  and its hash, and let anyone reproduce the hash from the published
  inputs.
- Close the gaps in `KNOWN-ISSUES.md` §2 first; they are the exit
  criteria of the ceremony: transport identity salts generated by the
  ceremony (G-01), validator memory growth profiled and fixed (G-02,
  TASK-241), the multi-node test made deterministic under load (G-03,
  TASK-239), the chart rendering `node.json` from values (G-04,
  TASK-242), one role vocabulary end to end (G-05, TASK-243).
- Pin the block time for the public chain (TASK-186) against the storage
  figures in `KNOWN-ISSUES.md` R-10.

**Topology run by the author**

- First validator behind sentries, a DNS-stable bootnode, and rpc nodes
  for the read API, deployed from `charts/viper-pq-chain`.
- Public endpoints at the planned names, live only from genesis: the
  explorer and status page at `pqchain.agwswebconsulting.it`, the read
  API at `rpc.pqchain.agwswebconsulting.it`, the P2P seed at
  `boot1.pqchain.agwswebconsulting.it:26656`.

**External operators**

- Full, rpc and archive nodes from the reference configs, syncing from
  the bootnode; `docs/validator-onboarding.md` and the chart README are
  the entry points.
- Validator admission for external operators: key generation, on-chain
  registration, activation at an epoch boundary and the first elected
  proposer round, exercised end to end by at least two operators who
  are not the author (TASK-185 as re-scoped for the testnet). The
  alias role names are removed at the first minor release after
  genesis.
- Re-aligned SDKs (`@v1p3r4llbl4ck/sdk`, `viper-pqchain`) published
  against the testnet chain id.

**Operations**

- Peer-id and KEM salt rotation on a schedule (ADR-047, `pqcd wallet
  rotate-peer-id`), NTS time sync (TASK-150), prune and cold-storage
  rotation on the non-archive roles, archival sidecar anchoring epoch
  roots at a real time-stamping authority.

---

## Later

Open items with a reference; none is scheduled.

- **External cryptographic audit** (TASK-115): `pqc-crypto`,
  `pqc-state::apply`, the transaction validation pipeline, the P2P
  layer and the TLV envelope, scoped in `specs/audit-scope.md`.
  Findings are triaged into `KNOWN-ISSUES.md`.
- **Post-quantum GossipSub envelope** (R-14): replace the classical
  Ed25519 message signature with an application-layer post-quantum
  envelope; the natural moment is FIPS 206 (FN-DSA, ADR-067) or a
  genesis.
- **Formally verified primitives**: libcrux behind the `PqVerifier`
  dispatch (R-01), once the crypto-agility envelope has been audited.
- **HSM-backed consensus signing**: cloud and hardware backends for the
  `CommitSigner` trait in `pqc-hsm`; automatic key rotation follows,
  not precedes, the HSM.
- **Light-client sync committee in production** (SPEC-LIGHT-CLIENT-001,
  ADR-068): nodes publishing sync-committee attestations so a client
  can verify headers without the node core.
- **Cold-sync replay gate on real history** (TASK-198 follow-up): run the
  replay-equivalence check against exported testnet history, not only
  the synthetic pin vector.
- **Larger fault-injection harness** (TASK-151), NTS/Roughtime time sync
  (TASK-150), the fairness assumption in the Quint model (TASK-238),
  hedged ML-DSA signing (R-07).
- **Validator set growth** (ADR-065: 3 → 64 → 256 → 1024) and the
  **permissionless entry plan** (ADR-066), each gated on measured
  behaviour of the previous step.
- **Long horizon** (`docs/long-horizon-roadmap.md`): STARK signature
  aggregation (ADR-061), PQ-VRF migration (ADR-062), a third signature
  family from the NIST on-ramp (ADR-063), operator diversity targets.
  Each carries a trigger condition rather than a date.

---

## Deferred until the trust layer proves itself

- generic smart-contract execution
- bridge-heavy interoperability
- retail payment optimisation
- ecosystem grants and expansion programmes
- any native token: the `token_economics` feature and the *Reserved*
  specifications stay dormant; there is no offering planned.

Last updated: 2026-08-24.
