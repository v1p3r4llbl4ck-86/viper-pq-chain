# Phase 8 — Milestone M1: P2P Cutover (libp2p/QUIC)

**Doc ID**: phase-8-m1-plan
**Status**: planning — baseline approved 2026-04-21
**Owner**: alberto (solo, with cohort esterno for later milestones)
**Date**: 2026-04-21
**Depends on**: ADR-041, ADR-042 (accepted), SPEC-P2P-001 v0.2, SPEC-P2P-002 (new, this work)

## 0. TL;DR

M1 retires the SSH reverse tunnel + HTTP-polling P2P used in Phase 6 and replaces it with a production rust-libp2p stack: QUIC primary, TCP/TLS 1.3 fallback, GossipSub v1.2 for consensus and mempool traffic, request-response for block and snapshot fetch. Scope is deliberately narrow — **libp2p transport + cutover only**, no hybrid-KEM rollout, no dynamic validator set, no second PQ algorithm. Those are M1b/M2/M4.

**Effort**: 2–3 calendar weeks solo. **Budget**: €0 (devnet-2 hosts already paid). **Rollback**: single ansible playbook restores SSH tunnel topology from a tagged commit.

**Exit criterion**: 3-node devnet-2 runs 1 hour continuously on libp2p-only transport with the daily-check canary tx landing, zero alerts, and `pqchain_p2p_peers_connected{network="validator"} = 2` on the producer.

---

## 1. Context and Motivation

### Where Phase 6 landed us

Phase 6 shipped a functional 3-node cluster using two workarounds:
- `pqchain-tunnel-follower1.service` — `ssh -N -R 26656:127.0.0.1:26656 root@<follower-a>`
- HTTP polling — followers `GET /internal/p2p/blocks/{height}` against the producer every N seconds

Observable pain:
- follower-2 (203.0.113.30) has **never peered** to the producer; it sits in limbo with height=0, importing only via the daily-check snapshot path
- block import lag grows proportionally to block size once ML-DSA-65 payloads (2–16 KB) are in use
- the 59k `KEM session failure` log entries per day (Zabbix trigger) are structural — they are the result of session churn on the ML-KEM standalone handshake path; the libp2p transport obsoletes the handshake entirely
- `ssh_tunnel_*` config fields cannot accommodate a third peer without a new systemd unit per peer (N² admin surface)

### What ADR-041 gave us

- transport: QUIC primary + TCP/TLS 1.3 fallback, X25519MLKEM768 hybrid KEM *default once stable*
- gossip: GossipSub v1.2 with IDONTWANT (non-negotiable for PQ signature sizes)
- three logically separate networks (26656 validator / 26666 VFN / 26676 public)
- layered discovery: signed bootstrap → ENR-over-DNS (DNSSEC) → discv5/Kademlia → on-chain registry
- anti-eclipse: validator-pubkey ↔ PeerId binding, ASN diversity, sentry pattern

### What's left to actually *ship* M1

ADR-041 and SPEC-P2P-001 define **what**. M1 fills in **how** for the subset the 3-node devnet-2 needs *today*:
- classical-X25519 TLS for the handshake (hybrid KEM is gated behind a feature flag, flipped in M1b)
- signed bootstrap discovery only (no DNS, no discv5 — single-cohort network)
- on-chain registry lookup for validator-network peer admission
- request-response protocols to close the two HTTP endpoints that still carry real traffic (block fetch, snapshot)

---

## 2. Objectives and Out-of-Scope

### In scope (M1)

1. Make `crates/pqc-p2p` a real dependency of `pqcd`, behind the `libp2p-backend` feature.
2. Wire `SwarmHandle` into `pqcd` bootstrap; consensus votes and blocks flow through it.
3. Implement request-response `/viper/block-fetch/1.0.0` and `/viper/snapshot/1.0.0`.
4. Remove (not disable) the `/internal/p2p/*` HTTP endpoints and the SSH-tunnel systemd unit.
5. Ship ansible roles that configure multiaddrs, open UDP firewall rules, and migrate `config.yaml`.
6. Publish `scripts/p2p-health.sh` and extend `daily-check.sh` with peer-count telemetry.
7. 3-node 1-hour convergence test on devnet-2, reproducible.

### Out of scope (explicitly deferred)

| Item | Deferred to |
|------|-------------|
| X25519MLKEM768 hybrid KEM default-on | **M1b** — when rustls-post-quantum stabilises and libp2p 0.56+ lands |
| Dynamic validator set (join/leave without restart) | **M2** — ADR-042 integration |
| On-chain `ValidatorPeerId` publication | **M2** |
| SLH-DSA-SHAKE-192s as second signing algorithm | **M3** — ADR-043 |
| TLV envelope + on-chain verifier registry | **M3** — ADR-044 |
| External validator cohort recruitment | **M4** — ADR-045 archival overlay + operator onboarding |
| ENR-over-DNS, discv5, ASN-diversity enforcement | Phase 8 hardening milestone (post-M4) |
| NAT traversal (DCUtR + circuit-relay-v2) | Phase 9+ |

### Non-goals

- **Zero downtime.** The cutover is planned as a maintenance window of ≤30 min. Downtime is acceptable for a devnet.
- **Cross-version compatibility.** There is no wire protocol negotiation between Phase 6 and Phase 8 binaries. All three nodes cut over in the same window.

---

## 3. Prerequisites (already in place)

| Artefact | Status | Notes |
|----------|--------|-------|
| ADR-041 — P2P libp2p/QUIC/X25519MLKEM768 | accepted 2026-04-21 | addendum in this milestone |
| ADR-042 — Dynamic validator set | accepted 2026-04-21 | consumed by M2, referenced in M1 peer-binding |
| SPEC-P2P-001 v0.2 | revised 2026-04-21 | `msg_type 0xC1/0xC2/0xC3` inner consensus tags |
| `crates/pqc-p2p` skeleton | in tree (feature-gated) | behaviour.rs/transport.rs/swarm.rs compile under `libp2p-backend` |
| devnet-2 hosts | live | producer 203.0.113.10, follower-a 203.0.113.20, follower-b 203.0.113.30 |
| canary wallet | funded | addr `0b98dcf2…` / keystore `/etc/pqchain/canary.json` |
| Zabbix monitoring | active | template "Viper PQ Chain Node", dashboard 404 |

No new hardware. No new external dependencies beyond what `crates/pqc-p2p/Cargo.toml` already declares (libp2p 0.55).

---

## 4. Cluster Breakdown — TASK-128..146

### Cluster A — Specs & ADR (docs first, unblocks B)

| TASK | Subject | Deliverable | Effort |
|------|---------|-------------|--------|
| TASK-128 | Write `specs/p2p-libp2p.md` (SPEC-P2P-002) | this file's companion implementation spec | 1 d |
| TASK-129 | Update `specs/p2p-messaging.md` §6 | disambiguate outer `MessageType` vs inner consensus `msg_type` | 0.25 d |
| TASK-130 | ADR-041 addendum — hybrid KEM deferral | §Addendum (2026-04-22) in `DECISIONS.md` | 0.25 d |
| TASK-131 | Reconcile `MessageType` enum in pqc-p2p | doc + type-level cross-reference to inner consensus tags | 0.25 d |

**Exit**: PR merges; `cargo doc` has no dangling links; spec IDs stable.

### Cluster B — Code integration (depends on A)

| TASK | Subject | Deliverable | Effort |
|------|---------|-------------|--------|
| TASK-132 | Add `pqc-p2p` as pqcd dep with `libp2p-backend` feature on | `crates/pqcd/Cargo.toml` + feature propagation | 0.25 d |
| TASK-133 | 2-swarm integration test (T4/T6 in SPEC-P2P-002) | `crates/pqc-p2p/tests/two_swarm.rs` | 1.5 d |
| TASK-134 | Wire `SwarmHandle::spawn` into pqcd bootstrap | `crates/pqcd/src/main.rs` (or devnet.rs wire-up path) | 1 d |
| TASK-135 | Block propagation via `Block` topic + request-response | producer publishes; followers validate+insert | 1.5 d |
| TASK-136 | Consensus vote emit/receive | `pqc-consensus` vote sink reads from `SwarmEvent::VoteReceived` | 1 d |
| TASK-137 | Tx gossip + `ValidatorPeerId` binding check | mempool admits from `TransactionReceived`; reject unbound peers on 26656 | 1.5 d |

**Exit**: `cargo test -p pqc-p2p --features libp2p-backend` green; `cargo run -p pqcd` boots with libp2p on single host.

### Cluster C — Config & deploy (depends on B; overlaps D)

| TASK | Subject | Deliverable | Effort |
|------|---------|-------------|--------|
| TASK-138 | Multiaddr config schema migration | `config.yaml.j2` adds `p2p:`; startup guard rejects `ssh_tunnel_*` | 0.25 d |
| TASK-139 | Update ansible `configure` template | `deploy/ansible/roles/pqchain/templates/config.yaml.j2` | 0.5 d |
| TASK-140 | UFW — open UDP 26656/26666/26676 | `deploy/ansible/roles/pqchain/tasks/firewall.yml` | 0.25 d |
| TASK-141 | Playbook `cutover-libp2p.yml` | stops pqcd; disables tunnel unit; installs new binary + config; starts pqcd; waits for peer count ≥1 | 1 d |
| TASK-142 | Playbook `rollback-libp2p.yml` | checks out Phase 6 tag, reinstalls via pipeline-deploy.yml, re-enables tunnel unit | 0.5 d |

**Exit**: `cutover-libp2p.yml` run against devnet-2 succeeds on first try; `rollback-libp2p.yml` exercised in dry-run (not executed).

### Cluster D — Verifica & docs (depends on B, runs alongside C)

| TASK | Subject | Deliverable | Effort |
|------|---------|-------------|--------|
| TASK-143 | Health probe script | `scripts/p2p-health.sh` — prometheus-parse `pqchain_p2p_peers_connected` | 0.25 d |
| TASK-144 | 3-node convergence test (1h soak) | `scripts/check_devnet_convergence.sh` extended with gossip-metrics check; reportf under `reports/soak/` | 1 d |
| TASK-145 | RUNBOOK §20 — libp2p ops | append-only section; peer count, restart, rollback, legacy tunnel removal | 0.5 d |
| TASK-146 | Update `devnet2_endpoints.md` (auto memory) | add QUIC ports, bootstrap multiaddrs, probe command | 0.1 d |

**Exit**: the 1h soak report lands in `reports/soak/YYYY-MM-DD.md`, canary tx succeeds throughout, alerts=[] on daily-check.

---

## 5. Dependency DAG

```
A (docs) ──┬─► B132 ──► B133 ──► B134 ──┬─► B135 ──┐
           │                            ├─► B136 ──┤
           │                            └─► B137 ──┤
           │                                       │
           └─► C138 ──► C139 ──► C140 ──► C141 ────┤
                                         C142 (parallel to C141)
                                                   │
                                                   ▼
                                  D143 ──► D144 ──► D145 ──► D146
```

Critical path: A128 → A129 → B132 → B133 → B134 → B135 → C141 → D144 → D145.

Parallelisable: A130/A131 run alongside A128; C140/C142 run alongside C138/C139/C141; D143 runs as soon as B134 is mergeable.

---

## 6. Effort Estimate

Summed cluster effort: **~12 days of focused work**. Solo cadence with review and integration friction:
- happy path: **2 weeks** (10 working days, tight sequencing)
- realistic: **3 weeks** — inclusive of libp2p 0.55 quirks, rustls handshake debugging, Zabbix trigger re-tuning, and at least one rollback-and-retry of `cutover-libp2p.yml`

Suggested sprint layout:
- Week 1: Cluster A (all 4 tasks) + B132 + B133 + start B134
- Week 2: finish B134 → B137; start Cluster C
- Week 3: Cluster C finish; Cluster D; 1h soak; PR to main

---

## 7. Budget Note — Zero Hardware

M1 runs entirely on the existing 3-node devnet-2. Validator-set expansion (M2/M4) is where hardware cost appears. Confirmed plan for that phase: **closed cohort esterno** — 8–12 operators bring their own hardware (min spec: 8-core Zen4+, 32 GB ECC, 2 TB NVMe per `docs/historical/phase-8-spec.md`). No VPS rental is required; if a stopgap VPS is ever needed for rehearsal, Contabo €5–8/month × 5 = €30/month is the fallback reference.

**ESP32 or similar microcontrollers are not viable for any validator role**: 520 KB SRAM cannot hold the signed-message working set (ML-DSA-65 pk alone is 1952 B × active-set-size), and there is no on-device NVMe-class storage for full state. Recorded here to close the question permanently.

---

## 8. Rollback Strategy

Rollback is a **first-class deliverable** (TASK-142), not an afterthought.

Pre-cutover: tag `phase-8-m1-pre` on develop before executing `cutover-libp2p.yml`. The tag captures the Phase 6 SSH-tunnel binary and config.

On failure (any of: cutover ansible fails; `p2p-health.sh` returns non-zero after 5 min; daily-check alerts fire):
1. `ansible-playbook rollback-libp2p.yml` — checks out `phase-8-m1-pre`, rebuilds pqcd, reinstalls on all 3 hosts, re-enables `pqchain-tunnel-follower1.service`.
2. Retargets daily-check to the old `PRODUCER_API` (same address; no change needed).
3. Writes `reports/incident/libp2p-cutover-N.md` with failure mode, logs excerpt, next-try delta.

Max tolerated rollback window: 15 min. Cutover window: 30 min. Combined: 45 min cap on the maintenance window. If exceeded, roll back and re-plan.

---

## 9. Acceptance Criteria (M1 Done)

All must be true for M1 to close:

- [ ] `specs/p2p-libp2p.md` (SPEC-P2P-002) merged on develop
- [ ] ADR-041 Addendum (2026-04-22) in DECISIONS.md describing hybrid-KEM deferral
- [ ] `cargo test -p pqc-p2p --features libp2p-backend` passes (T1–T6 from SPEC-P2P-002 §10)
- [ ] `cargo build --release -p pqcd` succeeds with `libp2p-backend` on by default in pqcd's Cargo.toml
- [ ] `pqchain-tunnel-follower1.service` is **gone** from devnet-2 (unit file + systemd state both cleaned)
- [ ] `/internal/p2p/*` HTTP handlers are **deleted from source** (grep returns nothing in `crates/pqcd/src/`)
- [ ] devnet-2 all 3 nodes show `pqchain_p2p_peers_connected{network="validator"} = 2` on the producer (follower-1 and follower-2 both peered — the follower-2 limbo is resolved)
- [ ] 1-hour soak report under `reports/soak/YYYY-MM-DD.md` shows: no alerts, canary tx lands every 10 min, block height advances monotonically, `pqchain_p2p_gossip_received_total` grows on all nodes
- [ ] RUNBOOK §20 ops section written and reviewed
- [ ] `devnet2_endpoints.md` auto-memory updated with new multiaddrs and probe command

---

## 10. Risks and Mitigations

| # | Risk | Likelihood | Impact | Mitigation |
|---|------|------------|--------|------------|
| R1 | libp2p 0.55 API breakage mid-flight (0.x churn) | Med | Med | Vendor the crates (already planned per ADR-041 §Decision); pin in workspace Cargo.lock |
| R2 | QUIC MTU/fragmentation breaks handshake on some ISPs | Low | High | Test QUIC Initial size under 1200 B; enable TCP/TLS fallback; document in RUNBOOK §20 |
| R3 | GossipSub mesh doesn't converge at n=3 (below gossipsub defaults) | Med | Med | Override `mesh_n_low=1 mesh_n=2 mesh_n_high=3` for devnet; revisit at n≥8 |
| R4 | follower-2 fails to peer on cutover (never has yet) | High | Med | Cutover playbook includes explicit `FetchSnapshot` step after peer connect; health probe waits up to 5 min |
| R5 | Hidden reliance on `/internal/p2p/*` in some SDK or script | Low | Med | grep SDKs + `scripts/` before TASK-141; any hit becomes a sub-task |
| R6 | Rollback itself fails | Low | High | Exercise `rollback-libp2p.yml` in a dry-run with `--check` before the cutover window; keep `phase-8-m1-pre` tag immutable |
| R7 | Zabbix triggers fire during cutover window | High | Low | Silence the "Viper PQ Chain Node" template during the window; unsilence after health probe green |

---

## 11. Deferred / Open Questions

| # | Question | Target resolution |
|---|----------|-------------------|
| Q1 | Exact `mesh_n_*` and score-threshold values for n=3 | Empirically during TASK-133, codified in TASK-135 |
| Q2 | Should `ValidatorPeerId::binding_sig` land in TASKS.md M1 or wait for M2? | M2 — M1 uses a config-file pinned map, not on-chain |
| Q3 | Does `p2p-health.sh` auto-page Zabbix, or only report? | Report only for M1 — Zabbix trigger delta deferred to RUNBOOK §20 follow-up |
| Q4 | Maximum snapshot size cap | 512 MiB in SPEC-P2P-002 §7.2; revisit if Phase 8 produces >256 MiB snapshots |

---

## 12. References

- `DECISIONS.md` ADR-041 — P2P Layer Phase 8 — libp2p + QUIC + X25519MLKEM768
- `DECISIONS.md` ADR-042 — Dynamic Validator Set On-Chain (consumed by M2)
- `specs/p2p-messaging.md` — SPEC-P2P-001 v0.2
- `specs/p2p-libp2p.md` — SPEC-P2P-002 (companion to this plan, written in TASK-128)
- `docs/historical/phase-8-spec.md` — Phase 8 top-level plan (validator hardware, cohort model)
- `ROADMAP.md` — Phase 8 objective and exit criteria
- `crates/pqc-p2p/` — skeleton already in tree (9 modules, feature-gated)
- `deploy/ansible/playbooks/setup-tunnel.yml` — to be removed by TASK-141
- `scripts/daily-check.sh` — extended by TASK-143/144
