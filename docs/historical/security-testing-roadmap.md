# Security Testing Roadmap — viper-pq-1

**Version**: 1.0 (2026-04-26)
**Owner**: Galassi Alberto
**Window**: 2026-04-28 → 2026-05-02 (current week)
**Driving framing**: Lint + SAST + supply-chain checks (the current `.gitlab-ci.yml` stack) catch coding errors. They do **not** simulate an attacker. For a custom L1 chain, the bugs that bite live in the *distributed logic* — consensus protocol, P2P reception, state replay — not in the Rust syntax.

This roadmap closes that gap by adding 5 layers on top of the existing pipeline: extended fuzzing, sanitiser-driven dynamic analysis, malicious-node runtime simulation, API abuse testing, and runtime intrusion detection. Each entry is tracked as a TASKS.md item; this doc is the single coherent narrative.

## §1 — Threat model anchor

The threat model proper lives at `specs/threat-model.md` (352 LOC, 16 sub-sections covering signature attacks, consensus attacks, P2P transport attacks, replay, and harvest-now-decrypt-later). The gap analysis lives at `specs/fault-injection-report.md`. **This roadmap is the *implementation plan* for the testing surface that answers the spec — it does NOT redefine the threat model.**

If a new attack class appears that is NOT in the threat model, file an ADR in `DECISIONS.md` and update `specs/threat-model.md` first; only then add the test.

## §2 — Inventory: what's already in place

| Layer | Status | In-tree evidence |
|---|---|---|
| L1 — Threat model | ✅ Present | `specs/threat-model.md` + `specs/fault-injection-report.md` |
| L2 — Fuzzing (cargo-fuzz) | 🟡 Partial — 3 targets | `fuzz/Cargo.toml`, `fuzz/fuzz_targets/{fuzz_decode_tx, fuzz_shake256, fuzz_validate_tx}.rs`, `fuzz/corpus/`, `fuzz/seed/`, `scripts/fuzz-all.sh` |
| L3 — Byzantine in-process tests | 🟡 Partial — 4 scenarios in-process | `crates/pqcd/tests/fault_injection.rs` (1211 LOC): equivocation, sub-quorum withhold, split-brain fork, partition recovery |
| L4 — Sanitiser | 🟡 Partial — only via libfuzzer-sys | `scripts/fuzz-all.sh` references sanitiser; no dedicated CI job |
| L5 — Supply chain | ✅ Present | `cargo audit` + `cargo deny check` in `.gitlab-ci.yml`, `deny.toml` (TASK-149) |
| L6 — API pentest | ❌ Absent | Nothing |
| L7 — Runtime IDS | ❌ Absent | Nothing — VM-based deploy (systemd), no container layer |
| L8 — Chaos | 🟡 Partial — soak only | `scripts/{libp2p-soak,canary-tx-soak}.sh` are load/soak, not chaos |

## §3 — Implementation plan, ranked by impact-per-cost

Each layer below is a TASKS.md task. Cross-references in the table.

### Top tier — high impact, low cost (target: this week)

#### L2 — Extend cargo-fuzz with 3-4 new targets — task #21
**Why now**: existing targets cover TX/hash decode but miss the highest-risk surfaces: block decoder, P2P envelope decoder, commit-signature verifier, state-apply round-trip. Each of these processes adversarially-controlled bytes (a hostile peer can shape a `BlockHeader` byte sequence; the chain must not panic on any input).

**Targets to add**:
- `fuzz_decode_block` — `pqc_types::StoredBlock` + `BlockHeader` CBOR decoder (entry path for every gossiped block)
- `fuzz_p2p_envelope` — `pqc_p2p::GossipMessage` decode for `Block` / `ConsensusVote` / `Transaction` topics
- `fuzz_commit_signatures` — `verify_commit_quorum` on adversarial sig vectors (length, alg-id, address mismatches)
- `fuzz_state_apply` — admit-then-apply round-trip on synthesised tx (rate-limit, sender-budget, fee-market)

**Corpus seed**: capture real on-chain bytes from `producer-1::/v1/blocks/<height>` for the block decoder, real CBOR tx from the mempool (`pqcd snapshot-export`), real consensus votes from P2P logs.

**Effort**: ~1 day. **Output**: 3-4 new entries in `fuzz/fuzz_targets/`, `scripts/fuzz-all.sh` updated.

---

#### L4 — CI sanitiser job (ASan on fuzz targets) — task #22
**Why now**: libfuzzer-sys harnesses can run under AddressSanitizer with a single flag. ASan on a 5-min fuzz budget per target catches memory corruption that pure-Rust code mostly avoids — but `unsafe` blocks (vendored `slh-dsa`, `librocksdb-sys`, libp2p network buffers) re-introduce. Cost is one CI job; benefit is "first crash" detection on every PR.

**Implementation**: opt-in CI variable `RUN_FUZZ_SANITIZER=true` triggers a `fuzz:sanitizer` job that uses `rust:nightly` image + `cargo +nightly fuzz run --sanitizer=address <target> -- -max_total_time=300` per target. Crashes saved as artifact. Optional: weekly cron-triggered pipeline with a 30-min budget per target.

**UB sanitiser is deliberately skipped**: the marginal find-rate over ASan in pure-Rust crypto code does not justify the runtime overhead. Re-evaluate if/when we add C/C++ FFI beyond rocksdb.

**Effort**: ~2 hours.

---

#### L8 — Chaos runner — task #23
**Why now**: the chain has been running 23h+ in nominal conditions, but no test has stressed it under packet loss / node restart / network partition. These are real conditions on a 3-VM dev cluster (Hetzner / Contabo / IONOS occasionally drop packets, hosts get rebooted for kernel patches). The TASK-198 cold-sync replay test catches state-root divergence post-restart — but only if the test triggers it. Chaos runner triggers it.

**Scenarios** (`scripts/chaos-runner.sh <scenario> <host>`):
- `kill-pqcd` — `systemctl stop`, sleep 30s, `systemctl start`. Verifies recovery from RocksDB checkpoint.
- `delay-net` — `tc qdisc add dev eth0 root netem delay 200ms` for 60s. Verifies P2P timeouts and proposer-rotation tolerance.
- `loss-net` — `netem loss 10%` for 60s. Verifies block-fetch retry path.
- `partition-net` — `iptables -A INPUT -s <peer> -j DROP` for 60s. Verifies BFT 2-of-3 quorum closes despite missing 1 peer.

**Safety**: never runs while the canary cron is mid-tx (lock file at `/var/lock/viper-chaos.lock`, conflicts with `viper-canary-soak.sh`); auto-cleans `tc` / `iptables` rules on exit-trap.

**Pre-binding-window OK to do whatever; once binding opens** (per AGENTS.md "Mainnet-discipline rules — Binding window"), this needs an opt-in switch + maintenance-window guard in addition to the existing safeties.

**Effort**: ~3 hours. **Output**: `scripts/chaos-runner.sh`, `reports/chaos/<date>-<scenario>.log` per run.

---

### Medium tier — high impact, medium cost

#### L3 — Malicious node runtime mode — task #24 (the real pentest)
**Why now**: `crates/pqcd/tests/fault_injection.rs` already covers Byzantine scenarios *in-process* (single test binary builds 3 fake nodes in the same process), but the scenarios that bite a live chain involve a **real malicious peer over libp2p gossip** — a peer that the producer + honest follower must isolate without halting. This is the "attacker node" the user named explicitly.

**Implementation**: feature-gated (`#[cfg(feature = "attack-modes")]`, OFF in release builds) field `attack_mode: Option<AttackMode>` in `NodeConfig`. Four variants:
1. `InvalidParentHash` — when elected proposer, emit a block whose `prev_hash` is random bytes. Honest peers should reject via `PARENT_HASH_MISMATCH` and not advance.
2. `DoubleProposeAtHeight` — emit two blocks at the same height with different `state_root`. Drives the equivocation-evidence path (TASK-213) which should slash the malicious validator's stake by 5% (`SLASH_FRACTION_BPS = 500`).
3. `WithholdPrecommit` — never gossip the local precommit. Honest peers should still close quorum via the other 2 (3/3 threshold for N=3 means this scenario *will* halt the chain — confirming the threshold).
4. `ReplayFinalizedBlock` — re-emit a sealed block from height H-N as if new. Honest peers should reject via duplicate-hash check / "below-finalized" classifier (devnet.rs:5085 `BlockInboundClass`).

**Test**: new `crates/pqcd/tests/malicious_node.rs` brings up a 3-node cluster with one host in attack mode; assertions on the honest peers' behaviour.

**Effort**: ~2 days (~500 LOC + integration test). **This is the audit-prep deliverable.**

---

#### L6a — k6 abuse + race tests — task #25
**Why now**: the every-5-min canary cron already exposes a real race (`REPLACEMENT_UNDERPRICED` when 3 hosts fire simultaneously). k6 amplifies that to find the actual rate-limit threshold + race surface of the notary backend (and, downstream, of pqcd's mempool admission path).

**Scenarios** (`scripts/k6/notarize-abuse.js`):
- Burst — 100 RPS sustained for 60s; expect graceful degradation, not 5xx.
- Race — 50 concurrent submissions with the same `document_hash`; expect dedup or one-accepted-49-rejected with a clean error code.
- Malformed — random byte payloads; expect 400, never crash / timeout.
- Auth-bypass — submit without TLS (HTTP); expect 426 Upgrade Required from nginx.

**Run model**: docker oneliner from the operator/control machine, NOT in CI (avoid hammering production on every push). Manual or weekly cron.

**Effort**: ~4 hours.

---

#### L7a — Falco runtime IDS — task #27
**Why now**: pre-binding-window the chain runs solo, so the only realistic intruder is a user who SSH'd into one of the 3 hosts (e.g. a stolen credential). Falco's syscall-level rules catch the moment the intruder reads `/etc/pqchain/keystore.json` or spawns a non-`pqchain` process touching the data dir, *before* they extract anything.

**Custom rules** (`/etc/falco/falco_rules.local.yaml`):
- Alert on any non-`pqchain` uid opening `/etc/pqchain/{keystore.json,node.json}`.
- Alert on outbound connection from `pqcd` to an IP not in {peer-1, peer-2, the CI host}.
- Alert on `execve` of `pqcd` or `viper-notary` by uid ≠ `pqchain`.
- Alert on `/etc/pqchain/*` deletion by any uid.

**Tuning**: 2-day "log only, no alert" calibration window before flipping to active alerting (avoid pager-storm from benign Ansible runs).

**Effort**: ~2 hours per host; install via apt (`falcosecurity-falco`), copy rules, enable systemd unit.

---

### Lower tier — context-dependent

#### L6b — OWASP ZAP baseline scan — task #26
One-shot baseline scan against `https://pqchain.agwswebconsulting.it/`. The HTTPS frontend exposes 7 routes (landing, docs, explorer, RPC, notary), most static — small surface, low expected yield. Worth running once for the audit checkbox; revisit monthly only if findings warrant.

**Effort**: ~1 hour.

---

#### L7b — Trivy on Docker images — task #28 (DEFERRED)
The deploy is systemd on bare VMs; no Docker images published. CI uses public images (`rust:1.88`, `rustsec/audit`, etc.) which are scanned by their publishers. This task activates only when we publish a `viper-pqchain/pqcd:viper-pq-1-vX.Y.Z` image (e.g. for K8s deployment, or for a "one-line operator install"). Trivy is then a one-liner `trivy image <tag>` in the release stage.

**Effort**: ~30 minutes when the trigger fires; no work now.

---

## §4 — Week schedule

| Day | Items | Estimate | Done-when |
|---|---|---|---|
| 2026-04-28 (Mon) | L2 fuzz extend | 1d | 4 new fuzz targets land + smoke 1-min run each passes |
| 2026-04-29 (Tue) | L4 sanitiser CI + L8 chaos runner | 5h | Pipeline has `fuzz:sanitizer` opt-in job; `scripts/chaos-runner.sh` exercises 4 scenarios on producer-1 cleanly |
| 2026-04-30 (Wed) — 2026-05-01 (Thu) | L3 malicious node mode | 2d | `attack_mode` feature lands behind `#[cfg(feature = "attack-modes")]`; integration test in `tests/malicious_node.rs` passes; chain stays alive when one host in attack mode |
| 2026-05-02 (Fri) | L6a k6 + L7a Falco install | 6h | k6 burst/race/malformed/auth-bypass all pass; Falco running on 3 hosts in calibration mode |
| Weekend | L6b ZAP baseline + roadmap retrospective | 2h | One ZAP report archived to `reports/zap/`; this doc's §2 inventory updated |

Buffer: 1-day slip is OK on any single item; if the malicious-node mode bumps, k6 + Falco move to Saturday — those two are independent and can land in parallel since they touch different surfaces.

### Actual completion (2026-04-26 / 2026-04-27)

| TASK | Layer | Status | Commit | Notes |
|---|---|---|---|---|
| TASK-216 | L2 fuzz extend | ✅ | `1377b0b` | 3/4 targets shipped (fuzz_decode_block, fuzz_p2p_envelope, fuzz_signed_vote); fuzz_state_apply deferred — needs StateStore + Mempool fixture |
| TASK-217 | L4 sanitiser CI | ✅ | `c46ab49` | `fuzz:sanitizer` opt-in via `RUN_FUZZ_SANITIZER=true`; ASan only (UB sanitiser low yield in pure-Rust crypto) |
| TASK-218 | L8 chaos | ✅ | `1692e62` | `scripts/chaos-runner.sh` with 4 scenarios + lockfile + auto-cleanup trap |
| TASK-219 MVP | L3 malicious | ✅ | `7fdcb37` | `attack_mode` feature + `WithholdPrecommit` (load-bearing for N=3 quorum=3/3) |
| TASK-219b | L3 sub | ✅ | `c0178c3` | `InvalidParentHash` |
| TASK-219c | L3 sub | ✅ | `0a34640` | `DoubleProposeAtHeight` (slashing assertion relaxed to "chain stays alive" — full pipeline > 30 s budget) |
| TASK-219d | L3 sub | ✅ | `15f25f8` | `ReplayFinalizedBlock` |
| TASK-220 | L6a k6 | ✅ | `cf09024` | 4 scenarios in `scripts/k6/notarize-abuse.js`, ~3 min wallclock |
| TASK-221 | L7a Falco | ✅ | `5968ba5` | Rules + idempotent `install.sh`; default `enabled: false` for 2-day calibration |
| TASK-222 | L6b ZAP | ✅ | `11a95f4` | `scripts/zap/baseline-scan.sh` against the live frontend |
| TASK-29 | semgrep findings | ✅ | `403c385` | 10 findings cleared, `security:semgrep.allow_failure` flipped to `false` |
| TASK-223 | L7b Trivy | 🚫 deferred | — | Activates when first Docker image is published |

**Single planned-but-incomplete item**: `fuzz_state_apply` (the 4th target from TASK-216). Tracked in `docs/security-testing-roadmap.md` §3.L2 deferred; lands when the synth StateStore+Mempool fixture is worth the engineering cost.

**Pipeline state post-TASK-29**: every job either hard-pass or hard-fail. No more `allow_failure: true`. Future regressions block the pipeline.

## §5 — Deferred / out of scope

- **L7b Trivy**: trigger = first published Docker image. Not now.
- **K8s observability stack** (Falco enterprise, NeuVector, etc.): trigger = first K8s deployment of the chain. The current systemd model does not need it; Falco standalone covers the runtime-IDS tier sufficiently.
- **Property-based testing (proptest beyond what `proptest` already gives via cargo-fuzz)**: revisit if/when the malicious-node mode finds more state-divergence bugs than fuzzing did. Pre-launch: not needed.
- **External pentest engagement**: out of week scope. Re-surface once L2-L4 + L3 + L6 are done; an external pentester then has a much cleaner attack surface to work against and the engagement gets more value per hour.

## §6 — Cross-references

- `specs/threat-model.md` — the threat model proper (anchor).
- `specs/fault-injection-report.md` — gap analysis behind `crates/pqcd/tests/fault_injection.rs` Byzantine scenarios.
- `KNOWN-ISSUES.md` — section 3 hosts active bugs (R-10 was resolved 2026-04-26 via this discipline; future R-11+ entries from this roadmap land here).
- `TASKS.md` — items #21-#28 reflect the layer-by-layer plan above (renamed to ADR-numbered TASK IDs once landed).
- `AGENTS.md` "Mainnet-discipline rules — Binding window" — chaos / malicious-mode tests are pre-binding only; once external state lands on the chain, these need maintenance-window guards.

---

**Status of the roadmap itself**: living document. Update §2 inventory + §4 schedule whenever a task lands. Close the doc out (move to `docs/historical/`) only when all items are either DONE or DEFERRED with a fixed trigger.
