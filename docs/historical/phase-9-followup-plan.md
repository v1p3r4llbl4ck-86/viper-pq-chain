# Phase 9 Follow-Up Plan

**Status:** working plan, updated as tasks land.
**Owners:** core protocol team.
**Created:** 2026-05-06.
**Authority:** consolidates the open-task batch identified after the
`viper-pq-1` Phase 8.5 launch + the 2026-05-06 Phase 9 prep wave
(TASK-225 / TASK-219 / TASK-222 closed).

This doc is the operational counterpart of
`docs/long-horizon-roadmap.md` (TASK-225). The roadmap doc lists the
*direction-decided* multi-decade items with explicit trigger
conditions; this doc lists the *near-term-actionable* items each with
estimate + dependency + recommended ordering. When a task lands, the
checkbox flips and the entry stays as a record.

---

## Dependency graph

```
                    ┌─ TASK-225 §3 (3rd alg slot) ──────┐
                    │                                    ▼
      ┌─ TASK-226 ──┘                         ┌─ TASK-223 (online key rotation)
      │  (FN-DSA bench/spike)                 │   ↑ blocks on ADR-053 §T1.5 dual-path
      │                                       │
      ▼                                       │
   gov reserves                               │
   AlgId 0x0010                               │
                                              │
TASK-221 ────► multicodec PR ─────────────────┤
(upstream codepoint                           │  ALL the alg work needs an
 reservation)                                 │  agile registry (TASK-223)
                                              │
TASK-218 ────► QUIC + hybrid TLS ─────────────┤
(M1b closure)   ↑ blocks on rustls-pq stable  │
                                              ▼
TASK-222 [DONE] ─► GossipSub calibrated ──► TASK-228 (scale-up plan)
                                             │
                                             ├─ gated on STARK aggreg
                                             │  (long-horizon §1, Y4-Y6)
                                             │
                                             └─ gated on TASK-185 cohort
                                                growth (Y2 trigger)

TASK-227 ────► /diversity dashboard + quarterly report
(pairs with TASK-185 cohort onboarding — measures the cohort)

TASK-224 ────► permissionless transition ADR
(no upstream dep — pure design; pairs with TASK-227 + TASK-228)
```

---

## Recommended ordering

### Batch A — code-actionable now (~2-4 g)

| Order | Task | Effort | Status | Notes |
|-------|------|--------|--------|-------|
| 1 | TASK-221 — multicodec mapping + upstream PR | 0.5 g code + PR review (1-3 sett async) | planned | safest; sblocca cross-ecosystem narrative |
| 2 | TASK-227 — diversity Y0 baseline + script | 1.5 g (script + report; frontend separabile +1 g) | planned | quick win utile per TASK-185 cohort onboarding |
| 3 | TASK-223 — online consensus-key rotation | 2 g | planned (highest risk) | state-root format change; richiede cold-sync replay test PRIMA del merge |

### Batch B — doc/design (no code, ~2 g)

| Order | Task | Effort | Status | Output |
|-------|------|--------|--------|--------|
| 4 | TASK-228 — scale-up plan committee 256 → 1024 | 0.5 g | planned | ADR-065 + sezione in `docs/long-horizon-roadmap.md` §1 |
| 5 | TASK-224 — permissionless eligibility transition | 1 g | planned | ADR-066 + `docs/permissionless-transition.md` |
| 6 | TASK-226 — FN-DSA evaluation + AlgId reservation | 0.5 g doc + 1 g spike (deferred to Q4 2027) | planned | ADR-067 + governance proposal reserving 0x0010 |

### Batch C — bloccati su upstream

| Order | Task | Effort code | Trigger | Status |
|-------|------|-------------|---------|--------|
| 7 | TASK-218 — QUIC + hybrid PQ TLS | 2-3 g | rustls-post-quantum stable + libp2p 0.56+ | blocked, re-poll quarterly |

---

## Per-task detail

### TASK-221 — Multicodec upstream registration

**Deliverable.** PR a `multiformats/multicodec` con righe per:
- ML-DSA-44 / ML-DSA-65 / ML-DSA-87
- SLH-DSA-SHAKE-128f / SLH-DSA-SHAKE-128s / SLH-DSA-SHAKE-192s / SLH-DSA-SHAKE-256s
- ML-KEM-512 / ML-KEM-768 / ML-KEM-1024

Plus `crates/pqc-crypto/src/alg.rs` doc comments wiring the equivalence
between Viper's internal `algo_id: u16_le` (per ADR-044 TLV envelope)
and the multicodec varint codepoints.

**Steps.**
1. Map each Viper AlgId to a proposed multicodec codepoint. Use
   pre-existing AlgId hex values where the multicodec table has them
   free; otherwise pick from the multicodec reserved range (`0x1200–0x12FF`
   is the typical "post-quantum signature" reservation block).
2. Submit PR to <https://github.com/multiformats/multicodec> — single
   TSV file change + description that cites Viper Chain as a consumer
   and lists the in-tree spec authority (`crates/pqc-crypto/src/envelope.rs`).
3. Add a `// Multicodec: 0x...` comment next to each AlgId definition
   in `alg.rs`. The comment is the local source of truth until the
   upstream PR lands; once merged, both tables agree by construction.
4. SDK note (`sdk/typescript/README.md` + Python equivalent) that the
   mapping is canonical for cross-ecosystem interop (IPFS, libp2p
   stream protocols, multibase content addressing).

**Risk.** Maintainer review may rename / re-codepoint the proposed
slots. Re-assignment is a constants change, no wire-break — Viper's
canonical encoding is `algo_id: u16_le` (ADR-044), not the multicodec
varint, so the upstream codepoints exist purely for cross-ecosystem
interop.

**Closure criterion.** Multicodec PR merged AND `alg.rs` doc comments
match the merged codepoints.

---

### TASK-227 — Diversity targets enforcement + reporting

**Deliverable.**
- `scripts/compute-nakamoto.py` — reads on-chain validator set + jurisdictional metadata, computes Nakamoto coefficient weighted by `self_bond`.
- `reports/diversity/2026-Q2.md` — Y0 baseline against `viper-pq-1`.
- `/diversity` dashboard (frontend extension on `pqchain.agwswebconsulting.it`). **Separable** — chain-side delivery is the script + report; the dashboard is a website-repo task that pairs with TASK-232.

**Steps.**
1. Pin script consumes `/v1/validators` + per-validator jurisdiction metadata (the `validator-onboarding.md` evidence file). Computes:
   - Nakamoto coefficient (smallest validator subset whose combined `self_bond` ≥ 33% of total stake).
   - Top-client-implementation share (operator-self-declared at registration).
   - Distinct legal jurisdictions, geographic regions, hosting providers.
   - Output as JSON + markdown table.
2. Y0 baseline report — 3-validator state. The numbers are *bad* (NC=1 because all three live on the same operator infrastructure as of the Phase 8.5 launch). Frame this as "pre-cohort baseline; the Y2 cohort under TASK-185 is the closure target", per the methodology in `docs/long-horizon-roadmap.md` §5.
3. Frontend dashboard (deferred to website-repo work; pairs with TASK-232).
4. Quarterly cadence — script is regenerable; report is a new file under `reports/diversity/<UTC quarter>.md` per run. Operator workflow: cron the script monthly, review + publish quarterly.

**Risk.** Y0 baseline embarrassment: 3-validator NC=1 makes for an unflattering first report. Mitigation: explicit framing as "baseline before the cohort" + Y5/Y10 targets table.

**Closure criterion.** Script + Y0 report committed; first quarterly cadence run scheduled (Q3 2026).

---

### TASK-223 — Online consensus-key rotation

**Deliverable.** validator-record schema bump + `MsgType::ConsensusKeyRotateV2` apply path + slashing-evidence handling + 1 multi-node integration test rotating a validator from ML-DSA-65 to ML-DSA-87 mid-flight without restart.

**Steps.**
1. **Pre-flight.** Re-read ADR-046 + ADR-020 to identify the exact gap. Likely current schema has only `(consensus_alg_id, consensus_pk)` singletons; rotation requires `keys: Vec<KeyEntry>` with `valid_from_height` + `valid_until_height` for overlap.
2. **Schema bump.** Validator-record extension. Rides P-COMPAT-001 §2 — ADR + activation height + dual-path decoder + cold-sync replay-equivalence test pin update.
3. **Tx type.** `ConsensusKeyRotateV2 { old_pk_hash, new_alg_id, new_pk, sig_with_old, sig_with_new }`. Dual signature is BIP-39-style proof-of-possession on both keys.
4. **Apply.** Validator-record retains old key with `valid_until_height = current + N` epochs (overlap = 1 epoch). Slashing-evidence-registry MUST handle:
   - same-round double-sign with both keys = equivocation regardless of overlap window;
   - cross-round signing with either key inside window = OK;
   - signing with new key before `valid_from_height` = equivocation.
5. **Cold-sync test.** Extend `crates/pqc-consensus/tests/cold_sync_replay.rs` (TASK-198) with a fixture that performs a rotation. State-root pre/post must reproduce byte-identical.
6. **CLI.** `pqcd wallet rotate-consensus-key --keystore <old> --new-alg <id> --new-keystore <new>` + the runbook rotation procedure (now `docs/operators/RUNBOOK.md` §16).

**Risks.**
- **State-root format change.** P-COMPAT-001 §2(d) mandates green cold-sync replay BEFORE merge. If the fixture cannot reproduce state-root byte-identical, the PR is blocked.
- **Slashing semantics during overlap window.** Specify the equivocation rule above explicitly in the ADR; under-specification creates a slashing-evasion vector.
- **SDK migration.** Existing v1 `ConsensusKeyRotate` tx must still deserialize — `legacy_path_deprecation_epoch` clause per P-COMPAT-001 §7. ADR must commit a concrete deprecation epoch.

**Pairing.** Logically depends on TASK-228 (scale-up needs dynamic keystore anyway). Bundle 223 + 228 as a single workstream when attacked.

**Closure criterion.** Multi-node integration test green; cold-sync replay test green with the new fixture; ADR-046 supplement + the runbook rotation procedure (`docs/operators/RUNBOOK.md` §16).

---

### TASK-228 — Scale-up plan committee 256 → 1024

**Deliverable.** ADR-065 (reserved) + expanded section in
`docs/long-horizon-roadmap.md` §1 (currently a placeholder).

**Steps.**
1. Pin current 3-validator constraints:
   - `LocalProposer` test harness keystore caps at 3 keys (TASK-113 Step 6 stuck — this is a test-only constraint, not a chain-level one)
   - BFT quorum threshold `ceil((2N+1)/3)` grows with N → producer without all signing keys can't form commit (unblocked by TASK-223 + dynamic keystore)
   - P2P mesh: GossipSub `mesh_n=8` calibrated for 64-256 (TASK-222 done)
2. Step 64-validator (Phase 9 cohort target):
   - Unblock TASK-113 Step 6 via TASK-223 dynamic keystore
   - Fan-out 64-node testbed; 7-day soak under `viper-pq-1`
   - Hardware target: 8-core / 32 GB RAM / 1 TB NVMe per validator
3. Step 256-validator (Phase 10):
   - GossipSub IDONTWANT essential (already wired); peer-score telemetry mandatory (DONE TASK-222)
   - Hardware target: 16-core / 64 GB RAM / 2 TB NVMe
   - Block-time decision (TASK-186) becomes load-bearing — at 500 ms / 256 validators / 3 sigs the chain produces ~17 GB/h of pure consensus chatter
4. Step 1024+ (Phase 11+):
   - Gated on STARK aggregation maturity (long-horizon §1, Y4-Y6)
   - Without aggregation, commit-sig footprint is ~33 GB/day per validator at 1024 — not sustainable
   - Hardware target re-baseline depends on aggregation overhead (proof verify cost)
5. Hardware spec ladder per step

**Risk.** Numbers are speculative until TASK-185 cohort generates real data at scale. ADR is "design intent" not "commitment".

**Closure criterion.** ADR-065 + long-horizon §1 expansion committed.

---

### TASK-224 — Permissionless eligibility transition

**Deliverable.** ADR-066 (reserved) + `docs/permissionless-transition.md`.

**Steps.**
1. Document current closed-cohort gates:
   - ADR-013 size targets (24/32/50)
   - Manual onboarding via TASK-185
   - Operator runbook (`docs/validator-onboarding.md`) is the gate; no on-chain gate yet
2. Stake floor design — 3 scenarios:
   - **Low** (1k VENOM): broad participation, weak Sybil resistance
   - **Medium** (10k VENOM): balanced — likely landing point
   - **High** (100k VENOM): strong Sybil resistance, exclusive
   - Each scored against an economic-security model (cost-to-attack vs validator yield)
3. Anti-Sybil mechanics:
   - Proof-of-uniqueness via on-chain attestation hash (operator KYC hash registered on-chain — *hash only*, no full KYC; binding to a tax-ID-bound attestation)
   - ASN + /24 diversity restriction (already partial via ADR-041 `max_peers_per_asn`)
   - Slashing-evidence-registry windows extended for permissionless (validator set is now unbounded)
4. Phased opening:
   - Governance-controlled `permissionless_enabled` flag
   - Testnet rehearsal with N existing cohort validators + open registration
   - Gradual ramp 25% → 50% → 100% per quarterly governance vote
5. Slashing-evidence-registry evolution — current code assumes validator set is knowable; permissionless requires extending the window for slashing claims and accepting evidence against any validator that has *ever* been Active.

**Risk.** Anti-Sybil is the hard part; KYC introduces compliance scope creep. Likely output: "open at stake-floor X with no KYC; governance can pause if Sybil pattern observed".

**Closure criterion.** ADR-066 + design doc committed; on-chain `permissionless_enabled` flag wired (default false); testnet rehearsal scheduled.

---

### TASK-226 — FN-DSA evaluation post-FIPS-206-final

**Deliverable.** Governance proposal reserving AlgId `0x0010` + ADR-067 documenting the inclusion criteria and the deterministic-FP replay risk + (deferred to Q4 2027) `reports/fn-dsa-spike-2027-Q4.md`.

**Steps (now).**
1. Draft governance proposal `ProposalEffect::ReserveAlgIdRange(0x0010, "FN-DSA-padded-512", reserved_lifecycle)` — locks the slot ahead of FIPS 206 finalisation.
2. ADR-067 documenting:
   - Inclusion criteria (FIPS-final, ≥1 audited Rust impl, signature/pk size budget, sigverify cost target)
   - **Deterministic-FP replay risk**: Falcon-class signing (FN-DSA's foundation) depends on FP-deterministic Tonelli-Shanks. Cross-CPU-architecture FP determinism is NOT portable (rounding-mode differences between x86 / ARM / RISC-V). Pre-final adoption could ship signatures that one architecture validates and another rejects — a chain-halt class bug. Wait for FIPS-final spec to pin the determinism contract.
3. Governance proposal landed before Q4 2027 so the AlgId is reserved when the spike fires.

**Steps (deferred to Q4 2027).**
4. Rust spike on `fn-dsa-rs` or equivalent (depends on what's audited at that point)
5. Benchmark `sigverify_fee_v_X` on reference HW (fee class already parametrised for ML-DSA-65)
6. Governance proposal promoting `0x0010` from `Reserved` to `Active`

**Risk.** FIPS 206 timeline can slip. Reserving now is low-cost; spike is gated. Worst case: AlgId stays Reserved indefinitely, never promoted to Active — that's still better than not reserving.

**Closure criterion.** ADR-067 + governance proposal committed; AlgId 0x0010 in `Reserved` lifecycle on-chain.

---

### TASK-218 — QUIC + hybrid PQ TLS

**Deliverable.** Flip `hybrid-kem-tls` Cargo feature default-on + 2-week TCP+TLS co-existence soak + cutover.

**Pre-flight (NOT actionable today).**
- rustls-post-quantum API stabilisation status (last check: 2026-04-22 per `docs/historical/phase-8-m1-plan.md`)
- libp2p 0.56+ availability with QUIC + rustls-pq integration

**Steps (when triggered).**
1. Bump libp2p to 0.56+ in workspace
2. Wire X25519MLKEM768 in rustls config in `pqc-p2p::transport`
3. Verify QUIC listener on `/udp/.../quic-v1` works alongside TCP
4. **ClientHello fragmentation test** — capture QUIC Initial datagram in test, assert hybrid CH (~1.2 KB) fits one Initial. At MTU 1280 (IPv6 minimum) the CH may fragment; verify libp2p QUIC handles fragmentation per <https://tldr.fail>
5. 2-week testnet co-existence: both TCP+TLS and QUIC active, monitor handshake success rates per transport
6. Flip default to QUIC primary; remove TCP+TLS after soak

**Re-poll cadence.** Quarterly check of rustls-post-quantum stable releases. Update this doc's Pre-flight section when the trigger fires.

**Closure criterion.** QUIC primary on `viper-pq-1`; TCP+TLS fallback retained for 2 weeks then removed.

---

## Update cadence

- **Per-task land:** flip the `[planned]` → `[in-progress]` → `[closed (commit `<hash>`, YYYY-MM-DD)]` marker in the recommended-ordering table.
- **Quarterly:** re-poll TASK-218 trigger (rustls-pq stable + libp2p 0.56).
- **On scope change:** update the dependency graph + per-task detail.

The doc is intentionally short. New near-term-actionable items get a
new § when they land in TASKS.md; long-horizon items belong in
`docs/long-horizon-roadmap.md`, not here.
