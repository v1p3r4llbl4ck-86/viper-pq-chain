# Archival Overlay Specification

**Spec ID**: SPEC-ARCHIVAL-001
**Version**: 0.1
**Status**: Draft
**Date**: 2026-04-23
**Implements**: ADR-045 (Archival Overlay — SLH-DSA-SHAKE-256s + RFC 3161 Timestamping)
**Depends on**: ADR-043 (SLH-DSA-SHAKE-192s as Second PQ Algorithm), ADR-044 (Crypto Agility — TLV Envelope), ADR-042 (Dynamic Validator Set On-Chain), SPEC-GENESIS-001, SPEC-CONSENSUS-001
**References**: RFC 3161, RFC 4998, RFC 5816, ETSI TS 119 511, ETSI TS 119 512, BSI TR-03125 (TR-ESOR), FIPS 205, NIST SP 800-208

---

## 1. Scope

This specification defines the **archival overlay**: an independent, cryptographically decoupled layer that signs a per-epoch Merkle commitment of Viper PQ Chain block history with a hash-based signature scheme (SLH-DSA-SHAKE-256s) and anchors the resulting commitment to external qualified timestamp authorities per RFC 3161, then extends the validity horizon every ≤5 years via RFC 4998 ERS renewal.

In scope:
- wire format, CBOR encoding, and state-root binding of the on-chain `ArchivalRecord`
- epoch-root computation and domain separation
- SLH-DSA-SHAKE-256s signer-set policy (governance-controlled, threshold signing)
- RFC 3161 TSA integration (sidecar), failure modes, and anchor-redundancy policy
- RFC 4998 Evidence Record Syntax renewal procedure and cadence
- verification protocol for an external auditor in year N+20
- governance parameters and upgrade path

Out of scope:
- consensus finality (defined in SPEC-CONSENSUS-001)
- TLV envelope wire format (defined in ADR-044)
- transaction envelope (defined in SPEC-TX-001)
- validator set, churn, and slashing (defined in ADR-042 / SPEC-SLASH-001)
- RFC 3161 TSA provider selection at the operational level (listed in `docs/phase-8-m4-plan.md` §5)

---

## 2. Normative Language

RFC 2119. MUST / SHOULD / MAY carry their usual meaning. `consensus-critical` means a value whose byte-stable computation is part of the state root.

---

## 3. Purpose and Threat Model

### 3.1 The 20-year verifiability horizon

Viper PQ Chain's notarisation and attestation product commits the network to a **20-year verifiability horizon** (WHITEPAPER.md §2 and §7; `docs/phase-8-spec.md` §1): a receipt issued in year N MUST be verifiable against the chain's history in year N+20 by a third party with only the public artefacts (block headers, state roots, signatures, TSA counter-signs) in hand. This horizon is longer than the current confidence interval on either (a) the asymptotic hardness of structured-lattice problems or (b) the operational lifetime of any single TSA provider.

### 3.2 Cryptographic family diversity

ADR-006 and ADR-043 document the project's two-family doctrine:

- **Primary (hot path)**: ML-DSA-65 (CRYSTALS-Dilithium, lattice-based, FIPS 204). Confidence is *high today* and relies on assumptions about MLWE/MSIS hardness.
- **Secondary (second-opinion)**: SLH-DSA-SHAKE-192s (stateless hash-based, FIPS 205). Confidence rests only on the security of the hash function family; no algebraic structure is exploitable by Shor or by lattice-specific cryptanalysis.

The archival overlay sits one level above the secondary: the **archival-grade** algorithm is **SLH-DSA-SHAKE-256s** (FIPS 205, Category 5). It is used infrequently (once per epoch at most) precisely so its per-signature cost (sig 29 792 B, ~3 000 verify/s on reference hardware) is paid only at the overlay cadence.

### 3.3 Adversary model

The archival overlay is designed against the following threat sequence, stated with deliberate pessimism:

1. **Q-day (year N)**: a mature quantum adversary emerges. ML-DSA-65 remains unbroken *today* but the community confidence interval on lattice hardness narrows.
2. **Year N+10**: a classical cryptanalytic advance (e.g., a BKW-family refinement against MLWE, or an improved LLL variant producing sub-exponential structured-lattice attacks) reduces the effective security of ML-DSA-65 below its claimed Category 3 level.
3. **Year N+20**: an auditor examining a receipt issued at block height H (year N−1) must still be able to prove, to a third party, that block H was in fact committed by the chain at the claimed height, with the claimed contents, at the claimed wall-clock time.

The archival overlay MUST make this year-N+20 audit succeed even if **every** ML-DSA signature in the chain history is forgeable by year N+10. The required assurances at audit time are:

- **Existence**: the block H was in fact in the canonical chain at height H. Anchored by the SLH-DSA-SHAKE-256s signature over the epoch root in which H sits.
- **Temporal ordering**: the block existed *before* a given wall-clock time. Anchored by the RFC 3161 TSA counter-sign and, if needed, by the RFC 4998 ERS renewal chain.
- **Content integrity**: the block's bytes hash to the claimed value. Inherent in the Merkle-opening to `epoch_root`.

An adversary is explicitly NOT trusted to forge SHAKE-256 collisions or to break SLH-DSA-SHAKE-256s; these are the roots of trust of the overlay. This matches the NIST SP 800-208 stance on stateless hash-based signatures for long-term archival.

### 3.4 Out-of-scope attacks

- **Full TSA collusion against a chain slice**: if *every* TSA the chain anchored to during a specific epoch is subsequently compromised AND the SLH-DSA signature is broken, the temporal ordering of that epoch cannot be reconstructed. This is why §6.3 requires ≥ 2 anchors from operationally independent TSAs and §8 requires periodic ERS renewal: both reduce the attack surface to "all anchors at one moment AND a hash-family break", which is the floor any long-term preservation scheme hits.
- **Availability attacks on the archival record itself**: out of scope. The `ArchivalRecord` lives on-chain and is replicated via normal state sync; an adversary who can delete it from every validator has already won by a wider margin.

---

## 4. Overlay Architecture

### 4.1 Epoch root

At each epoch boundary (per ADR-042 `EpochInfo::is_epoch_boundary(h)` with mainnet `EpochConfig::mainnet()` giving ~1 hour epochs), every node computes:

```
epoch_root := SHAKE-256(
    "VIPER-ARCHIVAL-V1"
 || u64_be(epoch_number)
 || u64_be(first_height)
 || u64_be(last_height)
 || concat_i=first_height..=last_height(block_hash_i)
)
```

- output length 32 bytes (SHAKE-256 XOF truncated to 256 bits)
- domain-separation tag `"VIPER-ARCHIVAL-V1"` prevents collision with any other leaf in the state root (cf. the `VIPER-RECENT-SLASHES-V1` precedent in ADR-048)
- `block_hash_i` is the canonical consensus block hash (SPEC-CONSENSUS-001 §7.4), not the state root and not the commit-hash
- `concat` is byte-stable by iteration order `i = first_height ..= last_height` (ascending, no sort), so every honest node computes the same `epoch_root` independently

The `epoch_root` computation MUST be consensus-critical: two honest nodes at the same epoch boundary MUST produce byte-identical `epoch_root` values. Failure of this invariant is a state-root divergence and halts the chain on the next block.

### 4.2 Archival signer set

The set of validators who co-sign the `epoch_root` is governed by an on-chain parameter:

```
StateStore.archival_signer_set: BTreeSet<Address>
```

- **Initial value at genesis**: the full Active validator set at epoch 0 (mirrors ADR-042 bootstrap).
- **Mutation**: via `ProposalEffect::UpdateArchivalSignerSet` (SPEC-GOV-001 governance flow, 66% supermajority, 30-day timelock — reuses the ADR-042 pluggable-verifier precedent).
- **Invariant**: the signer set MUST be a subset of the validators with status `Active` at the epoch boundary. Governance proposals that would add non-Active validators are rejected at apply time.

### 4.3 Archival threshold

```
StateStore.archival_threshold_m_of_n: (u16 m, u16 n)
```

- **Default**: `(ceil(2 * |archival_signer_set| / 3), |archival_signer_set|)` — BFT-style 2/3 supermajority, matching SPEC-CONSENSUS-001 §6 commit-quorum.
- **Minimum invariant**: `m ≥ ceil(2 * n / 3)` enforced at proposal apply.
- **Rationale**: a strictly-less-than-2/3 archival quorum would make the archival claim weaker than the consensus claim it backs, inverting trust. `m = n` (unanimous) is permitted but operationally fragile (one offline signer halts archival).

### 4.4 ArchivalRecord

```
struct ArchivalRecord {
    epoch_number:           u64,
    first_height:           u64,
    last_height:            u64,
    epoch_root:             [u8; 32],                    // §4.1
    slh_sig_set:            Vec<(Address, Vec<u8>)>,     // §4.5
    timestamp_anchors:      Vec<TimestampAnchor>,        // §6
    evidence_record_version: u32,                        // §8 (0 = no renewal yet)
    created_at_height:      u64,                         // block that applied this record
}

struct TimestampAnchor {
    tsa_ref:       TsaRef,              // identifier of the TSA
    tst_bytes:     Vec<u8>,             // RFC 3161 TimeStampToken DER
    created_at:    u64,                 // unix seconds from TSA's genTime
    tsa_cert_ref:  CertRef,             // reference into §6.5 trust list
}

enum TsaRef {
    QualifiedEuTrustList(String),       // EU Trust List URI
    Bitcoin(OpReturnRef),               // optional, §6.4
    Other(String),                      // governance-added
}
```

Encoded as deterministic CBOR (SPEC-TX-001 §4 rules). `slh_sig_set` entries MUST be sorted ascending by `Address` (byte-lexicographic) to fix byte-stability.

### 4.5 SLH-DSA-SHAKE-256s signatures

Each entry `(addr_i, sig_i)` in `slh_sig_set` is an SLH-DSA-SHAKE-256s signature (FIPS 205, Cat 5, pk 64 B, sig 29 792 B) computed by validator `addr_i` over:

```
sig_preimage := "VIPER-ARCHIVAL-SIG-V1"
             || u64_be(epoch_number)
             || epoch_root
```

Domain separation MUST be distinct from any other signature preimage in the chain (consensus votes SPEC-CONSENSUS-001 §8.3, transaction envelopes SPEC-TX-001 §8, `VIPER-ARCHIVAL-V1` epoch-root domain §4.1).

Public keys for validator archival signing are **separate** from the consensus key (ADR-043 designates SLH-DSA for the archival overlay specifically to diversify family). Each validator registers an archival public key alongside (or after) consensus registration:

```
struct ValidatorArchivalKey {
    operator_addr:      Address,
    algo_id:            u16,                // 0x0023 (SLH-DSA-SHAKE-256s per ADR-044 registry)
    archival_pk:        Vec<u8>,            // 64 bytes
    registered_height:  u64,
}
```

Registered via a new `ValidatorRegisterArchivalKey` transaction (opcode allocated in the `0x04xx` validator-lifecycle range, adjacent to ADR-047's `ValidatorRotatePeerId`).

### 4.6 Apply semantics

At each epoch boundary height `h_boundary`:

1. On every node, `apply_block` computes `epoch_root` (§4.1) using blocks `first_height ..= last_height` of the epoch that just closed.
2. Designated archival signers (§4.2) each produce an SLH-DSA-SHAKE-256s signature over the §4.5 preimage using their registered `archival_pk`.
3. Any Active validator (not only signers) MAY submit an `ArchivalRecordSubmit` transaction assembling ≥ `m` signatures. The transaction is admissible only if:
   - `epoch_root` matches the network's own computation (locally recomputed at admission);
   - every `(addr_i, sig_i)` verifies under `addr_i`'s registered archival pk via the `PqVerifier` dispatch (ADR-044);
   - the number of verified signatures ≥ `archival_threshold_m_of_n.m`;
   - `addr_i` was in `archival_signer_set` at `h_boundary`.
4. On apply, the `ArchivalRecord` is inserted into `StateStore.archival_records` keyed by `epoch_number`. Only the first admitted record for a given epoch wins; duplicates are rejected.
5. The TSA anchor (§6) and ERS renewal (§8) are added by subsequent `ArchivalRecordAddAnchor` / `ArchivalRecordRenew` transactions; they do not alter the signer set or `epoch_root`.

### 4.7 Not in the consensus hot path

The archival overlay runs **one level above** consensus finality. A block at epoch-boundary height commits normally (SPEC-CONSENSUS-001 §6) and the next block builds on it whether or not the epoch's archival record has yet been submitted. A failure to assemble the record delays external anchoring but does not halt the chain.

Rationale: the archival signature is hash-based and slow (~3 000 verify/s); putting it on the commit path would add seconds to block time. Moreover, by §6 the TSA counter-sign is necessarily out-of-consensus (it comes from an external network service). De-coupling the on-chain record from the external anchor keeps the chain live when TSAs are temporarily unreachable.

---

## 5. On-Chain State

Adds one consensus-critical column to `StateStore`:

```
pub struct StateStore {
    ...
    pub archival_records:        BTreeMap<u64, ArchivalRecord>,   // keyed by epoch_number
    pub archival_signer_set:     BTreeSet<Address>,
    pub archival_threshold_m_of_n: (u16, u16),
    pub archival_keys:           BTreeMap<Address, ValidatorArchivalKey>,
    pub archival_tsa_endpoints:  Vec<TsaEndpoint>,                // §6.5, governance-mutable
    pub archival_renewal_period_blocks: u64,                      // §8, default 5 years
}
```

The state-root folding (ADR-030, `VIPER-STATE-V2`) hashes each field under a distinct domain tag:

- `VIPER-ARCHIVAL-RECORDS-V1` for `archival_records`
- `VIPER-ARCHIVAL-SIGNERS-V1` for `archival_signer_set`
- `VIPER-ARCHIVAL-THRESH-V1` for `archival_threshold_m_of_n`
- `VIPER-ARCHIVAL-KEYS-V1` for `archival_keys`
- `VIPER-ARCHIVAL-TSA-V1` for `archival_tsa_endpoints`
- `VIPER-ARCHIVAL-RENEWAL-V1` for `archival_renewal_period_blocks`

Snapshot-sync byte-stability is preserved: `BTreeMap` / `BTreeSet` iteration is ascending by key, and fields are consensus-critical with deterministic CBOR encoding (SPEC-TX-001 §4).

---

## 6. External Timestamp Anchor

### 6.1 RFC 3161 — Time-Stamp Authority

For each accepted `ArchivalRecord`, at least one RFC 3161 TSA MUST be queried to produce a `TimeStampToken` (TST) over the hash `SHAKE-256("VIPER-ARCHIVAL-TSA-V1" || epoch_number || epoch_root)`. The TST binds the hash to `genTime` under the TSA's own X.509 certificate.

Request/response flow (per RFC 3161 §2):
1. Sidecar computes `digest = SHA-256(tsa_preimage)` (SHA-256 is the mandatory-to-implement hash per RFC 3161; RFC 5816 adds SHA-384/512 options — see §6.6).
2. Sidecar builds `TimeStampReq` with `messageImprint.hashAlgorithm = id-sha256` and `messageImprint.hashedMessage = digest`.
3. Sidecar POSTs to the TSA's `application/timestamp-query` endpoint (HTTPS mandatory).
4. On `200 OK` with `TimeStampResp.status.status = granted`, the embedded `timeStampToken` (CMS `SignedData` structure) is the TST.
5. Sidecar submits an `ArchivalRecordAddAnchor` transaction carrying the TST bytes and the TSA reference.

The chain does NOT verify the TST cryptographically on apply (RFC 3161 TST verification requires an X.509 chain walk against the TSA's cert and the EU Trust List — out of reach for a Rust consensus module without bringing in a full PKI stack). Instead, the chain records the TST bytes verbatim and defers verification to the auditor at proof time (§7). This matches ETSI TS 119 512 §7.2 "preservation-with-external-verification".

### 6.2 RFC 5816 — ESSCertIDv2

For TSAs that support it, requests SHOULD include `reqPolicy` consistent with ETSI EN 319 422 §5.2 and `certReq = TRUE` so the response carries `ESSCertIDv2` in `SigningCertificateV2` (RFC 5816). This hardens the auditor-side path against ambiguity in cert-chain selection when the TSA has multiple signing certs.

### 6.3 Anchor redundancy

```
archival_tsa_endpoints: Vec<TsaEndpoint>
    // governance-mutable via ProposalEffect::UpdateArchivalTsaEndpoints

struct TsaEndpoint {
    name:           String,
    url:            String,
    trust_category: TsaTrustCategory,
    mandatory:      bool,              // see §6.3
}

enum TsaTrustCategory {
    EuQualified,         // eIDAS-qualified per EU Trust List
    EuAccredited,        // non-qualified but accredited
    Commercial,          // GlobalSign, DigiCert, etc.
    SecondaryChain,      // Bitcoin OP_RETURN, Ethereum L1, §6.4
}
```

**Invariant** (enforced at apply of `ArchivalRecordAddAnchor`): after all anchors for an epoch are recorded, the record MUST carry:

- at least **2** anchors with `trust_category ∈ {EuQualified, EuAccredited}`, AND
- at least **1** anchor with `mandatory = true` successfully attached within 24 hours of the epoch boundary.

If the invariant cannot be satisfied in the 24-hour window (e.g. two EU-qualified TSAs simultaneously down), the epoch's record remains in a `pending_anchor` state: the `epoch_root` and SLH-DSA signatures are already committed on-chain, so the integrity claim holds; only the temporal-ordering claim is postponed until anchors land. `pqchain_archival_records_pending_anchor` metric exposes the state.

### 6.4 Optional second anchor: Bitcoin / Ethereum L1

A secondary anchor via Bitcoin OP_RETURN or Ethereum L1 calldata is **optional and nice-to-have**, not part of the invariant in §6.3. Rationale:

- Bitcoin OP_RETURN: ~$0.50/tx at current fee levels; adds a proof-of-publication anchor with a 14-year track record. An auditor in year N+20 may value a Bitcoin-chain anchor more than a TSA cert whose issuer has since dissolved.
- Ethereum L1: more expensive (~$5–50/tx depending on gas), but richer read-surface (ERC-standard interfaces). Less attractive than Bitcoin for pure timestamping.

Governance MAY enable either via `ProposalEffect::AddArchivalAnchorKind` once the TSA cadence is stable.

### 6.5 Initial TSA provider list

The bootstrap `archival_tsa_endpoints` list at genesis MUST contain ≥ 3 operationally independent eIDAS-qualified TSAs (ETSI TS 119 511 §6.2). The concrete choice is deferred to `docs/phase-8-m4-plan.md` §5 but the current proposal is:

1. **Aruba QTSA** (IT, EU Trust List) — mandatory.
2. **InfoCert TSA** (IT, EU Trust List) — mandatory.
3. **Namirial TSA** (IT, EU Trust List).
4. **TrustPro Cloud TSA** (EU Trust List).

"Operationally independent" means different corporate owner, different physical data-centre provider, different upstream power/network operator. ETSI TS 119 511 §7 requires `≥ 2` and recommends `≥ 3`; we take the recommendation as mandatory for an L1 with a 20-year horizon.

Cost estimate: at ~€0.10–0.50 per TST and an epoch cadence of 1/hour (8 760 epochs/year) × 2 TSAs = 17 520 TSTs/year, annual cost is **€1 752 – €8 760**. Documented in the M4 plan (§4 of `docs/phase-8-m4-plan.md`).

### 6.6 Hash algorithm for TSA digests

The §6.1 preimage is hashed with SHA-256 for interoperability (RFC 3161 mandatory-to-implement). A secondary digest with SHAKE-256 is RECOMMENDED once a TSA on the list supports SHA-3/SHAKE hashing per RFC 5816 extensions. Until then, the chain's own SHAKE-256 domain-separation lives at the `epoch_root` layer; SHA-256 only appears in the TSA preimage, where it inherits TSA-side constraints rather than ours.

---

## 7. External Verification Protocol

An external auditor in year N+20 verifies a receipt for block H as follows. Inputs: the block bytes `B`, the claimed height `H`, the claimed consensus block hash `h_B`, and a public snapshot of the chain's state at some later height `H' > H` (the `archival_records` column carries the anchor).

### 7.1 Step 1 — Locate the epoch record

Compute `epoch_number := EpochInfo::for_height(H).epoch_number` using the ADR-042 epoch schedule as it was at height H. (Epoch length is governance-mutable; the auditor walks the `archival_renewal_period_blocks` history column to reconstruct the schedule if changed.) Fetch `r := state.archival_records[epoch_number]`.

### 7.2 Step 2 — Recompute and match epoch root

```
block_hashes_h = [ consensus_block_hash(block_at_height(h)) for h in r.first_height ..= r.last_height ]
candidate_epoch_root = SHAKE-256(
    "VIPER-ARCHIVAL-V1"
 || u64_be(r.epoch_number)
 || u64_be(r.first_height)
 || u64_be(r.last_height)
 || concat(block_hashes_h)
)
assert candidate_epoch_root == r.epoch_root
```

The block at height H MUST sit inside `[r.first_height, r.last_height]` and `consensus_block_hash(B) == h_B`. Matching here proves **existence** of block H inside the epoch that was archived.

### 7.3 Step 3 — Verify the SLH-DSA signature set

For each `(addr_i, sig_i) ∈ r.slh_sig_set`:

```
pk_i = state.archival_keys[addr_i].archival_pk  // as of r.created_at_height
preimage = "VIPER-ARCHIVAL-SIG-V1" || u64_be(r.epoch_number) || r.epoch_root
assert SLH_DSA_SHAKE_256s_verify(pk_i, preimage, sig_i)
```

The auditor requires `|verified_sigs| ≥ r.archival_threshold_m_of_n.m` where the threshold is the one recorded at `r.created_at_height`. SLH-DSA verification is purely hash-based: no lattice or number-theoretic assumption is invoked. This step carries the integrity claim even if ML-DSA-65 is fully broken.

### 7.4 Step 4 — Verify the TSA counter-signs

For each `a ∈ r.timestamp_anchors`:

1. Parse `a.tst_bytes` as an RFC 3161 `TimeStampToken` (CMS `SignedData`).
2. Verify the CMS signature over the TST `TSTInfo` using the TSA's signing cert referenced in `a.tsa_cert_ref`.
3. Verify the cert chain back to a trust anchor in the EU Trust List snapshot that covered `a.created_at` (the auditor has access to historic EU Trust List dumps per ETSI TS 119 612).
4. Extract `TSTInfo.genTime` and `TSTInfo.messageImprint.hashedMessage`.
5. Assert `messageImprint.hashedMessage == SHA-256("VIPER-ARCHIVAL-TSA-V1" || u64_be(r.epoch_number) || r.epoch_root)`.
6. The validity of the TSA's own cert at `genTime` MUST be within the cert's validity window (no OCSP required — the TST itself is evidence of the cert being valid at `genTime`).

The auditor requires ≥ 2 TSTs to verify under §6.3 category rules. This step carries the **temporal ordering** claim.

### 7.5 Step 5 — Follow the ERS renewal chain (if > 5 years old)

If `now - a.created_at > archival_renewal_period_blocks / blocks_per_second × (5 years)` (roughly: if the record is older than one renewal period), the auditor follows forward through `r.evidence_record_version` to the most recent renewal record. Each renewal (§8) is itself a timestamped hash over the previous ERS, building an RFC 4998 `EvidenceRecord` chain. The auditor verifies each link's TSA signature and each link's hash-chain concatenation.

### 7.6 Step 6 — Merkle-open to prove block-in-epoch inclusion

The final step proves block H's specific contents are in the epoch:

```
merkle_proof = derive_epoch_merkle_proof(block_at_height(H), r.first_height, r.last_height)
assert merkle_open(h_B, merkle_proof) == r.epoch_root
```

(§4.1 defines `epoch_root` as a flat SHAKE-256 over the concatenated block hashes — not a Merkle tree. For V1 the "open" is literal recomputation of step 2 with the auditor's copy of the block; a Merkle tree variant is deferred to V2 when the epoch length grows past ~1 000 blocks and recomputation cost matters.)

### 7.7 Proof bundle format

An auditor-deliverable proof bundle for block H is:

```
ArchivalProof {
    block:                    Block,
    block_height:             u64,
    epoch_record:             ArchivalRecord,
    epoch_block_hashes:       Vec<[u8; 32]>,        // §7.2 Merkle witness
    archival_key_snapshot:    Vec<ValidatorArchivalKey>, // §7.3 pk set
    trust_list_snapshot_ref:  String,               // §7.4 EU Trust List URL + date
    ers_renewal_chain:        Vec<EvidenceRecord>,  // §7.5, possibly empty
}
```

Size: ≤ 5 MB for typical 1-hour epoch with 7 200 blocks of 500 ms cadence. Encoded as deterministic CBOR. The chain's public API SHALL expose `GET /v1/archival/proof?height={H}` returning the bundle.

---

## 8. RFC 4998 Evidence Record Syntax Renewal

### 8.1 Why renewal

RFC 4998 §1: a cryptographically signed timestamp has a validity horizon bounded by (a) the lifetime of the signing certificate and (b) the expected service life of the hash function used. Renewal re-anchors the old evidence by hashing it (with a current-generation hash) and re-timestamping. The chain of renewals is the RFC 4998 `EvidenceRecord`.

ETSI TS 119 512 §6 defines the same operation as "preservation-without-signature" for long-term archival. BSI TR-03125 (TR-ESOR) aligns with this.

### 8.2 Cadence

`archival_renewal_period_blocks`, default equivalent to **5 years** (at 500 ms mainnet cadence: `5 × 365.25 × 86 400 × 2 = 315 576 000 blocks`). Governance may shorten this (e.g. to 4 years during a perceived hash-function weakening event) but not extend it past 10 years — consistent with ETSI TS 119 512 §6.3 guidance.

### 8.3 Renewal procedure

At each renewal horizon (tracked by `last_renewed_at_height` per record):

1. The archival sidecar builds a new `renewal_preimage := "VIPER-ARCHIVAL-ERS-V1" || u32_be(current_ers_version) || SHAKE-256(previous_evidence_record)`.
2. A fresh RFC 3161 TST is requested from ≥ 2 EU-qualified TSAs against `SHA-256(renewal_preimage)` (or SHA-512 if then standard).
3. The new TSTs plus the previous `EvidenceRecord` are bundled as an `EvidenceRecord_v{N+1}` per RFC 4998 `ArchiveTimeStampChain` syntax.
4. A single `ArchivalRecordRenew` transaction submits the bundle for all epochs whose renewal horizon has expired since the last run; one bundle can cover many epochs.
5. On apply, `archival_records[epoch].evidence_record_version` is incremented and the latest ERS is stored (older ones are retained by full archive nodes via §8.4).

The renewal sidecar runs as a **cron job**, `once per 6 months during early operation**, migrating to `once per quarter` as the chain grows. It is out-of-consensus (sidecar identical in shape to the §6.1 RFC 3161 sidecar).

### 8.4 Retention

Full archive nodes retain the complete ERS chain (prior versions are needed to verify the chain). Pruned nodes retain only the latest `EvidenceRecord_v{N}` per epoch; the earlier links are recoverable from archive nodes via `GET /v1/archival/ers-history?epoch={E}`. An auditor wanting to verify a year-N+20 receipt will fetch the full history on demand.

### 8.5 Failure mode

If renewal fails past the horizon (e.g. no TSA available), the record enters `renewal_overdue` status. The integrity claim (epoch_root + SLH-DSA) remains unaffected; only the RFC 4998 chain is truncated at the last successful renewal. ETSI TS 119 512 §6.4 permits a grace period; the chain MUST emit `pqchain_archival_renewal_overdue` for operator attention and SHOULD attempt renewal with fallback TSAs before the horizon + 30 days expires.

---

## 9. Alignment With ETSI TS 119 511 / 512 and BSI TR-03125

### 9.1 ETSI TS 119 511 — "Policy and security requirements for preservation services"

Mapping of the spec to ETSI TS 119 511 clauses:

| TS 119 511 Clause | SPEC-ARCHIVAL-001 Section |
|-------------------|---------------------------|
| §5 Preservation objectives | §3 (threat model, 20-year horizon) |
| §6.2 Independence of TSAs | §6.3, §6.5 (≥ 2 anchors, operational independence) |
| §6.3 Preservation evidence | §4 (ArchivalRecord), §8 (ERS renewal) |
| §7.2 External verification model | §7 (auditor protocol) |
| §8 Audit and monitoring | `pqchain_archival_*` metrics (§10) |

### 9.2 ETSI TS 119 512 — "Protocols for trust service providers providing long-term preservation"

Mapping to key TS 119 512 operations:

| TS 119 512 Operation | SPEC-ARCHIVAL-001 Section |
|----------------------|---------------------------|
| `PreservePO` (preserve evidence) | §4.6, §6.1 (SLH-DSA + TST) |
| `RetrievePO` | §7.7 (`GET /v1/archival/proof`) |
| `ValidatePO` | §7.1–§7.6 (auditor protocol) |
| Preservation Strategy `PDS-I` / `PDS-II` | §8 (ERS renewal) maps to `PDS-II` (evidence with TST renewal) |

### 9.3 BSI TR-03125 (TR-ESOR) — "Beweiswerterhaltung kryptographisch signierter Dokumente"

TR-03125 Modul M.1 ("ArchiSafe") and M.2 ("ArchiSig") alignment is intentional. The chain's `ArchivalRecord` conceptually corresponds to an ArchiSig "ArchiveTimeStampSequence" (ATSS), and the renewal cadence in §8.2 matches the TR-ESOR Modul M.3 "CryptoModule" guidance for hash- and signature-algorithm renewal horizons. The chain does **not** ship a certified ArchiSafe-compliant module (that would require an audit against the TR-ESOR criteria by a BSI-accredited party); what it ships is an *interoperable* evidence format that a BSI-accredited preservation service could consume verbatim.

### 9.4 RFC references

| RFC | Role |
|-----|------|
| RFC 3161 | Core TSA protocol; §6.1 |
| RFC 5816 | ESSCertIDv2 for unambiguous cert binding; §6.2 |
| RFC 4998 | Evidence Record Syntax (ERS); §8 |
| RFC 6283 | XML variant of ERS — not used, CBOR is the chain's encoding |

---

## 10. Metrics

Prometheus metrics exposed by `pqcd` (scraped by the existing `/v1/metrics` endpoint):

| Metric | Type | Meaning |
|--------|------|---------|
| `pqchain_archival_records_total` | counter | total `ArchivalRecord` entries applied |
| `pqchain_archival_records_pending_anchor` | gauge | records with `|timestamp_anchors| = 0` |
| `pqchain_archival_records_pending_threshold` | gauge | epochs whose SLH-DSA threshold has not yet been met |
| `pqchain_archival_tsa_requests_total{tsa=…,outcome=…}` | counter | requests to each TSA, `outcome ∈ {granted,rejected,timeout,error}` |
| `pqchain_archival_renewal_current_version` | gauge | max `evidence_record_version` across all records |
| `pqchain_archival_renewal_overdue` | gauge | records whose renewal horizon has elapsed |
| `pqchain_archival_sig_bytes_total` | counter | cumulative SLH-DSA signature bytes stored |
| `pqchain_archival_sign_duration_seconds` | histogram | per-validator SLH-DSA sign latency (sidecar-reported) |

These are in addition to the existing `pqchain_p2p_*` and consensus metrics. All metric names follow the `pqchain_<area>_<measure>_<unit>` convention documented at TASK-051 and in the operator runbook (`docs/operators/RUNBOOK.md`).

---

## 11. Governance Parameters

| Parameter | Type | Default | Range | Proposal Effect |
|-----------|------|---------|-------|-----------------|
| `archival_signer_set` | `BTreeSet<Address>` | all Active @ genesis | subset of Active | `UpdateArchivalSignerSet` |
| `archival_threshold_m_of_n` | `(u16, u16)` | `(ceil(2n/3), n)` | `m ≥ ceil(2n/3)` | `UpdateArchivalThreshold` |
| `archival_tsa_endpoints` | `Vec<TsaEndpoint>` | §6.5 list (≥3 EU-qualified) | `≥ 2 EuQualified` | `UpdateArchivalTsaEndpoints` |
| `archival_renewal_period_blocks` | `u64` | 315 576 000 (≈ 5 y) | `≤ 10 y` equivalent | `UpdateArchivalRenewalPeriod` |
| `archival_enabled` | `bool` | `true` | `{true,false}` | `DisableArchival` (emergency) |

All proposals follow SPEC-GOV-001 §5 supermajority (66%) and §5.3 30-day timelock, except `DisableArchival` which is ⅘-emergency per SPEC-GOV-001 §7.4 (used only if a TSA compromise requires temporary suspension).

---

## 12. Security Considerations

### 12.1 SLH-DSA key custody

Each validator's archival private key is stored alongside the consensus key with equivalent operational protections (SPEC-TEST-001 §6: encrypted keystore, Argon2id KDF, XChaCha20-Poly1305). Rotation cadence: rotation of the archival key does NOT invalidate past signatures (the chain stores which `archival_pk` was active at which height), so rotation is a cheap defensive operation. Recommendation: ≥ once per 3 years.

### 12.2 TSA compromise

A compromised TSA can issue a TST with a forged `genTime`. Mitigations baked in:

- ≥ 2 independent TSAs required (§6.3): forging the timeline requires simultaneously compromising both.
- RFC 4998 ERS renewal (§8) every ≤ 5 years: a TSA compromise discovered at renewal time can be isolated — subsequent renewals use different TSAs and carry forward the SLH-DSA + epoch-root integrity claim intact.
- EU Trust List snapshots (§7.4) are append-only historic records: the auditor uses the snapshot as-of the TST's `genTime`, not a current snapshot, so retroactive delisting of a TSA does not invalidate old TSTs but does block the TSA from fresh anchors.

### 12.3 Algorithm rollover

If SHAKE-256 is ever found weakened, the renewal step (§8.3) is the migration point: a new `EvidenceRecord` version can specify `SHAKE-384` or `SHA3-512` for the ERS preimage hash. The on-chain `ArchivalRecord.epoch_root` itself is immutable at SHAKE-256; an auditor in the post-rollover era verifies the historic root with historic SHAKE-256 code (maintained in `crates/pqc-crypto/legacy/`) and the renewal chain with current-generation hashes.

### 12.4 Downgrade and replay resistance

The §4.5 signature preimage binds `epoch_number`, so an attacker cannot replay an epoch-N signature as epoch-M. The §6.1 TSA preimage binds `epoch_number` and `epoch_root`, so a TST cannot be reused across epochs. Both preimages carry distinct domain separation tags from every other chain signature.

### 12.5 Observability

The §10 metrics expose every relevant failure mode; the operator runbook (`docs/operators/RUNBOOK.md`) specifies the operator playbook for each metric.

---

## 13. Test Strategy

| Layer | Test ID | Coverage |
|-------|---------|----------|
| Unit | T1 | `epoch_root` byte-stability across two nodes at the same epoch |
| Unit | T2 | SLH-DSA-SHAKE-256s sign+verify roundtrip against real backend (not stub) |
| Unit | T3 | `ArchivalRecord` CBOR encode/decode roundtrip, deterministic |
| Unit | T4 | Tampered `epoch_root` rejected at admission |
| Unit | T5 | Signer not in `archival_signer_set` rejected |
| Unit | T6 | Threshold-met / threshold-short cases |
| Integration | T7 | 3-node devnet reaches an epoch boundary, all 3 compute the same `epoch_root`, all 3 co-sign, `ArchivalRecord` applies |
| Integration | T8 | TSA-sidecar fake-server returns a TST, `ArchivalRecordAddAnchor` applies, `pqchain_archival_records_pending_anchor` decrements |
| Integration | T9 | ERS renewal roundtrip: 5-year-equivalent time warp, renewal bundle applies, `evidence_record_version` increments |
| Spec | T10 | Deterministic-CBOR vs. reference encoding fixture (check against ETSI TS 119 512 example vector) |
| Spec | T11 | External-auditor proof bundle reconstructs successfully with only `epoch_record + EU Trust List snapshot + SLH-DSA pk set` (no access to chain) |

---

## 14. Open Items

| # | Item | Target |
|---|------|--------|
| O1 | Merkle-tree variant of `epoch_root` for epochs > 1 000 blocks (V2) | Phase 9 |
| O2 | Bitcoin OP_RETURN anchor (§6.4) | Post-audit |
| O3 | `archival_keys` rotation transaction (`ValidatorRotateArchivalKey`) | TASK-163 |
| O4 | Formal proof (Quint/TLA+) that the §7 verification protocol is sound under `SHAKE-256 collision resistance + SLH-DSA unforgeability + TSA counter-sign unforgeability` | post-M4 audit |
| O5 | Define exact `tsa_cert_ref` format (URI vs. SKI vs. hash) | during TASK-164 |

---

## 15. References

- FIPS 205 — Stateless Hash-Based Digital Signature Standard (August 2024)
- NIST SP 800-208 — "Recommendation for Stateful Hash-Based Signature Schemes"
- RFC 3161 — Internet X.509 PKI Time-Stamp Protocol (TSP)
- RFC 4998 — Evidence Record Syntax (ERS)
- RFC 5816 — ESSCertIDv2 Update for RFC 3161
- ETSI TS 119 511 — Policy and security requirements for trust service providers providing long-term preservation of digital signatures
- ETSI TS 119 512 — Protocols for trust service providers providing long-term preservation
- ETSI EN 319 422 — Policy and security requirements for trust service providers issuing time-stamps
- BSI TR-03125 — "Beweiswerterhaltung kryptographisch signierter Dokumente" (TR-ESOR)
- ADR-043, ADR-044, ADR-045, ADR-048 (DECISIONS.md)
- SPEC-CONSENSUS-001, SPEC-GENESIS-001, SPEC-TX-001 (specs/)
- `docs/phase-8-m4-plan.md` — implementation plan
