# SDK Changelog

This file tracks changes to the Viper PQ Chain client SDKs:

- `@v1p3r4llbl4ck/sdk` (TypeScript) at `sdk/typescript/`
- `viper-pqchain` (Python) at `sdk/python/`

Both SDKs ship in lockstep and share a major.minor.patch line.
The chain itself uses the `viper-pq-1-vX.Y.Z` tag scheme (top-level
`CHANGELOG.md`); the SDK changelog is separate to keep dependency
diffs reviewable independently of node-binary diffs.

## [0.3.0] - 2026-04-25

Aligns the SDK surface with the 7 new public read endpoints landed in
pqcd `880e29c` (2026-04-25). All changes are additive — every 0.2.0
caller continues to compile and run unchanged. Two pre-existing methods
(`getValidator` / `get_validator`, `getAccountAttestations` /
`get_account_attestations`) had their return types widened to track the
new `{ "data": ... }` envelope and richer fields the server now exposes;
the method names, arg lists, and error semantics are unchanged.

### Added

- **7 typed read methods** aligned to pqcd `880e29c`:
  - `getAlgorithms` / `get_algorithms` — `GET /v1/algorithms`
  - `getAlgorithm` / `get_algorithm` — `GET /v1/algorithms/:alg_id`
  - `getValidator` / `get_validator` — `GET /v1/validators/:address`
    (now returns the richer `ValidatorDetail` with `consensus_pk_hex`,
    `node_id`, `registered_height`, `self_bond`, `tombstoned`)
  - `getAccountAttestations` / `get_account_attestations` —
    `GET /v1/accounts/:address/attestations` (now returns
    `AttestationSummary[]`)
  - `getProposals` / `get_proposals` — `GET /v1/governance/proposals`
  - `getProposal` / `get_proposal` —
    `GET /v1/governance/proposals/:proposal_id`
  - `getProposalVotes` / `get_proposal_votes` —
    `GET /v1/governance/proposals/:proposal_id/votes`

- **New types**: `AlgorithmEntry`, `ValidatorDetail`, `AttestationSummary`,
  `ProposalSummary`, `ProposalDetail`, `ProposalVotes`, `VoteRecord`.
  `AlgorithmEntry.benchmark_verify_per_sec` and `AlgorithmEntry.min_fee`
  are deliberately **optional** so the SDK works unchanged before AND
  after a parallel pqcd commit redacts those calibration-internal fields
  from the public response. Consumers that read those fields MUST
  null-check.

- **Envelope-aware error handling**: the `ViperError.code` field is now
  populated from both the legacy flat `{"error":"...","code":"..."}`
  shape and the new nested `{"error":{"code":"...","message":"..."}}`
  shape used by the 0.3.0 endpoints. Existing callers see no behavioural
  change for the older endpoints.

### Notes

- Backwards-compatible with 0.2.0 — no breaking changes. `Validator`
  (list shape) is retained alongside the new `ValidatorDetail`; the
  `Attestation` per-id shape is retained alongside the new
  `AttestationSummary`. The two methods whose return types widened
  (`getValidator`, `getAccountAttestations`) hit the same URLs they
  always did; the server changed, not the SDK contract.
- Cross-link to API.md sections that document each endpoint:
  - `/v1/algorithms` → API.md §"Algorithm Registry"
  - `/v1/validators/{address}` → API.md §"Validators / Detail"
  - `/v1/accounts/{address}/attestations` → API.md §"Accounts / Attestations"
  - `/v1/governance/proposals` → API.md §"Governance / Proposals"
  - `/v1/governance/proposals/{id}` → API.md §"Governance / Proposal Detail"
  - `/v1/governance/proposals/{id}/votes` → API.md §"Governance / Vote Roster"

### Packaging

- TypeScript `package.json`:
  - `version` → `0.3.0`.
  - `description` extended to mention the new public read surface.
  - `keywords` add `governance`, `algorithm-registry`.
- Python `pyproject.toml`:
  - `version` → `0.3.0`.
  - `description` extended to mention the new public read surface.
- Python `viper_pqchain/__init__.py`: `__version__ = "0.3.0"` and
  re-exports for the 7 new types.

## [0.2.0] - 2026-04-25

Published 2026-04-25T14:41Z to npm (`@v1p3r4llbl4ck/sdk@0.2.0`,
shasum `8bf90dbe401b4d41fbf60a0c2694c22f6d91205b`) and PyPI
(`viper-pqchain==0.2.0`, wheel + sdist) following the live launch
of `viper-pq-1` on the 3 dev hosts (commit `40712f0`). The 0.1.0
versions on both registries (published 2026-04-20 against the
viper-mainnet-1 / viper-devnet-2 era) stay available but track an
older chain_id and pre-ADR-053 type shapes; consumers should pin
0.2.0 from this release onwards.

### viper-pq-1 launch architecture (ADR-053) alignment

First release tracking the permanent `viper-pq-1` development chain. The
0.1.0 line targeted the retired `viper-devnet-2`/`-3` chain_ids and the
pre-ADR-053 protocol shape. This release migrates the SDK surface to
ADR-053 without breaking any existing call sites: every new field is
optional on read, every new method parameter has a backward-compatible
default. Consumers that were green on 0.1.0 stay green on 0.2.0.

#### Changed

- **chain_id default → `viper-pq-1`** (ADR-053 §T1.3, TASK-206). New
  exported constants: `DEFAULT_CHAIN_ID = "viper-pq-1"` and
  `DEFAULT_CHAIN_ID_HEX = "76697065722d70712d31"`. The TS smoke test's
  `VIPER_EXPECT_CHAIN_ID` env-var default flips from `viper-devnet-2`
  to `viper-pq-1`.

#### Added

- **`BlockHeader` v1 fields** (ADR-053 §T1.1, TASK-205). Optional fields
  on the SDK type, populated by ADR-053-aware nodes:
  - `header_version` — explicit `u16` version slot, viper-pq-1 emits `1`.
  - `timestamp_ns` — Unix nanoseconds as a decimal string (carries beyond
    year 2554, retiring the Bitcoin-2106/Ethereum-uint32 timestamp class).
  - `extension_root` — 32-byte Merkle commitment over the future
    key→value extension map. At v1 launch always the canonical
    `tagged_hash("VIPER-EXT-EMPTY-V1", &[])` (ADR-053 §T3.4 reservation).

- **`Account` smart-account fields** (ADR-053 §T3.5, TASK-205). Optional
  fields on the SDK type, populated by ADR-053-aware nodes:
  - `verifier_template_id` — `u16`. Default EOA template = `0x0001`.
  - `auth_data` — template-specific auth-data hex; MUST be empty under
    the EOA template.

  New exported constants: `VERIFIER_TEMPLATE_ID_EOA = 0x0001`,
  `VERIFIER_TEMPLATE_CORE_RESERVED_MAX = 0x000F`,
  `VERIFIER_TEMPLATE_GOV_MIN = 0x0010`.

- **Multi-dimensional fee market** (ADR-053 §T2.1, TASK-201). Optional
  `multi_dim_fee` field on `GovernanceParameters` plus a new exported
  `MultiDimFee` shape with `compute_base_fee_venom`, `storage_base_fee_venom`,
  `witness_base_fee_venom`, `contention_base_fee_venom`. The single-dimension
  scalar fields (`base_fee_venom`, `byte_fee_venom`, `sigverify_fee_venom`)
  are retained for backward compatibility — they mirror the compute
  dimension under ADR-053.

- **Storage fund** (ADR-053 §T2.2, TASK-199). Optional
  `storage_perpetual_cost_per_byte_venom` on `GovernanceParameters`;
  `FeeCalculator.estimate(...)` and `.estimate_from_cbor(...)` accept a new
  `storage_growth_bytes`/`storageGrowthBytes` parameter (default `0` for
  pure-compute txs); `FeeBreakdown` exposes a `storage_fee_venom`
  component.

#### Documentation

- Module docstrings clarify that the SDK does NOT compute signing
  preimages or addresses locally, so:
  - **ADR-053 §T1.2 ForkDigest** signing-domain prefix is enforced by
    `pqcd sign-tx`, not the SDK. Signing remains delegated to the Rust
    binary because no mature ML-DSA / SLH-DSA implementation exists in
    JavaScript or Python as of 2026.
  - **ADR-053 §T1.3 chain_id-bound address derivation** is enforced by
    the node; addresses come back from the node API already-derived and
    the SDK never recomputes them locally. (Knock-on: ADR-053 §T2.4 BIP340
    double-tagged hashing also lives entirely in `pqc-crypto`, not the
    SDK.)

#### Packaging

- TypeScript `package.json`:
  - `version` → `0.2.0`.
  - Added `repository`, `bugs`, `homepage` URLs (in line with the Python
    `pyproject.toml` `Homepage`).
  - `description` now references "viper-pq-1 launch architecture
    (ADR-053)" so the npm registry surfaces the alignment.
  - `keywords` extended with `viper-pq-1`, `slh-dsa`.
- Python `pyproject.toml`:
  - `version` → `0.2.0`.
  - Added `authors`, `readme = "README.md"`, `keywords`, `classifiers`
    (Apache-2.0, Python 3.9+ matrix, blockchain, post-quantum).
  - Added `Repository`, `Issues`, `Changelog` URLs alongside the
    existing `Homepage` + `Documentation`.
  - `description` now references "viper-pq-1 launch architecture
    (ADR-053)".

#### Out of scope (intentionally not changed — see "Documentation" above)

- Local signing preimages — SDK delegates to `pqcd sign-tx`.
- Local address derivation — SDK consumes already-derived addresses.
- Local tagged hashing primitive — not exposed by either SDK.
- BIP340 double-tagged hash — used inside the Rust `pqc-crypto` crate
  only; the SDK never invokes it.
- Light-client SDK — ADR-053 §T3.6 `SPEC-LIGHT-CLIENT-001` ships as the
  consensus rule + spec at launch; the light-verifier client is post-launch
  (will land in a future SDK release once the wire format stabilises).

## [0.1.0] - 2026-04-20

Initial publication. Targeted `viper-devnet-2` (pre-ADR-053). See git
history for details.
