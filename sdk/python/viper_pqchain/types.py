"""
Types for Viper PQ Chain API responses and transaction builders.

Balance and fee values are represented as ``int`` — Python has native arbitrary-
precision integers, so no precision loss occurs even at the full 10^27 venom range.

SIGNING LIMITATION: ML-DSA and SLH-DSA (FIPS 204/205) have no mature Python
implementation as of 2026. This SDK covers all read operations and unsigned
transaction construction. Signing must be performed by the ``pqcd sign-tx`` CLI
or a Rust-based signing service. Because the SDK does NOT construct signing
preimages locally, the ADR-053 §T1.2 ForkDigest prefix is enforced inside
``pqcd sign-tx`` and is therefore out of scope for this module. Likewise, the
ADR-053 §T1.3 chain_id-bound address derivation is out of scope: addresses are
returned by the node API already-derived; the SDK never recomputes them locally.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Chain id constants (ADR-053 §T1.3, TASK-206)
# ---------------------------------------------------------------------------

#: Default chain_id for the permanent viper-pq-1 development chain.
#: Replaces the retired ``viper-devnet-2`` / ``viper-devnet-3``.
DEFAULT_CHAIN_ID: str = "viper-pq-1"

#: Hex encoding of the UTF-8 bytes of ``viper-pq-1``.
DEFAULT_CHAIN_ID_HEX: str = "76697065722d70712d31"


# ---------------------------------------------------------------------------
# Verifier template ids (ADR-053 §T3.5, TASK-205)
# ---------------------------------------------------------------------------

#: Default EOA verifier template id (ADR-053 §T3.5). Sig.verify(msg, embedded_pk).
VERIFIER_TEMPLATE_ID_EOA: int = 0x0001

#: Inclusive upper bound of the protocol-reserved verifier-template id range.
VERIFIER_TEMPLATE_CORE_RESERVED_MAX: int = 0x000F

#: Inclusive lower bound of the governance-allocatable verifier-template id range.
VERIFIER_TEMPLATE_GOV_MIN: int = 0x0010


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------

# Hex-encoded 32-byte account address.
Address = str

# Hex-encoded block hash (32 bytes).
BlockHash = str

# Hex-encoded arbitrary-length byte string.
HexBytes = str

# Algorithm identifier string as defined in the Algorithm Registry.
AlgId = str


# ---------------------------------------------------------------------------
# Chain status
# ---------------------------------------------------------------------------


@dataclass
class ChainStatus:
    height: int
    tip_hash: BlockHash
    state_root: HexBytes
    timestamp_ms: int
    node_version: str
    chain_id: str


# ---------------------------------------------------------------------------
# Block
# ---------------------------------------------------------------------------


@dataclass
class BlockHeader:
    height: int
    prev_hash: BlockHash
    state_root: HexBytes
    timestamp_ms: int
    proposer_address: Address
    tx_count: int
    # ADR-053 §T1.1 (TASK-205) — explicit version slot. First field every
    # decoder reads; viper-pq-1 v1 emits ``1``. Optional on read for forward
    # compatibility with pre-ADR-053 server responses; absent → "v1 implicit".
    header_version: Optional[int] = None
    # ADR-053 §T1.1 — Unix nanosecond timestamp as a decimal string (u64 ns
    # carries beyond year 2554 — sidesteps the Bitcoin 2106 / Ethereum uint32
    # timestamp class). Pre-launch servers returned ms only via ``timestamp_ms``.
    timestamp_ns: Optional[str] = None
    # ADR-053 §T1.1 + §T3.4 — 32-byte Merkle commitment over the future
    # key→value extension map. At viper-pq-1 v1 launch this is always the
    # canonical empty-extension-root tagged_hash("VIPER-EXT-EMPTY-V1", []);
    # future P-COMPAT-001 upgrades populate keys (``exec_payload_root``,
    # ``builder_bid_commitment``, …) without re-renumbering header slots.
    extension_root: Optional[HexBytes] = None


@dataclass
class Transaction:
    tx_hash: HexBytes
    sender: Address
    nonce: int
    op_type: str
    op_payload: HexBytes
    fee_venom: str
    signature: HexBytes
    alg_id: AlgId


@dataclass
class Block:
    hash: BlockHash
    header: BlockHeader
    transactions: list[Transaction]


# ---------------------------------------------------------------------------
# Account
# ---------------------------------------------------------------------------


@dataclass
class KeyEntry:
    key_version: int
    alg_id: AlgId
    public_key: HexBytes
    added_at_height: int
    revoked_at_height: Optional[int]


@dataclass
class Account:
    address: Address
    balance_venom: str
    nonce: int
    keys: list[KeyEntry]
    # ADR-053 §T3.5 (TASK-205) — unified smart-account verifier template id.
    # ``0x0001`` = default EOA-equivalent template (sig.verify(msg, embedded_pk)).
    # Governance-allocatable ids start at ``0x0010``. Optional on read for
    # forward compatibility with pre-ADR-053 server responses.
    verifier_template_id: Optional[int] = None
    # ADR-053 §T3.5 — template-specific auxiliary auth data (hex). MUST be
    # empty for the EOA template; the apply path rejects any inbound tx
    # whose target account has non-empty auth_data under the EOA template.
    auth_data: Optional[HexBytes] = None

    @property
    def balance(self) -> int:
        """Balance in venom as a Python int."""
        return int(self.balance_venom)


# ---------------------------------------------------------------------------
# Attestation
# ---------------------------------------------------------------------------


@dataclass
class Attestation:
    attestation_id: HexBytes
    issuer: Address
    subject: Address
    schema_id: HexBytes
    payload_hash: HexBytes
    issued_at_height: int
    revoked_at_height: Optional[int]


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


@dataclass
class Validator:
    address: Address
    consensus_pk: HexBytes
    consensus_alg: AlgId
    stake_venom: str
    status: str  # "active" | "inactive" | "jailed" | "exiting"
    registered_at_height: int
    jailed_at_height: Optional[int]

    @property
    def stake(self) -> int:
        """Stake in venom as a Python int."""
        return int(self.stake_venom)


# ---------------------------------------------------------------------------
# Governance
# ---------------------------------------------------------------------------


@dataclass
class MultiDimFee:
    """ADR-053 §T2.1 (TASK-201) multi-dimensional fee market state.

    SPEC-FEE-002 prices four independent dimensions with EIP-4844-style
    exponential ``base_fee_{n+1} = MIN · e^((used − target) / UPDATE_FRACTION)``
    updates. Each dimension carries a governance-immutable reserve floor
    that cannot be set to zero. Fields are decimal strings; use ``int(...)``
    for arithmetic.
    """

    compute_base_fee_venom: str
    storage_base_fee_venom: str
    witness_base_fee_venom: str
    contention_base_fee_venom: str


@dataclass
class GovernanceParameters:
    base_fee_venom: str
    byte_fee_venom: str
    sigverify_fee_venom: str
    min_stake_venom: str
    unbonding_period_blocks: int
    slash_double_sign: str
    slash_liveness: str
    slash_downtime_exit: str
    # ADR-053 §T2.1 — multi-dimensional fee market. Optional on read for
    # forward compatibility with pre-ADR-053 servers.
    multi_dim_fee: Optional[MultiDimFee] = None
    # ADR-053 §T2.2 (TASK-199) — storage fund perpetual cost per byte in
    # venom. State growth charge: ``bytes × storage_perpetual_cost_per_byte_venom``.
    # Optional for forward compatibility.
    storage_perpetual_cost_per_byte_venom: Optional[str] = None


# ---------------------------------------------------------------------------
# Fee estimate
# ---------------------------------------------------------------------------


@dataclass
class FeeBreakdown:
    base_fee_venom: str
    byte_fee_venom: str
    sigverify_fee_venom: str
    execution_fee_venom: str
    # ADR-053 §T2.2 — storage fund contribution
    # ``bytes × storage_perpetual_cost_per_byte_venom``. Defaults to ``"0"``
    # on read responses from pre-ADR-053 servers.
    storage_fee_venom: str = "0"


@dataclass
class FeeEstimate:
    total_venom: str
    breakdown: FeeBreakdown

    @property
    def total(self) -> int:
        """Total fee in venom as a Python int."""
        return int(self.total_venom)


# ---------------------------------------------------------------------------
# Transaction submission
# ---------------------------------------------------------------------------


@dataclass
class SubmitTxResponse:
    tx_hash: HexBytes
    status: str  # "accepted" | "rejected"
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Unsigned transaction builder params
# ---------------------------------------------------------------------------


@dataclass
class VaultCreateParams:
    sender: Address
    nonce: int
    alg_id: AlgId
    public_key: HexBytes


@dataclass
class VaultTransferParams:
    sender: Address
    nonce: int
    recipient: Address
    amount_venom: int  # native Python int — no BigInt needed


@dataclass
class AttestationCreateParams:
    sender: Address
    nonce: int
    subject: Address
    schema_id: HexBytes
    payload_hex: HexBytes


@dataclass
class ValidatorRegisterParams:
    sender: Address
    nonce: int
    consensus_pk: HexBytes
    consensus_alg: AlgId
    self_bond_venom: int


# ---------------------------------------------------------------------------
# Algorithm registry (pqcd 880e29c — 2026-04-25)
# ---------------------------------------------------------------------------


@dataclass
class AlgorithmEntry:
    """One row in the on-chain algorithm registry.

    ``benchmark_verify_per_sec`` and ``min_fee`` are optional because a
    parallel pqcd commit may redact these calibration-internal fields
    from the public response. SDK consumers MUST handle both shapes.
    """

    alg_id: int
    spec_ref: str
    pk_size: int
    sig_size: int
    sig_class: Optional[str]  # "reduced" | "standard" | "premium" | None
    lifecycle: str
    min_fee: Optional[int] = None
    benchmark_verify_per_sec: Optional[int] = None


# ---------------------------------------------------------------------------
# Validator detail (pqcd 880e29c — 2026-04-25)
# ---------------------------------------------------------------------------


@dataclass
class ValidatorDetail:
    """Extended single-validator response from GET /v1/validators/:address.

    Includes the live consensus public key and operator metadata that the
    list endpoint elides for payload-size reasons.
    """

    address: Address
    consensus_alg_id: int
    consensus_pk_hex: HexBytes
    node_id: str
    registered_height: int
    self_bond: str
    status: str  # "active" | "inactive" | "jailed" | "exiting"
    tombstoned: Optional[bool] = None


# ---------------------------------------------------------------------------
# Attestation summary (pqcd 880e29c — 2026-04-25)
# ---------------------------------------------------------------------------


@dataclass
class AttestationSummary:
    """Summary row from GET /v1/accounts/:address/attestations."""

    attestation_id: HexBytes
    issuer: Address
    subject: Address
    issued_at_height: int
    schema_id: Optional[HexBytes] = None
    payload_hash: Optional[HexBytes] = None
    revoked_at_height: Optional[int] = None


# ---------------------------------------------------------------------------
# Governance proposals + votes (pqcd 880e29c — 2026-04-25)
# ---------------------------------------------------------------------------


@dataclass
class ProposalSummary:
    """Listing row from GET /v1/governance/proposals."""

    proposal_id: str
    title: str
    proposer: Address
    status: str
    submitted_at_height: int
    voting_deadline: Optional[int] = None


@dataclass
class ProposalDetail:
    """Detail row from GET /v1/governance/proposals/:proposal_id."""

    proposal_id: str
    title: str
    proposer: Address
    status: str
    submitted_at_height: int
    voting_deadline: Optional[int] = None
    description: Optional[str] = None
    payload: Optional[HexBytes] = None  # hex-encoded CBOR
    tally: Optional[dict[str, str]] = None  # {"yes":"...", "no":"...", "abstain":"..."}


@dataclass
class VoteRecord:
    """Single vote row inside the proposal-votes response."""

    voter: Address
    option: str  # "yes" | "no" | "abstain"
    weight: str  # decimal string venom
    cast_at_height: int


@dataclass
class ProposalVotes:
    """Wrapper from GET /v1/governance/proposals/:proposal_id/votes."""

    proposal_id: str
    status: str
    votes: list[VoteRecord]
    voting_deadline: Optional[int] = None


# ---------------------------------------------------------------------------
# Error
# ---------------------------------------------------------------------------


class ViperError(Exception):
    """Raised when the node API returns an error or is unreachable."""

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        code: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
