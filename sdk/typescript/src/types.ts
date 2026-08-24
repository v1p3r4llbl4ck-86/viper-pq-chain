/**
 * TypeScript types for all Viper PQ Chain API response shapes.
 *
 * Balance and fee values are represented as `bigint` to handle the full
 * 10^27 venom range without precision loss (Number.MAX_SAFE_INTEGER is ~9×10^15).
 *
 * NOTE: ML-DSA and SLH-DSA signing is NOT available in this SDK. No mature
 * post-quantum signature implementation exists for JavaScript/TypeScript.
 * Transaction signing must be performed by the pqcd CLI or a secure Rust binary.
 * Because the SDK does NOT construct signing preimages locally, the ADR-053
 * §T1.2 ForkDigest prefix is enforced inside `pqcd sign-tx` and is therefore
 * out of scope for this module. Likewise, the ADR-053 §T1.3 chain_id-bound
 * address derivation is out of scope: addresses are returned by the node API
 * already-derived; the SDK never recomputes them locally.
 *
 * This SDK covers all read operations and unsigned transaction construction.
 */

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

/** Hex-encoded 32-byte account address. */
export type Address = string;

/** Hex-encoded block hash (32 bytes). */
export type BlockHash = string;

/** Hex-encoded arbitrary-length byte string. */
export type HexBytes = string;

/** Algorithm identifier string as defined in the Algorithm Registry. */
export type AlgId = "ml-dsa-44" | "ml-dsa-65" | "ml-dsa-87" | "slh-dsa-sha2-128s" | string;

/**
 * Default chain_id for the permanent viper-pq-1 development chain
 * (ADR-053 §T1.3, TASK-206). Hex form: "76697065722d70712d31".
 *
 * `viper-pq-1` replaces the retired `viper-devnet-2` / `viper-devnet-3`
 * chain_ids and operates with mainnet discipline (no resets, dual-path
 * decoders for breaking changes). SDK consumers should compare against
 * this constant rather than hard-coding the literal string.
 */
export const DEFAULT_CHAIN_ID = "viper-pq-1";

/** Hex encoding of the UTF-8 bytes of `viper-pq-1`. */
export const DEFAULT_CHAIN_ID_HEX = "76697065722d70712d31";

// ---------------------------------------------------------------------------
// Chain status
// ---------------------------------------------------------------------------

export interface ChainStatus {
  height: number;
  tip_hash: BlockHash;
  state_root: HexBytes;
  timestamp_ms: number;
  node_version: string;
  chain_id: string;
}

// ---------------------------------------------------------------------------
// Block
// ---------------------------------------------------------------------------

export interface BlockHeader {
  /**
   * ADR-053 §T1.1 (TASK-205) — explicit version slot. First field every
   * decoder reads; viper-pq-1 v1 emits `1`. Optional on read for forward
   * compatibility with pre-ADR-053 server responses that omit it; SDK
   * consumers SHOULD treat absence as "v1 implicit".
   */
  header_version?: number;
  height: number;
  prev_hash: BlockHash;
  state_root: HexBytes;
  /**
   * ADR-053 §T1.1 — Unix timestamp. From viper-pq-1 onwards this is
   * **nanoseconds** as a decimal string (u64 ns carries beyond year 2554
   * — sidesteps the Bitcoin 2106 / Ethereum uint32 timestamp class of late
   * corrections). Pre-launch responses returned milliseconds as a number;
   * the SDK keeps the legacy `timestamp_ms` slot unchanged for read
   * compatibility and exposes the new ns value via `timestamp_ns`.
   */
  timestamp_ms: number;
  /** ADR-053 §T1.1 — nanosecond Unix timestamp, decimal string. */
  timestamp_ns?: string;
  proposer_address: Address;
  tx_count: number;
  /**
   * ADR-053 §T1.1 + §T3.4 — 32-byte Merkle commitment over the future
   * key→value extension map. At viper-pq-1 v1 launch this is always the
   * canonical empty-extension-root (`tagged_hash("VIPER-EXT-EMPTY-V1", &[])`);
   * future P-COMPAT-001 upgrades populate keys (`exec_payload_root`,
   * `builder_bid_commitment`, …) without re-renumbering header slots.
   */
  extension_root?: HexBytes;
}

export interface Block {
  hash: BlockHash;
  header: BlockHeader;
  transactions: Transaction[];
}

// ---------------------------------------------------------------------------
// Transaction
// ---------------------------------------------------------------------------

/** All transaction operation types supported by the protocol. */
export type TxOpType =
  | "vault_create"
  | "vault_transfer"
  | "key_add"
  | "key_rotate"
  | "key_revoke"
  | "attestation_create"
  | "attestation_revoke"
  | "validator_register"
  | "validator_exit"
  | "validator_unjail"
  | "governance_proposal"
  | "governance_vote";

export interface Transaction {
  tx_hash: HexBytes;
  sender: Address;
  nonce: number;
  op_type: TxOpType;
  /** Encoded operation payload (CBOR hex). */
  op_payload: HexBytes;
  /** Fee paid in venom, as a decimal string (use BigInt for arithmetic). */
  fee_venom: string;
  /** Signature hex — empty when constructing unsigned transactions. */
  signature: HexBytes;
  /** Algorithm used for the signature. */
  alg_id: AlgId;
}

// ---------------------------------------------------------------------------
// Account
// ---------------------------------------------------------------------------

export interface KeyEntry {
  key_version: number;
  alg_id: AlgId;
  public_key: HexBytes;
  added_at_height: number;
  revoked_at_height: number | null;
}

export interface Account {
  address: Address;
  /** Balance in venom as a decimal string. Use BigInt for arithmetic. */
  balance_venom: string;
  nonce: number;
  keys: KeyEntry[];
  /**
   * ADR-053 §T3.5 (TASK-205) — unified smart-account verifier template id.
   * `0x0001` = default EOA-equivalent template (sig.verify(msg, embedded_pk)).
   * Governance-allocatable ids start at `0x0010` (multisig, time-locked
   * guardian, session-key allowlist, …). Optional on read for forward
   * compatibility with pre-ADR-053 server responses.
   */
  verifier_template_id?: number;
  /**
   * ADR-053 §T3.5 — template-specific auxiliary auth data (hex). MUST be
   * empty for the EOA template (`verifier_template_id == 0x0001`); the
   * apply path rejects any inbound tx whose target account has non-empty
   * auth_data under the EOA template.
   */
  auth_data?: HexBytes;
}

/** Default EOA verifier template id (ADR-053 §T3.5). */
export const VERIFIER_TEMPLATE_ID_EOA = 0x0001;
/** Inclusive upper bound of the protocol-reserved verifier-template id range (ADR-053 §T3.5). */
export const VERIFIER_TEMPLATE_CORE_RESERVED_MAX = 0x000f;
/** Inclusive lower bound of the governance-allocatable verifier-template id range (ADR-053 §T3.5). */
export const VERIFIER_TEMPLATE_GOV_MIN = 0x0010;

// ---------------------------------------------------------------------------
// Attestation
// ---------------------------------------------------------------------------

export interface Attestation {
  attestation_id: HexBytes;
  issuer: Address;
  subject: Address;
  schema_id: HexBytes;
  payload_hash: HexBytes;
  issued_at_height: number;
  revoked_at_height: number | null;
}

// ---------------------------------------------------------------------------
// Validator
// ---------------------------------------------------------------------------

export type ValidatorStatus = "active" | "inactive" | "jailed" | "exiting";

export interface Validator {
  address: Address;
  consensus_pk: HexBytes;
  consensus_alg: AlgId;
  /** Staked amount in venom as a decimal string. */
  stake_venom: string;
  status: ValidatorStatus;
  registered_at_height: number;
  jailed_at_height: number | null;
}

// ---------------------------------------------------------------------------
// Governance
// ---------------------------------------------------------------------------

/**
 * ADR-053 §T2.1 (TASK-201) — multi-dimensional fee market.
 *
 * SPEC-FEE-002 prices four independent dimensions with EIP-4844-style
 * exponential `base_fee_{n+1} = MIN · e^((used − target) / UPDATE_FRACTION)`
 * updates. Each dimension carries a governance-immutable reserve floor that
 * cannot be set to zero. Fields are decimal strings; use BigInt for
 * arithmetic.
 *
 * Optional on read for forward compatibility with pre-ADR-053 server
 * responses; consumers SHOULD treat absence as "use single base_fee".
 */
export interface MultiDimFee {
  /** Compute (gas) dimension base fee in venom per gas unit. */
  compute_base_fee_venom: string;
  /** Storage growth dimension base fee in venom per byte·epoch. */
  storage_base_fee_venom: string;
  /** Witness size dimension base fee in venom per witness byte. */
  witness_base_fee_venom: string;
  /** Per-account contention dimension base fee in venom. */
  contention_base_fee_venom: string;
}

export interface GovernanceParameters {
  /**
   * ADR-005 single-dimension base fee per transaction in venom — retained
   * for legacy callers. Under ADR-053 §T2.1 the authoritative pricing
   * lives in `multi_dim_fee`; this scalar mirrors `compute_base_fee_venom`
   * for backward compatibility.
   */
  base_fee_venom: string;
  /** Fee per byte of transaction payload in venom. */
  byte_fee_venom: string;
  /** Fee per signature verification op in venom. */
  sigverify_fee_venom: string;
  /**
   * ADR-053 §T2.1 — multi-dimensional fee market. Optional for forward
   * compatibility; absent on pre-ADR-053 nodes.
   */
  multi_dim_fee?: MultiDimFee;
  /**
   * ADR-053 §T2.2 (TASK-199) — storage fund perpetual cost per byte in
   * venom. State growth charge: `bytes × storage_perpetual_cost_per_byte_venom`.
   * Optional for forward compatibility.
   */
  storage_perpetual_cost_per_byte_venom?: string;
  /** Minimum validator stake in venom. */
  min_stake_venom: string;
  /** Unbonding period in blocks. */
  unbonding_period_blocks: number;
  /** Double-sign slashing fraction (e.g. "0.05" = 5%). */
  slash_double_sign: string;
  /** Liveness slashing fraction per missed block window. */
  slash_liveness: string;
  /** Downtime exit slash fraction. */
  slash_downtime_exit: string;
}

// ---------------------------------------------------------------------------
// Fee estimate
// ---------------------------------------------------------------------------

export interface FeeEstimate {
  /** Total estimated fee in venom as a decimal string. */
  total_venom: string;
  /** Breakdown components. */
  breakdown: {
    base_fee_venom: string;
    byte_fee_venom: string;
    sigverify_fee_venom: string;
    execution_fee_venom: string;
    /**
     * ADR-053 §T2.2 — storage fund contribution
     * `bytes × storage_perpetual_cost_per_byte_venom`. Zero when the
     * tx grows no state; populated when the calculator was given a
     * non-zero storage cost.
     */
    storage_fee_venom?: string;
  };
}

// ---------------------------------------------------------------------------
// Transaction submission
// ---------------------------------------------------------------------------

export interface SubmitTxRequest {
  /** CBOR-encoded signed transaction as hex. */
  tx_cbor_hex: HexBytes;
}

export interface SubmitTxResponse {
  tx_hash: HexBytes;
  /** "accepted" | "rejected" */
  status: string;
  error?: string;
}

// ---------------------------------------------------------------------------
// Unsigned transaction builders (output types)
// ---------------------------------------------------------------------------

export interface VaultCreateParams {
  sender: Address;
  nonce: number;
  alg_id: AlgId;
  public_key: HexBytes;
}

export interface VaultTransferParams {
  sender: Address;
  nonce: number;
  recipient: Address;
  /** Amount in venom as bigint. */
  amount_venom: bigint;
}

export interface AttestationCreateParams {
  sender: Address;
  nonce: number;
  subject: Address;
  schema_id: HexBytes;
  /** Raw payload bytes as hex. */
  payload_hex: HexBytes;
}

export interface ValidatorRegisterParams {
  sender: Address;
  nonce: number;
  consensus_pk: HexBytes;
  consensus_alg: AlgId;
  /** Self-bond amount in venom as bigint. */
  self_bond_venom: bigint;
}

// ---------------------------------------------------------------------------
// Algorithm registry (pqcd 880e29c — 2026-04-25)
// ---------------------------------------------------------------------------

/**
 * One row in the on-chain algorithm registry as exposed by
 * GET /v1/algorithms and GET /v1/algorithms/:alg_id.
 *
 * `benchmark_verify_per_sec` and `min_fee` are marked optional because
 * a parallel pqcd commit may redact these calibration-internal fields
 * from the public response. Consumers MUST handle both shapes.
 */
export interface AlgorithmEntry {
  /** Numeric algorithm identifier from the on-chain registry. */
  alg_id: number;
  /** Spec reference, e.g. "FIPS 204", "FIPS 205", "FIPS 206 (draft)". */
  spec_ref: string;
  /** Public-key size in bytes. */
  pk_size: number;
  /** Signature size in bytes. */
  sig_size: number;
  /**
   * Signature class tier, e.g. "reduced" | "standard" | "premium". May
   * be `null` for non-signature algorithms (e.g. KEM entries like FIPS 203).
   */
  sig_class: string | null;
  /** Lifecycle stage: "active" | "deprecated" | "retired" | "proposed". */
  lifecycle: string;
  /**
   * Minimum fee in venom (decimal int, see note below). Optional —
   * may be redacted by the public node response.
   */
  min_fee?: number;
  /**
   * Calibration benchmark: signature verifications per second on the
   * reference hardware. Optional — may be redacted by the public node
   * response.
   */
  benchmark_verify_per_sec?: number;
}

// ---------------------------------------------------------------------------
// Validator detail (pqcd 880e29c — 2026-04-25)
// ---------------------------------------------------------------------------

/**
 * Extended single-validator response from GET /v1/validators/:address.
 * Includes the live consensus public key and operator metadata that the
 * list endpoint elides for payload-size reasons.
 */
export interface ValidatorDetail {
  address: Address;
  /** Numeric consensus algorithm id (matches the algorithm registry). */
  consensus_alg_id: number;
  /** Hex-encoded consensus public key. */
  consensus_pk_hex: HexBytes;
  /** Operator-supplied node identifier, e.g. "validator-1". */
  node_id: string;
  /** Block height at which the validator was registered. */
  registered_height: number;
  /** Self-bond amount in venom as a decimal string. */
  self_bond: string;
  /** Status string: "active" | "inactive" | "jailed" | "exiting". */
  status: string;
  /** True if the validator has been permanently tombstoned. */
  tombstoned?: boolean;
}

// ---------------------------------------------------------------------------
// Account attestation summary (pqcd 880e29c — 2026-04-25)
// ---------------------------------------------------------------------------

/**
 * Summary row returned by GET /v1/accounts/:address/attestations.
 * Wider than the per-id `Attestation` shape because the listing form may
 * include or omit fields depending on indexer state.
 */
export interface AttestationSummary {
  attestation_id: HexBytes;
  issuer: Address;
  subject: Address;
  schema_id?: HexBytes;
  payload_hash?: HexBytes;
  issued_at_height: number;
  revoked_at_height?: number | null;
}

// ---------------------------------------------------------------------------
// Governance proposals + votes (pqcd 880e29c — 2026-04-25)
// ---------------------------------------------------------------------------

/** Listing row from GET /v1/governance/proposals. */
export interface ProposalSummary {
  proposal_id: string;
  title: string;
  proposer: Address;
  status: string;
  submitted_at_height: number;
  voting_deadline?: number;
}

/** Detail row from GET /v1/governance/proposals/:proposal_id. */
export interface ProposalDetail extends ProposalSummary {
  description?: string;
  /** Hex-encoded CBOR proposal payload. */
  payload?: HexBytes;
  /** Tally totals; absent before the voting window opens. */
  tally?: {
    yes: string;
    no: string;
    abstain: string;
  };
}

/** Single vote row inside the proposal-votes response. */
export interface VoteRecord {
  voter: Address;
  /** "yes" | "no" | "abstain". */
  option: string;
  /** Voting weight in venom as a decimal string. */
  weight: string;
  cast_at_height: number;
}

/** Wrapper returned by GET /v1/governance/proposals/:proposal_id/votes. */
export interface ProposalVotes {
  proposal_id: string;
  voting_deadline?: number;
  status: string;
  votes: VoteRecord[];
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

export class ViperError extends Error {
  constructor(
    message: string,
    public readonly statusCode?: number,
    public readonly code?: string
  ) {
    super(message);
    this.name = "ViperError";
  }
}
