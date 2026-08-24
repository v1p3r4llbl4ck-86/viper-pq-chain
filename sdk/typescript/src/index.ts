/**
 * @viper-pqchain/sdk — TypeScript SDK for Viper PQ Chain
 *
 * Public surface area:
 *  - ViperClient: HTTP client for all node read/write endpoints
 *  - FeeCalculator: local fee estimation from governance parameters
 *  - Transaction builders: buildVaultCreate, buildVaultTransfer, etc.
 *  - Utilities: venomToVpr, vprToVenom, bytesToHex, hexToBytes, isValidAddress
 *  - All TypeScript types and the ViperError class
 *
 * @example
 * ```typescript
 * import { ViperClient, venomToVpr } from "@viper-pqchain/sdk";
 *
 * const client = new ViperClient({ baseUrl: "http://localhost:9000" });
 * const status = await client.getStatus();
 * console.log("Chain height:", status.height);
 *
 * const account = await client.getAccount("<address-hex>");
 * console.log("Balance:", venomToVpr(BigInt(account.balance_venom)), "VPR");
 * ```
 */

// Client
export { ViperClient } from "./client.js";
export type { ViperClientOptions } from "./client.js";

// Fee
export { FeeCalculator } from "./fee.js";

// Transaction builders
export {
  buildVaultCreate,
  buildVaultTransfer,
  buildAttestationCreate,
  buildValidatorRegister,
  buildValidatorExit,
  encodeTokenTransferPayload,
} from "./tx.js";
export type { UnsignedTransaction } from "./tx.js";

// Utilities
export {
  bytesToHex,
  hexToBytes,
  isValidAddress,
  assertValidAddress,
  venomToVpr,
  vprToVenom,
  parseVenom,
} from "./utils.js";

// All types
export type {
  Account,
  Address,
  AlgId,
  AlgorithmEntry,
  Attestation,
  AttestationCreateParams,
  AttestationSummary,
  Block,
  BlockHash,
  BlockHeader,
  ChainStatus,
  FeeEstimate,
  GovernanceParameters,
  HexBytes,
  KeyEntry,
  MultiDimFee,
  ProposalDetail,
  ProposalSummary,
  ProposalVotes,
  SubmitTxRequest,
  SubmitTxResponse,
  Transaction,
  TxOpType,
  Validator,
  ValidatorDetail,
  ValidatorRegisterParams,
  ValidatorStatus,
  VaultCreateParams,
  VaultTransferParams,
  VoteRecord,
} from "./types.js";
export {
  DEFAULT_CHAIN_ID,
  DEFAULT_CHAIN_ID_HEX,
  VERIFIER_TEMPLATE_ID_EOA,
  VERIFIER_TEMPLATE_CORE_RESERVED_MAX,
  VERIFIER_TEMPLATE_GOV_MIN,
  ViperError,
} from "./types.js";
