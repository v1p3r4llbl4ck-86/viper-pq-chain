/**
 * Fee estimation for Viper PQ Chain transactions.
 *
 * Fee model (ADR-005 + ADR-053 §T2.1, §T2.2):
 *   total = base_fee
 *         + byte_fee × payload_bytes
 *         + sigverify_fee × sig_count
 *         + execution_fee
 *         + storage_fee  (when state-growing — ADR-053 §T2.2)
 *
 * Parameters are governance-mutable and fetched from /v1/governance/parameters.
 * This module provides a local calculator once parameters are known.
 *
 * NOTE: under ADR-053 §T2.1 the authoritative on-chain pricing is the four
 * dimensions {compute, storage, witness, contention}, each with its own
 * EIP-4844-style exponentially-updated base fee and a non-zero reserve floor.
 * This calculator is a backward-compatible single-dimension approximation
 * intended for client-side budgeting; for ground-truth pricing, defer to
 * the node's /v1/fee-market response (handled server-side by pqcd).
 */

import { FeeEstimate, GovernanceParameters } from "./types.js";
import { parseVenom } from "./utils.js";

/** Execution gas cost per operation type. Hard-coded at Phase 5 calibration values. */
const EXECUTION_GAS_PER_OP: Record<string, bigint> = {
  vault_create: 5_000n,
  vault_transfer: 1_000n,
  key_add: 3_000n,
  key_rotate: 3_000n,
  key_revoke: 1_500n,
  attestation_create: 4_000n,
  attestation_revoke: 1_500n,
  validator_register: 10_000n,
  validator_exit: 5_000n,
  validator_unjail: 5_000n,
  governance_proposal: 20_000n,
  governance_vote: 2_000n,
};

export class FeeCalculator {
  private readonly baseFee: bigint;
  private readonly byteFee: bigint;
  private readonly sigverifyFee: bigint;
  // ADR-053 §T2.2 (TASK-199) — storage fund per-byte perpetual cost.
  // Zero when the node response omitted the field (pre-ADR-053 server).
  private readonly storagePerpetualCostPerByte: bigint;

  constructor(params: GovernanceParameters) {
    this.baseFee = parseVenom(params.base_fee_venom);
    this.byteFee = parseVenom(params.byte_fee_venom);
    this.sigverifyFee = parseVenom(params.sigverify_fee_venom);
    this.storagePerpetualCostPerByte = params.storage_perpetual_cost_per_byte_venom
      ? parseVenom(params.storage_perpetual_cost_per_byte_venom)
      : 0n;
  }

  /**
   * Estimate the fee for a transaction.
   *
   * @param opType - Transaction operation type.
   * @param payloadBytes - Byte length of the CBOR-encoded transaction payload.
   * @param sigCount - Number of signatures to verify (typically 1 for user txs).
   * @param storageGrowthBytes - ADR-053 §T2.2 storage growth in bytes; the
   *   storage fund contribution is `storageGrowthBytes × perpetualCostPerByte`.
   *   Defaults to 0 (pure-compute / read-only / state-shrinking txs).
   */
  estimate(
    opType: string,
    payloadBytes: number,
    sigCount = 1,
    storageGrowthBytes = 0,
  ): FeeEstimate {
    const byteFeeTotal = this.byteFee * BigInt(payloadBytes);
    const sigverifyFeeTotal = this.sigverifyFee * BigInt(sigCount);
    const executionFee = EXECUTION_GAS_PER_OP[opType] ?? 1_000n;
    // ADR-053 §T2.2 — storage fund contribution.
    const storageFee =
      this.storagePerpetualCostPerByte * BigInt(storageGrowthBytes);
    const total =
      this.baseFee + byteFeeTotal + sigverifyFeeTotal + executionFee + storageFee;

    return {
      total_venom: total.toString(),
      breakdown: {
        base_fee_venom: this.baseFee.toString(),
        byte_fee_venom: byteFeeTotal.toString(),
        sigverify_fee_venom: sigverifyFeeTotal.toString(),
        execution_fee_venom: executionFee.toString(),
        storage_fee_venom: storageFee.toString(),
      },
    };
  }

  /**
   * Estimate fee from a CBOR hex transaction string.
   * Payload size is computed from the hex length.
   */
  estimateFromCbor(
    opType: string,
    cborHex: string,
    sigCount = 1,
    storageGrowthBytes = 0,
  ): FeeEstimate {
    const payloadBytes = Math.ceil(cborHex.replace(/^0x/, "").length / 2);
    return this.estimate(opType, payloadBytes, sigCount, storageGrowthBytes);
  }
}
