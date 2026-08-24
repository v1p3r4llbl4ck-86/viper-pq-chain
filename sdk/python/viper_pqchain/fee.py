"""
Fee estimation for Viper PQ Chain transactions.

Fee model (ADR-005 + ADR-053 §T2.1, §T2.2):
    total = base_fee
          + byte_fee × payload_bytes
          + sigverify_fee × sig_count
          + execution_fee
          + storage_fee  (when state-growing — ADR-053 §T2.2)

Parameters are governance-mutable and fetched from /v1/governance/parameters.
This module provides a local calculator once parameters are known.

NOTE: under ADR-053 §T2.1 the authoritative on-chain pricing is the four
dimensions {compute, storage, witness, contention}, each with its own
EIP-4844-style exponentially-updated base fee and a non-zero reserve floor.
This calculator is a backward-compatible single-dimension approximation
intended for client-side budgeting; for ground-truth pricing, defer to the
node's /v1/fee-market response (handled server-side by pqcd).
"""

from __future__ import annotations

from .types import FeeBreakdown, FeeEstimate, GovernanceParameters

# Execution gas cost per operation type — calibrated at Phase 5 values.
_EXECUTION_GAS: dict[str, int] = {
    "vault_create": 5_000,
    "vault_transfer": 1_000,
    "key_add": 3_000,
    "key_rotate": 3_000,
    "key_revoke": 1_500,
    "attestation_create": 4_000,
    "attestation_revoke": 1_500,
    "validator_register": 10_000,
    "validator_exit": 5_000,
    "validator_unjail": 5_000,
    "governance_proposal": 20_000,
    "governance_vote": 2_000,
}


class FeeCalculator:
    """
    Snapshot fee calculator built from governance parameters.

    Instantiate via ``ViperClient.get_fee_calculator()`` to get fresh values,
    or construct directly from a ``GovernanceParameters`` object.
    """

    def __init__(self, params: GovernanceParameters) -> None:
        self._base_fee = int(params.base_fee_venom)
        self._byte_fee = int(params.byte_fee_venom)
        self._sigverify_fee = int(params.sigverify_fee_venom)
        # ADR-053 §T2.2 (TASK-199) — storage fund per-byte perpetual cost.
        # Zero when the node response omitted the field (pre-ADR-053 server).
        self._storage_perpetual_cost_per_byte = (
            int(params.storage_perpetual_cost_per_byte_venom)
            if params.storage_perpetual_cost_per_byte_venom
            else 0
        )

    def estimate(
        self,
        op_type: str,
        payload_bytes: int,
        sig_count: int = 1,
        storage_growth_bytes: int = 0,
    ) -> FeeEstimate:
        """
        Estimate the fee for a transaction.

        :param op_type: Transaction operation type (e.g. ``"vault_create"``).
        :param payload_bytes: Byte length of the CBOR-encoded transaction payload.
        :param sig_count: Number of signatures to verify (typically 1 for user txs).
        :param storage_growth_bytes: ADR-053 §T2.2 storage growth in bytes;
            the storage fund contribution is
            ``storage_growth_bytes × perpetual_cost_per_byte``. Defaults to 0
            (pure-compute / read-only / state-shrinking txs).
        :returns: FeeEstimate with total and per-component breakdown.
        """
        byte_fee_total = self._byte_fee * payload_bytes
        sigverify_fee_total = self._sigverify_fee * sig_count
        execution_fee = _EXECUTION_GAS.get(op_type, 1_000)
        # ADR-053 §T2.2 — storage fund contribution.
        storage_fee = self._storage_perpetual_cost_per_byte * storage_growth_bytes
        total = (
            self._base_fee
            + byte_fee_total
            + sigverify_fee_total
            + execution_fee
            + storage_fee
        )

        return FeeEstimate(
            total_venom=str(total),
            breakdown=FeeBreakdown(
                base_fee_venom=str(self._base_fee),
                byte_fee_venom=str(byte_fee_total),
                sigverify_fee_venom=str(sigverify_fee_total),
                execution_fee_venom=str(execution_fee),
                storage_fee_venom=str(storage_fee),
            ),
        )

    def estimate_from_cbor(
        self,
        op_type: str,
        cbor_hex: str,
        sig_count: int = 1,
        storage_growth_bytes: int = 0,
    ) -> FeeEstimate:
        """
        Estimate fee from a hex-encoded CBOR transaction string.

        Payload size is computed from the hex length.
        """
        hex_clean = cbor_hex.removeprefix("0x")
        payload_bytes = (len(hex_clean) + 1) // 2
        return self.estimate(op_type, payload_bytes, sig_count, storage_growth_bytes)
