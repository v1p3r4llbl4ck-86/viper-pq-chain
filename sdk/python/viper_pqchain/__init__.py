"""
viper-pqchain — Python SDK for Viper PQ Chain.

Quick start::

    from viper_pqchain import ViperClient, FeeCalculator
    from viper_pqchain.tx import build_vault_create
    from viper_pqchain.types import VaultCreateParams
    from viper_pqchain.utils import vpr_to_venom

    client = ViperClient("http://localhost:9000")

    # Read chain state
    status = client.get_status()
    print(f"Height: {status.height}  tip: {status.tip_hash}")

    # Estimate a fee
    calc = client.get_fee_calculator()
    est = calc.estimate("vault_create", payload_bytes=256)
    print(f"Estimated fee: {est.total_venom} venom")

    # Build an unsigned transaction (signing via pqcd sign-tx)
    tx = build_vault_create(
        VaultCreateParams(
            sender="01" * 32,
            nonce=0,
            alg_id="ml-dsa-65",
            public_key="<hex-encoded-public-key>",
        ),
        fee_budget_venom=est.total,
    )
    import json
    print(json.dumps(tx, indent=2))

SIGNING LIMITATION: ML-DSA (FIPS 204) has no mature Python implementation as
of 2026. All signing must be performed by the ``pqcd sign-tx`` CLI or a
Rust-based service. See the README for the full signing workflow.
"""

from .client import ViperClient
from .fee import FeeCalculator
from .types import (
    Account,
    AlgorithmEntry,
    Attestation,
    AttestationCreateParams,
    AttestationSummary,
    Block,
    BlockHeader,
    ChainStatus,
    DEFAULT_CHAIN_ID,
    DEFAULT_CHAIN_ID_HEX,
    FeeEstimate,
    GovernanceParameters,
    KeyEntry,
    MultiDimFee,
    ProposalDetail,
    ProposalSummary,
    ProposalVotes,
    SubmitTxResponse,
    Transaction,
    Validator,
    ValidatorDetail,
    ValidatorRegisterParams,
    VaultCreateParams,
    VaultTransferParams,
    VERIFIER_TEMPLATE_CORE_RESERVED_MAX,
    VERIFIER_TEMPLATE_GOV_MIN,
    VERIFIER_TEMPLATE_ID_EOA,
    ViperError,
    VoteRecord,
)
from .utils import assert_valid_address, venom_to_vpr, vpr_to_venom

__all__ = [
    # Client
    "ViperClient",
    # Fee
    "FeeCalculator",
    # Types
    "Account",
    "AlgorithmEntry",
    "Attestation",
    "AttestationCreateParams",
    "AttestationSummary",
    "Block",
    "BlockHeader",
    "ChainStatus",
    "DEFAULT_CHAIN_ID",
    "DEFAULT_CHAIN_ID_HEX",
    "FeeEstimate",
    "GovernanceParameters",
    "KeyEntry",
    "MultiDimFee",
    "ProposalDetail",
    "ProposalSummary",
    "ProposalVotes",
    "SubmitTxResponse",
    "Transaction",
    "Validator",
    "ValidatorDetail",
    "ValidatorRegisterParams",
    "VaultCreateParams",
    "VaultTransferParams",
    "VERIFIER_TEMPLATE_CORE_RESERVED_MAX",
    "VERIFIER_TEMPLATE_GOV_MIN",
    "VERIFIER_TEMPLATE_ID_EOA",
    "ViperError",
    "VoteRecord",
    # Utils
    "assert_valid_address",
    "venom_to_vpr",
    "vpr_to_venom",
]

__version__ = "0.3.0"
