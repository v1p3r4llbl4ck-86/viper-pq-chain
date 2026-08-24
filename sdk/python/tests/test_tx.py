"""Unit tests for unsigned transaction builders."""

import pytest
from viper_pqchain.tx import (
    build_attestation_create,
    build_validator_exit,
    build_validator_register,
    build_vault_create,
    build_vault_transfer,
)
from viper_pqchain.types import (
    AttestationCreateParams,
    ValidatorRegisterParams,
    VaultCreateParams,
    VaultTransferParams,
)

ADDR_A = "01" * 32
ADDR_B = "02" * 32


def test_build_vault_create_structure():
    tx = build_vault_create(
        VaultCreateParams(
            sender=ADDR_A,
            nonce=0,
            alg_id="ml-dsa-65",
            public_key="aabb" * 512,
        ),
        fee_budget_venom=20_000,
    )
    assert tx["version"] == 1
    assert tx["op_type"] == "vault_create"
    assert tx["sender"] == ADDR_A
    assert tx["nonce"] == 0
    assert tx["op_payload"]["alg_id"] == "ml-dsa-65"
    assert tx["fee_budget_venom"] == "20000"


def test_build_vault_create_rejects_missing_pubkey():
    with pytest.raises(ValueError, match="public_key"):
        build_vault_create(
            VaultCreateParams(sender=ADDR_A, nonce=0, alg_id="ml-dsa-65", public_key=""),
            fee_budget_venom=1,
        )


def test_build_vault_transfer_structure():
    tx = build_vault_transfer(
        VaultTransferParams(
            sender=ADDR_A,
            nonce=5,
            recipient=ADDR_B,
            amount_venom=10**18,
        ),
        fee_budget_venom=15_012,
    )
    assert tx["op_type"] == "vault_transfer"
    assert tx["op_payload"]["recipient"] == ADDR_B
    assert tx["op_payload"]["amount_venom"] == str(10**18)
    assert tx["fee_budget_venom"] == "15012"


def test_build_vault_transfer_rejects_zero_amount():
    with pytest.raises(ValueError, match="amount_venom"):
        build_vault_transfer(
            VaultTransferParams(sender=ADDR_A, nonce=0, recipient=ADDR_B, amount_venom=0),
            fee_budget_venom=1,
        )


def test_build_attestation_create():
    tx = build_attestation_create(
        AttestationCreateParams(
            sender=ADDR_A,
            nonce=1,
            subject=ADDR_B,
            schema_id="cc" * 32,
            payload_hex="deadbeef",
        ),
        fee_budget_venom=18_512,
    )
    assert tx["op_type"] == "attestation_create"
    assert tx["op_payload"]["subject"] == ADDR_B
    assert tx["op_payload"]["payload_hex"] == "deadbeef"


def test_build_validator_register():
    tx = build_validator_register(
        ValidatorRegisterParams(
            sender=ADDR_A,
            nonce=0,
            consensus_pk="ff" * 1952,
            consensus_alg="ml-dsa-65",
            self_bond_venom=10**24,
        ),
        fee_budget_venom=24_000,
    )
    assert tx["op_type"] == "validator_register"
    assert tx["op_payload"]["self_bond_venom"] == str(10**24)


def test_build_validator_exit():
    tx = build_validator_exit(ADDR_A, nonce=3, fee_budget_venom=5_500)
    assert tx["op_type"] == "validator_exit"
    assert tx["op_payload"] == {}
    assert tx["nonce"] == 3


def test_invalid_address_rejected():
    with pytest.raises(ValueError, match="sender"):
        build_validator_exit("not-an-address", nonce=0, fee_budget_venom=1)


def test_negative_nonce_rejected():
    with pytest.raises(ValueError, match="nonce"):
        build_validator_exit(ADDR_A, nonce=-1, fee_budget_venom=1)


def test_fee_budget_stored_as_string():
    """Fee budget must be a decimal string to avoid float precision loss."""
    large = 10**27
    tx = build_validator_exit(ADDR_A, nonce=0, fee_budget_venom=large)
    assert tx["fee_budget_venom"] == str(large)
