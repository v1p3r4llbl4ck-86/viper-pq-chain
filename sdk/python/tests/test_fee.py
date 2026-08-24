"""Unit tests for FeeCalculator."""

import pytest
from viper_pqchain.fee import FeeCalculator
from viper_pqchain.types import GovernanceParameters


def _params(**overrides) -> GovernanceParameters:
    defaults = dict(
        base_fee_venom="500",
        byte_fee_venom="2",
        sigverify_fee_venom="14000",
        min_stake_venom="1000000000000000000000000",  # 1M VPR
        unbonding_period_blocks=100800,
        slash_double_sign="0.05",
        slash_liveness="0.005",
        slash_downtime_exit="0.02",
    )
    defaults.update(overrides)
    return GovernanceParameters(**defaults)


def test_vault_create_estimate():
    calc = FeeCalculator(_params())
    est = calc.estimate("vault_create", payload_bytes=256, sig_count=1)

    # base_fee=500 + byte_fee=2*256=512 + sigverify=14000*1=14000 + exec=5000
    assert int(est.total_venom) == 500 + 512 + 14_000 + 5_000
    assert int(est.breakdown.base_fee_venom) == 500
    assert int(est.breakdown.byte_fee_venom) == 512
    assert int(est.breakdown.sigverify_fee_venom) == 14_000
    assert int(est.breakdown.execution_fee_venom) == 5_000


def test_unknown_op_type_uses_default_gas():
    calc = FeeCalculator(_params())
    est = calc.estimate("future_op", payload_bytes=0, sig_count=0)
    assert int(est.breakdown.execution_fee_venom) == 1_000


def test_estimate_from_cbor_hex():
    calc = FeeCalculator(_params())
    # 32 bytes = 64 hex chars
    cbor_hex = "aa" * 32
    est = calc.estimate_from_cbor("vault_transfer", cbor_hex)
    assert int(est.breakdown.byte_fee_venom) == 2 * 32


def test_estimate_from_cbor_with_0x_prefix():
    calc = FeeCalculator(_params())
    cbor_hex = "0x" + "bb" * 10
    est = calc.estimate_from_cbor("vault_transfer", cbor_hex)
    assert int(est.breakdown.byte_fee_venom) == 2 * 10


def test_multi_sig_multiplies_sigverify():
    calc = FeeCalculator(_params())
    est = calc.estimate("governance_proposal", payload_bytes=0, sig_count=3)
    assert int(est.breakdown.sigverify_fee_venom) == 14_000 * 3
