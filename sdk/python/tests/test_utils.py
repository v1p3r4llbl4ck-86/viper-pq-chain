"""Unit tests for utility helpers."""

import pytest
from viper_pqchain.utils import assert_valid_address, venom_to_vpr, vpr_to_venom


def test_valid_address_passes():
    assert_valid_address("01" * 32)


def test_valid_address_with_uppercase():
    assert_valid_address("AB" * 32)


def test_short_address_rejected():
    with pytest.raises(ValueError, match="64-character"):
        assert_valid_address("deadbeef")


def test_non_hex_address_rejected():
    with pytest.raises(ValueError, match="non-hex"):
        assert_valid_address("gg" * 32)


def test_venom_to_vpr_one_vpr():
    assert venom_to_vpr(10**18) == "1.000000000000000000"


def test_venom_to_vpr_fractional():
    assert venom_to_vpr(5 * 10**17) == "0.500000000000000000"


def test_venom_to_vpr_large():
    assert venom_to_vpr(10**27) == "1000000000.000000000000000000"


def test_vpr_to_venom_whole():
    assert vpr_to_venom("1") == 10**18


def test_vpr_to_venom_fractional():
    assert vpr_to_venom("1.5") == 15 * 10**17


def test_vpr_to_venom_roundtrip():
    original = 123_456_789_012_345_678
    assert vpr_to_venom(venom_to_vpr(original)) == original


def test_vpr_to_venom_invalid():
    with pytest.raises(ValueError):
        vpr_to_venom("1.2.3")
