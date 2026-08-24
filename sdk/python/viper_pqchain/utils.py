"""Utility helpers for Viper PQ Chain SDK."""

from __future__ import annotations


def assert_valid_address(address: str, field_name: str = "address") -> None:
    """
    Validate that *address* is a 64-character lowercase hex string (32 bytes).

    :raises ValueError: if the address is malformed.
    """
    clean = address.lower().removeprefix("0x")
    if len(clean) != 64:
        raise ValueError(
            f"{field_name} must be a 64-character hex string (32 bytes), "
            f"got {len(clean)} characters: {address!r}"
        )
    try:
        bytes.fromhex(clean)
    except ValueError:
        raise ValueError(
            f"{field_name} contains non-hex characters: {address!r}"
        )


def assert_nonce(nonce: int) -> None:
    """
    Validate that *nonce* is a non-negative integer.

    :raises TypeError: if nonce is not an int.
    :raises ValueError: if nonce is negative.
    """
    if not isinstance(nonce, int):
        raise TypeError(f"nonce must be an int, got {type(nonce).__name__}")
    if nonce < 0:
        raise ValueError(f"nonce must be non-negative, got {nonce}")


def venom_to_vpr(venom: int) -> str:
    """
    Convert a venom integer to a human-readable VPR string with 18 decimal places.

    Example::

        >>> venom_to_vpr(1_000_000_000_000_000_000)
        '1.000000000000000000'
    """
    whole = venom // 10**18
    frac = venom % 10**18
    return f"{whole}.{frac:018d}"


def vpr_to_venom(vpr: str) -> int:
    """
    Convert a VPR decimal string to venom integer.

    Example::

        >>> vpr_to_venom("1.5")
        1500000000000000000
    """
    parts = vpr.strip().split(".")
    if len(parts) == 1:
        return int(parts[0]) * 10**18
    if len(parts) == 2:
        whole = int(parts[0])
        frac_str = parts[1][:18].ljust(18, "0")
        return whole * 10**18 + int(frac_str)
    raise ValueError(f"Invalid VPR string: {vpr!r}")
