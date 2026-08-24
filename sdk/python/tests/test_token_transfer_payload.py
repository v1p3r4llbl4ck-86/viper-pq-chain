"""Unit tests for ``encode_token_transfer_payload``.

Mirrors the Rust tests ``token_transfer_accepts_u128_amount_as_bstr`` and
``token_transfer_rejects_wrong_length_amount_bstr`` in
``crates/pqc-state/src/tests.rs``, plus the encoder branching in
``crates/pqcd/src/main.rs::cmd_wallet_send``.
"""

import pytest

from viper_pqchain.tx import encode_token_transfer_payload

RECIPIENT_HEX = "bb" * 32
RECIPIENT_BYTES = bytes.fromhex(RECIPIENT_HEX)

# Common prefix in every ``token_transfer`` payload:
#   0xA2           — map(2)
#   0x01           — uint(1)            = key "recipient"
#   0x58 0x20 …    — bstr(32) + 32-byte address
#   0x02           — uint(2)            = key "amount"
#
# → fixed-length 37-byte prefix; amount encoding follows at offset 37.
PAYLOAD_PREFIX_LEN = 1 + 1 + 2 + 32 + 1


def test_small_amount_is_cbor_integer():
    """Backward-compat: amount=500 stays a CBOR uint on the wire."""
    payload = encode_token_transfer_payload(RECIPIENT_BYTES, 500)
    tail = payload[PAYLOAD_PREFIX_LEN:]
    # 500 = 0x01F4 → CBOR uint(500) = 0x19 0x01 0xF4 (3 bytes).
    assert tail == b"\x19\x01\xf4"

    expected_hex = "a2" + "01" + "5820" + RECIPIENT_HEX + "02" + "1901f4"
    assert payload.hex() == expected_hex


def test_amount_at_u64_max_stays_integer():
    """Boundary: amount == u64::MAX uses CBOR uint(u64), not bstr."""
    u64_max = (1 << 64) - 1
    payload = encode_token_transfer_payload(RECIPIENT_BYTES, u64_max)
    tail = payload[PAYLOAD_PREFIX_LEN:]
    assert len(tail) == 9
    assert tail[0] == 0x1B
    assert tail[1:] == b"\xff" * 8


def test_amount_above_u64_encodes_as_16_byte_bstr():
    """Round-trip: amount = u64::MAX + 1 → 16-byte big-endian bstr."""
    big_amount = (1 << 64) + 1  # matches the Rust test
    payload = encode_token_transfer_payload(RECIPIENT_BYTES, big_amount)
    tail = payload[PAYLOAD_PREFIX_LEN:]

    # CBOR bstr(16) head = 0x50 (major type 2, length 16 ≤ 23).
    assert tail[0] == 0x50
    assert len(tail) == 17
    assert tail[1:] == big_amount.to_bytes(16, "big")


def test_u128_max_round_trips_as_all_ff():
    """u128::MAX encodes to 16 bytes of 0xFF."""
    u128_max = (1 << 128) - 1
    payload = encode_token_transfer_payload(RECIPIENT_BYTES, u128_max)
    tail = payload[PAYLOAD_PREFIX_LEN:]
    assert tail[0] == 0x50
    assert tail[1:] == b"\xff" * 16


def test_accepts_hex_string_recipient():
    a = encode_token_transfer_payload(RECIPIENT_HEX, 42)
    b = encode_token_transfer_payload(RECIPIENT_BYTES, 42)
    assert a == b


def test_accepts_0x_prefixed_hex():
    a = encode_token_transfer_payload("0x" + RECIPIENT_HEX, 42)
    b = encode_token_transfer_payload(RECIPIENT_BYTES, 42)
    assert a == b


def test_rejects_wrong_length_recipient():
    """Mirrors the wrong-length amount-bstr guard on the node side."""
    with pytest.raises(ValueError, match="32 bytes"):
        encode_token_transfer_payload(b"\x00" * 31, 1)
    with pytest.raises(ValueError, match="32 bytes"):
        encode_token_transfer_payload(b"\x00" * 33, 1)


def test_rejects_non_int_amount():
    with pytest.raises(TypeError, match="int"):
        encode_token_transfer_payload(RECIPIENT_BYTES, "500")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="int"):
        encode_token_transfer_payload(RECIPIENT_BYTES, 1.5)  # type: ignore[arg-type]


def test_rejects_bool_amount():
    """bool is an int subclass in Python — guard against accidental True/False."""
    with pytest.raises(TypeError, match="int"):
        encode_token_transfer_payload(RECIPIENT_BYTES, True)  # type: ignore[arg-type]


def test_rejects_negative_amount():
    with pytest.raises(ValueError, match="non-negative"):
        encode_token_transfer_payload(RECIPIENT_BYTES, -1)


def test_rejects_amount_above_u128():
    with pytest.raises(ValueError, match="u128"):
        encode_token_transfer_payload(RECIPIENT_BYTES, 1 << 128)


def test_zero_amount_encodes():
    """Zero is a valid on-wire encoding; zero-amount rejection is enforced
    by ``apply_token_transfer`` on the node, not by the encoder."""
    payload = encode_token_transfer_payload(RECIPIENT_BYTES, 0)
    tail = payload[PAYLOAD_PREFIX_LEN:]
    assert tail == b"\x00"
