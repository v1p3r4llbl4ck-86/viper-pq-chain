"""
Unsigned transaction builder for Viper PQ Chain.

SIGNING LIMITATION: ML-DSA and SLH-DSA (FIPS 204/205) have no mature Python
implementation as of 2026. This builder produces a structured unsigned transaction
dictionary. Signing must be performed by the ``pqcd sign-tx`` CLI command or a
Rust-based signing service.

Workflow:
  1. Build unsigned tx with this module → get a dict payload.
  2. Serialise to JSON and pass to ``pqcd sign-tx --tx-json <file> --key-file <key>``.
  3. Submit the signed CBOR hex via ``ViperClient.submit_tx()``.

The ``op_payload`` field is a plain dict; CBOR encoding is performed by the
pqcd CLI or server-side. This keeps the SDK dependency-free.
"""

from __future__ import annotations

from typing import Any, Union

from .types import (
    AttestationCreateParams,
    ValidatorRegisterParams,
    VaultCreateParams,
    VaultTransferParams,
)
from .utils import assert_nonce, assert_valid_address

UnsignedTransaction = dict[str, Any]


# ---------------------------------------------------------------------------
# Canonical token_transfer payload CBOR encoder
# ---------------------------------------------------------------------------
#
# The on-wire payload for a ``token_transfer`` tx is a CBOR map:
#   {1: recipient (bstr, 32 bytes), 2: amount}
#
# Amount (key 2) has two canonical encodings, matching the Rust encoder in
# ``crates/pqcd/src/main.rs`` (``cmd_wallet_send``) and the decoder's
# ``expect_u128`` in ``crates/pqc-state/src/apply/transfer.rs``:
#   - CBOR unsigned integer (major type 0)  when amount <= u64::MAX
#   - CBOR byte string (major type 2, 16B)  when amount  > u64::MAX
#
# The bstr branch mirrors the u128 convention used for balances in
# ``pqc_types::multisig::MultisigAccountState::to_cbor_bytes`` — 16 bytes,
# big-endian.

_U64_MAX = (1 << 64) - 1
_U128_MAX = (1 << 128) - 1


def _encode_unsigned_head(major_type: int, value: int) -> bytes:
    """Emit a CBOR (major_type, argument) head per RFC 8949 §3, shortest form."""
    if value < 0:
        raise ValueError(f"CBOR head argument must be non-negative, got {value}")
    mt = (major_type & 0x07) << 5
    if value < 24:
        return bytes([mt | value])
    if value <= 0xFF:
        return bytes([mt | 24, value])
    if value <= 0xFFFF:
        return bytes([mt | 25]) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes([mt | 26]) + value.to_bytes(4, "big")
    if value <= _U64_MAX:
        return bytes([mt | 27]) + value.to_bytes(8, "big")
    raise ValueError(f"CBOR head argument exceeds u64: {value}")


def _encode_bytes(data: bytes) -> bytes:
    """Encode a CBOR byte string (major type 2)."""
    return _encode_unsigned_head(2, len(data)) + data


def _encode_uint(value: int) -> bytes:
    """Encode a CBOR unsigned integer (major type 0)."""
    if value < 0:
        raise ValueError(f"CBOR uint must be non-negative, got {value}")
    if value > _U64_MAX:
        raise ValueError(f"CBOR uint exceeds u64 ({_U64_MAX}): {value}")
    return _encode_unsigned_head(0, value)


def encode_token_transfer_payload(
    recipient: Union[bytes, bytearray, memoryview, str],
    amount: int,
) -> bytes:
    """Encode a ``token_transfer`` payload as CBOR bytes.

    The output matches the Rust encoder in ``cmd_wallet_send``
    (``crates/pqcd/src/main.rs``) and is round-trip compatible with the
    decoder in ``crates/pqc-state/src/apply/transfer.rs``.

    :param recipient: 32-byte recipient address. Accepted as ``bytes``,
        ``bytearray``, ``memoryview``, or a 64-char hex string.
    :param amount: Amount in venom as a Python ``int``. Must fit in u128
        (``0..=2**128 - 1``). Amounts up to ``u64::MAX`` are encoded as a
        CBOR unsigned integer; larger amounts are encoded as a 16-byte
        big-endian bytestring.
    :raises TypeError: if *amount* is not an ``int`` (e.g. a ``bool`` or
        ``float``). ``bool`` is rejected explicitly because it is an ``int``
        subclass but semantically unsafe here.
    :raises ValueError: if *recipient* is not exactly 32 bytes or *amount*
        is outside ``[0, 2**128 - 1]``.
    """
    if isinstance(recipient, str):
        clean = recipient.removeprefix("0x").lower()
        recipient_bytes = bytes.fromhex(clean)
    else:
        recipient_bytes = bytes(recipient)

    if len(recipient_bytes) != 32:
        raise ValueError(
            f"recipient must be exactly 32 bytes, got {len(recipient_bytes)}"
        )

    # bool is an int subclass in Python; reject it to catch accidental True/False.
    if isinstance(amount, bool) or not isinstance(amount, int):
        raise TypeError(
            f"amount must be an int; received {type(amount).__name__}"
        )
    if amount < 0:
        raise ValueError(f"amount must be non-negative, got {amount}")
    if amount > _U128_MAX:
        raise ValueError(f"amount exceeds u128 range: {amount}")

    # Map header: 2 entries → 0xA2.
    map_header = bytes([0xA2])

    # key 1 → recipient bstr(32)
    key1 = _encode_uint(1)
    recipient_cbor = _encode_bytes(recipient_bytes)

    # key 2 → amount (integer when ≤ u64::MAX, else 16-byte bstr)
    key2 = _encode_uint(2)
    if amount <= _U64_MAX:
        amount_cbor = _encode_uint(amount)
    else:
        amount_cbor = _encode_bytes(amount.to_bytes(16, "big"))

    return map_header + key1 + recipient_cbor + key2 + amount_cbor


def build_vault_create(
    params: VaultCreateParams,
    fee_budget_venom: int,
) -> UnsignedTransaction:
    """Build an unsigned vault_create transaction."""
    assert_valid_address(params.sender, "sender")
    assert_nonce(params.nonce)
    if not params.public_key:
        raise ValueError("public_key is required")

    return {
        "version": 1,
        "op_type": "vault_create",
        "sender": params.sender,
        "nonce": params.nonce,
        "op_payload": {
            "alg_id": params.alg_id,
            "public_key": params.public_key,
        },
        "fee_budget_venom": str(fee_budget_venom),
        "alg_id": params.alg_id,
    }


def build_vault_transfer(
    params: VaultTransferParams,
    fee_budget_venom: int,
) -> UnsignedTransaction:
    """Build an unsigned vault_transfer transaction."""
    assert_valid_address(params.sender, "sender")
    assert_valid_address(params.recipient, "recipient")
    assert_nonce(params.nonce)
    if params.amount_venom <= 0:
        raise ValueError("amount_venom must be positive")

    return {
        "version": 1,
        "op_type": "vault_transfer",
        "sender": params.sender,
        "nonce": params.nonce,
        "op_payload": {
            "recipient": params.recipient,
            "amount_venom": str(params.amount_venom),
        },
        "fee_budget_venom": str(fee_budget_venom),
        "alg_id": "ml-dsa-65",
    }


def build_attestation_create(
    params: AttestationCreateParams,
    fee_budget_venom: int,
) -> UnsignedTransaction:
    """Build an unsigned attestation_create transaction."""
    assert_valid_address(params.sender, "sender")
    assert_valid_address(params.subject, "subject")
    assert_nonce(params.nonce)

    return {
        "version": 1,
        "op_type": "attestation_create",
        "sender": params.sender,
        "nonce": params.nonce,
        "op_payload": {
            "subject": params.subject,
            "schema_id": params.schema_id,
            "payload_hex": params.payload_hex,
        },
        "fee_budget_venom": str(fee_budget_venom),
        "alg_id": "ml-dsa-65",
    }


def build_validator_register(
    params: ValidatorRegisterParams,
    fee_budget_venom: int,
) -> UnsignedTransaction:
    """Build an unsigned validator_register transaction."""
    assert_valid_address(params.sender, "sender")
    assert_nonce(params.nonce)
    if params.self_bond_venom <= 0:
        raise ValueError("self_bond_venom must be positive")

    return {
        "version": 1,
        "op_type": "validator_register",
        "sender": params.sender,
        "nonce": params.nonce,
        "op_payload": {
            "consensus_pk": params.consensus_pk,
            "consensus_alg": params.consensus_alg,
            "self_bond_venom": str(params.self_bond_venom),
        },
        "fee_budget_venom": str(fee_budget_venom),
        "alg_id": "ml-dsa-65",
    }


def build_validator_exit(
    sender: str,
    nonce: int,
    fee_budget_venom: int,
) -> UnsignedTransaction:
    """Build an unsigned validator_exit transaction."""
    assert_valid_address(sender, "sender")
    assert_nonce(nonce)

    return {
        "version": 1,
        "op_type": "validator_exit",
        "sender": sender,
        "nonce": nonce,
        "op_payload": {},
        "fee_budget_venom": str(fee_budget_venom),
        "alg_id": "ml-dsa-65",
    }
