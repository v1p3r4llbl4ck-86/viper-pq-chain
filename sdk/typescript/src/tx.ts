/**
 * Unsigned transaction builder for Viper PQ Chain.
 *
 * SIGNING LIMITATION: ML-DSA and SLH-DSA (FIPS 204/205) have no mature
 * JavaScript/TypeScript implementation as of 2026. This builder produces
 * a structured unsigned transaction object. Signing must be performed
 * by the `pqcd sign-tx` CLI command or a Rust-based signing service.
 *
 * Workflow:
 *   1. Build unsigned tx with this module → get JSON payload.
 *   2. Pass JSON to `pqcd sign-tx --tx-json <file> --key-file <key>`.
 *   3. Submit the signed CBOR hex via ViperClient.submitTx().
 *
 * The "op_payload" field is a plain object; CBOR encoding is performed
 * by the pqcd CLI or server-side. This keeps the SDK dependency-free.
 */

import {
  AttestationCreateParams,
  TxOpType,
  ValidatorRegisterParams,
  VaultCreateParams,
  VaultTransferParams,
} from "./types.js";
import { assertValidAddress, hexToBytes } from "./utils.js";

export interface UnsignedTransaction {
  version: 1;
  op_type: TxOpType;
  sender: string;
  nonce: number;
  op_payload: Record<string, unknown>;
  /** Fee budget in venom as a decimal string. Must cover estimated fee. */
  fee_budget_venom: string;
  alg_id: string;
}

// ---------------------------------------------------------------------------
// Canonical token_transfer payload CBOR encoder
// ---------------------------------------------------------------------------
//
// The on-wire payload for a `token_transfer` tx is a CBOR map:
//   {1: recipient (bstr, 32 bytes), 2: amount}
//
// Amount (key 2) has two canonical encodings, matching the Rust encoder in
// `crates/pqcd/src/main.rs` (cmd_wallet_send) and the decoder's `expect_u128`
// in `crates/pqc-state/src/apply/transfer.rs`:
//   - CBOR unsigned integer (major type 0)  when amount <= u64::MAX
//   - CBOR byte string (major type 2, 16B)  when amount  > u64::MAX
//
// The bstr branch mirrors the u128 convention used for balances in
// `pqc_types::multisig::MultisigAccountState::to_cbor_bytes` — 16 bytes,
// big-endian. Amounts are `bigint` throughout; `number` only carries 53
// integer bits, nowhere near the 128-bit range.

const U64_MAX = (1n << 64n) - 1n;
const U128_MAX = (1n << 128n) - 1n;

/**
 * Encode an unsigned integer head (major type + argument) per RFC 8949 §3.
 * Emits the shortest form for the given value.
 */
function encodeUnsignedHead(majorType: number, value: bigint): Uint8Array {
  if (value < 0n) {
    throw new Error(`CBOR head argument must be non-negative, got ${value}`);
  }
  const mt = (majorType & 0x07) << 5;
  if (value < 24n) {
    return new Uint8Array([mt | Number(value)]);
  }
  if (value <= 0xffn) {
    return new Uint8Array([mt | 24, Number(value)]);
  }
  if (value <= 0xffffn) {
    const v = Number(value);
    return new Uint8Array([mt | 25, (v >>> 8) & 0xff, v & 0xff]);
  }
  if (value <= 0xffffffffn) {
    const v = Number(value);
    return new Uint8Array([
      mt | 26,
      (v >>> 24) & 0xff,
      (v >>> 16) & 0xff,
      (v >>> 8) & 0xff,
      v & 0xff,
    ]);
  }
  if (value <= U64_MAX) {
    const buf = new Uint8Array(9);
    buf[0] = mt | 27;
    let v = value;
    for (let i = 8; i >= 1; i--) {
      buf[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    return buf;
  }
  throw new Error(`CBOR head argument exceeds u64: ${value}`);
}

/** Encode a CBOR byte string (major type 2). */
function encodeBytes(data: Uint8Array): Uint8Array {
  const head = encodeUnsignedHead(2, BigInt(data.length));
  const out = new Uint8Array(head.length + data.length);
  out.set(head, 0);
  out.set(data, head.length);
  return out;
}

/** Encode a CBOR unsigned integer (major type 0). */
function encodeUint(value: bigint): Uint8Array {
  if (value < 0n) {
    throw new Error(`CBOR uint must be non-negative, got ${value}`);
  }
  if (value <= U64_MAX) {
    return encodeUnsignedHead(0, value);
  }
  throw new Error(`CBOR uint exceeds u64 (${U64_MAX}): ${value}`);
}

/** Concatenate Uint8Array chunks. */
function concatBytes(chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

/** Convert a u128 bigint to a 16-byte big-endian Uint8Array. */
function u128ToBeBytes(value: bigint): Uint8Array {
  if (value < 0n || value > U128_MAX) {
    throw new Error(`value out of u128 range: ${value}`);
  }
  const out = new Uint8Array(16);
  let v = value;
  for (let i = 15; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/**
 * Encode a `token_transfer` payload as CBOR bytes.
 *
 * The output matches the Rust encoder in `cmd_wallet_send`
 * (`crates/pqcd/src/main.rs`) and is round-trip compatible with the
 * decoder in `crates/pqc-state/src/apply/transfer.rs`.
 *
 * @param recipient - 32-byte recipient address, as a `Uint8Array` or a
 *                    64-char hex string.
 * @param amount    - Amount in venom as a `bigint`. Must fit in u128
 *                    (0..=2**128 - 1). Amounts up to `u64::MAX` are encoded
 *                    as a CBOR unsigned integer; larger amounts are encoded
 *                    as a 16-byte big-endian bytestring.
 */
export function encodeTokenTransferPayload(
  recipient: Uint8Array | string,
  amount: bigint
): Uint8Array {
  const recipientBytes =
    typeof recipient === "string" ? hexToBytes(recipient) : recipient;
  if (recipientBytes.length !== 32) {
    throw new Error(
      `recipient must be exactly 32 bytes, got ${recipientBytes.length}`
    );
  }
  if (typeof amount !== "bigint") {
    throw new TypeError(
      `amount must be a bigint; received ${typeof amount}. ` +
        `Use a BigInt literal (e.g. 1000n) to avoid JS Number precision loss.`
    );
  }
  if (amount < 0n) {
    throw new Error(`amount must be non-negative, got ${amount}`);
  }
  if (amount > U128_MAX) {
    throw new Error(`amount exceeds u128 range: ${amount}`);
  }

  // Map header: 2 entries → 0xA2.
  const mapHeader = new Uint8Array([0xa2]);

  // key 1 → recipient bytes
  const key1 = encodeUint(1n);
  const recipientCbor = encodeBytes(recipientBytes);

  // key 2 → amount (integer when ≤ u64::MAX, else 16-byte bstr)
  const key2 = encodeUint(2n);
  const amountCbor =
    amount <= U64_MAX ? encodeUint(amount) : encodeBytes(u128ToBeBytes(amount));

  return concatBytes([mapHeader, key1, recipientCbor, key2, amountCbor]);
}

/** Validate nonce is a non-negative integer. */
function assertNonce(nonce: number): void {
  if (!Number.isInteger(nonce) || nonce < 0) {
    throw new Error(`nonce must be a non-negative integer, got ${nonce}`);
  }
}

/** Build an unsigned vault_create transaction. */
export function buildVaultCreate(
  params: VaultCreateParams,
  feeBudgetVenom: bigint
): UnsignedTransaction {
  assertValidAddress(params.sender, "sender");
  assertNonce(params.nonce);
  if (!params.public_key) throw new Error("public_key is required");

  return {
    version: 1,
    op_type: "vault_create",
    sender: params.sender,
    nonce: params.nonce,
    op_payload: {
      alg_id: params.alg_id,
      public_key: params.public_key,
    },
    fee_budget_venom: feeBudgetVenom.toString(),
    alg_id: params.alg_id,
  };
}

/** Build an unsigned vault_transfer transaction. */
export function buildVaultTransfer(
  params: VaultTransferParams,
  feeBudgetVenom: bigint
): UnsignedTransaction {
  assertValidAddress(params.sender, "sender");
  assertValidAddress(params.recipient, "recipient");
  assertNonce(params.nonce);
  if (params.amount_venom <= 0n) {
    throw new Error("amount_venom must be positive");
  }

  return {
    version: 1,
    op_type: "vault_transfer",
    sender: params.sender,
    nonce: params.nonce,
    op_payload: {
      recipient: params.recipient,
      amount_venom: params.amount_venom.toString(),
    },
    fee_budget_venom: feeBudgetVenom.toString(),
    alg_id: "ml-dsa-65",
  };
}

/** Build an unsigned attestation_create transaction. */
export function buildAttestationCreate(
  params: AttestationCreateParams,
  feeBudgetVenom: bigint
): UnsignedTransaction {
  assertValidAddress(params.sender, "sender");
  assertValidAddress(params.subject, "subject");
  assertNonce(params.nonce);

  return {
    version: 1,
    op_type: "attestation_create",
    sender: params.sender,
    nonce: params.nonce,
    op_payload: {
      subject: params.subject,
      schema_id: params.schema_id,
      payload_hex: params.payload_hex,
    },
    fee_budget_venom: feeBudgetVenom.toString(),
    alg_id: "ml-dsa-65",
  };
}

/** Build an unsigned validator_register transaction. */
export function buildValidatorRegister(
  params: ValidatorRegisterParams,
  feeBudgetVenom: bigint
): UnsignedTransaction {
  assertValidAddress(params.sender, "sender");
  assertNonce(params.nonce);
  if (params.self_bond_venom <= 0n) {
    throw new Error("self_bond_venom must be positive");
  }

  return {
    version: 1,
    op_type: "validator_register",
    sender: params.sender,
    nonce: params.nonce,
    op_payload: {
      consensus_pk: params.consensus_pk,
      consensus_alg: params.consensus_alg,
      self_bond_venom: params.self_bond_venom.toString(),
    },
    fee_budget_venom: feeBudgetVenom.toString(),
    alg_id: "ml-dsa-65",
  };
}

/** Build an unsigned validator_exit transaction. */
export function buildValidatorExit(
  sender: string,
  nonce: number,
  feeBudgetVenom: bigint
): UnsignedTransaction {
  assertValidAddress(sender, "sender");
  assertNonce(nonce);

  return {
    version: 1,
    op_type: "validator_exit",
    sender,
    nonce,
    op_payload: {},
    fee_budget_venom: feeBudgetVenom.toString(),
    alg_id: "ml-dsa-65",
  };
}
