/**
 * Unit tests for `encodeTokenTransferPayload` — mirrors the Rust tests
 * `token_transfer_accepts_u128_amount_as_bstr` and
 * `token_transfer_rejects_wrong_length_amount_bstr` in
 * `crates/pqc-state/src/tests.rs`, and the encoder branching in
 * `crates/pqcd/src/main.rs::cmd_wallet_send`.
 */

import { encodeTokenTransferPayload } from "../tx.js";
import { bytesToHex, hexToBytes } from "../utils.js";

const RECIPIENT_HEX = "bb".repeat(32);
const RECIPIENT_BYTES = hexToBytes(RECIPIENT_HEX);

// Common prefix in every `token_transfer` payload:
//   0xA2           — map(2)
//   0x01           — uint(1)            = key "recipient"
//   0x58 0x20 …    — bstr(32) + 32-byte address
//   0x02           — uint(2)            = key "amount"
//
// → fixed-length 37-byte prefix; amount encoding follows at offset 37.
const PAYLOAD_PREFIX_LEN = 1 /* map hdr */ + 1 /* key 1 */ + 2 /* bstr hdr */ + 32 /* addr */ + 1; /* key 2 */

describe("encodeTokenTransferPayload", () => {
  test("small amount (500) is a CBOR integer on the wire", () => {
    const payload = encodeTokenTransferPayload(RECIPIENT_BYTES, 500n);
    // 500 = 0x01F4 → CBOR uint(500) = 0x19 0x01 0xF4 (3 bytes).
    const tail = payload.slice(PAYLOAD_PREFIX_LEN);
    expect(Array.from(tail)).toEqual([0x19, 0x01, 0xf4]);

    // Full expected hex (prefix + amount).
    const expectedHex = "a2" + "01" + "5820" + RECIPIENT_HEX + "02" + "1901f4";
    expect(bytesToHex(payload)).toBe(expectedHex);
  });

  test("amount == u64::MAX still uses CBOR integer (boundary)", () => {
    const u64Max = (1n << 64n) - 1n;
    const payload = encodeTokenTransferPayload(RECIPIENT_BYTES, u64Max);
    const tail = payload.slice(PAYLOAD_PREFIX_LEN);
    // CBOR uint(u64::MAX) = 0x1B 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF
    expect(tail[0]).toBe(0x1b);
    expect(tail.length).toBe(9);
    expect(Array.from(tail.slice(1))).toEqual([
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ]);
  });

  test("amount > u64::MAX is encoded as a 16-byte big-endian bstr", () => {
    const bigAmount = (1n << 64n) + 1n; // matches the Rust test
    const payload = encodeTokenTransferPayload(RECIPIENT_BYTES, bigAmount);
    const tail = payload.slice(PAYLOAD_PREFIX_LEN);

    // CBOR bstr(16) head = 0x50 (major type 2, length 16 ≤ 23).
    expect(tail[0]).toBe(0x50);
    expect(tail.length).toBe(17);

    // Big-endian u128(2^64 + 1) = 00…00 01 00…00 01.
    const expectedAmountBytes = new Uint8Array(16);
    expectedAmountBytes[7] = 0x01;
    expectedAmountBytes[15] = 0x01;
    expect(Array.from(tail.slice(1))).toEqual(Array.from(expectedAmountBytes));
  });

  test("round-trip: u128::MAX encodes to 16 bytes of 0xFF", () => {
    const u128Max = (1n << 128n) - 1n;
    const payload = encodeTokenTransferPayload(RECIPIENT_BYTES, u128Max);
    const tail = payload.slice(PAYLOAD_PREFIX_LEN);
    expect(tail[0]).toBe(0x50);
    expect(Array.from(tail.slice(1))).toEqual(new Array(16).fill(0xff));
  });

  test("accepts hex-string recipient", () => {
    const a = encodeTokenTransferPayload(RECIPIENT_HEX, 42n);
    const b = encodeTokenTransferPayload(RECIPIENT_BYTES, 42n);
    expect(bytesToHex(a)).toBe(bytesToHex(b));
  });

  test("rejects wrong-length recipient (mirrors wrong-length amount bstr guard in Rust)", () => {
    const short = new Uint8Array(31);
    expect(() => encodeTokenTransferPayload(short, 1n)).toThrow(/32 bytes/);
    const long = new Uint8Array(33);
    expect(() => encodeTokenTransferPayload(long, 1n)).toThrow(/32 bytes/);
  });

  test("rejects non-bigint amount (would silently lose precision as number)", () => {
    expect(() =>
      // @ts-expect-error — intentional: asserting the runtime guard.
      encodeTokenTransferPayload(RECIPIENT_BYTES, 42)
    ).toThrow(/bigint/);
  });

  test("rejects negative amount", () => {
    expect(() => encodeTokenTransferPayload(RECIPIENT_BYTES, -1n)).toThrow(
      /non-negative/
    );
  });

  test("rejects amount > u128::MAX", () => {
    const tooBig = 1n << 128n;
    expect(() =>
      encodeTokenTransferPayload(RECIPIENT_BYTES, tooBig)
    ).toThrow(/u128/);
  });

  test("zero amount still encodes (on-chain zero-amount rejection is a state-transition concern)", () => {
    // The SDK encoder matches the wire format; `amount > 0` is enforced by
    // `apply_token_transfer` on the node side, not by the encoder.
    const payload = encodeTokenTransferPayload(RECIPIENT_BYTES, 0n);
    const tail = payload.slice(PAYLOAD_PREFIX_LEN);
    expect(Array.from(tail)).toEqual([0x00]);
  });
});
