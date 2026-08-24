/**
 * Hex encoding utilities and address validation for Viper PQ Chain.
 */

/** Convert a Uint8Array to a lowercase hex string. */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Convert a hex string to a Uint8Array. Throws if input is not valid hex. */
export function hexToBytes(hex: string): Uint8Array {
  const normalized = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (normalized.length % 2 !== 0) {
    throw new Error(`Invalid hex string (odd length): ${hex}`);
  }
  if (!/^[0-9a-fA-F]*$/.test(normalized)) {
    throw new Error(`Invalid hex string (non-hex chars): ${hex}`);
  }
  const bytes = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < normalized.length; i += 2) {
    bytes[i / 2] = parseInt(normalized.slice(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Validate a Viper account address.
 *
 * A valid address is a 32-byte hex string (64 hex characters).
 */
export function isValidAddress(address: string): boolean {
  return /^[0-9a-fA-F]{64}$/.test(address);
}

/** Assert that a value is a valid address, throwing ViperError if not. */
export function assertValidAddress(address: string, label = "address"): void {
  if (!isValidAddress(address)) {
    throw new Error(
      `Invalid ${label}: expected 32-byte hex string (64 chars), got "${address}"`
    );
  }
}

/**
 * Convert a venom amount (bigint) to a human-readable VPR string.
 *
 * 1 VPR = 10^18 venom. Result is formatted to up to 18 decimal places,
 * with trailing zeros stripped.
 *
 * @example venomToVpr(1_000_000_000_000_000_000n) === "1"
 * @example venomToVpr(500_000_000_000_000_000n) === "0.5"
 */
export function venomToVpr(venom: bigint): string {
  const SCALE = 10n ** 18n;
  const whole = venom / SCALE;
  const frac = venom % SCALE;
  if (frac === 0n) {
    return whole.toString();
  }
  const fracStr = frac.toString().padStart(18, "0").replace(/0+$/, "");
  return `${whole}.${fracStr}`;
}

/**
 * Convert a VPR string to venom (bigint).
 *
 * Accepts integer or decimal strings like "1", "0.5", "1.5".
 * Throws if the string has more than 18 decimal places.
 */
export function vprToVenom(vpr: string): bigint {
  const [whole, frac = ""] = vpr.split(".");
  if (frac.length > 18) {
    throw new Error(
      `VPR value "${vpr}" has more than 18 decimal places`
    );
  }
  const fracPadded = frac.padEnd(18, "0");
  return BigInt(whole) * 10n ** 18n + BigInt(fracPadded);
}

/**
 * Parse a venom decimal string (as returned by API) to bigint.
 * Handles values returned in `balance_venom`, `fee_venom`, etc.
 */
export function parseVenom(value: string): bigint {
  return BigInt(value);
}
