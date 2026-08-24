/**
 * TypeScript SDK smoke tests — run against a live node.
 * Read-only: no transactions submitted; uses public node API.
 *
 * Override network-specific expectations via env vars:
 *   VIPER_NODE_URL         — API base URL (default: producer-1 on viper-pq-1)
 *   VIPER_EXPECT_CHAIN_ID  — chain_id to assert (default: viper-pq-1)
 *   VIPER_MIN_HEIGHT       — minimum tip height (default: 1000)
 *   VIPER_CANARY_ADDRESS   — known funded address (default: viper-pq-1 validator-1)
 *
 * ADR-053 §T1.3 (TASK-205): default chain_id is `viper-pq-1`. Earlier
 * `viper-devnet-2` / `viper-devnet-3` chain_ids are retired.
 */

import {
  DEFAULT_CHAIN_ID,
  ViperClient,
  buildVaultCreate,
  buildVaultTransfer,
  buildAttestationCreate,
  venomToVpr,
  vprToVenom,
  isValidAddress,
  ViperError,
} from "../index.js";

const NODE_URL = process.env.VIPER_NODE_URL ?? "http://127.0.0.1:26657";
const EXPECTED_CHAIN_ID = process.env.VIPER_EXPECT_CHAIN_ID ?? DEFAULT_CHAIN_ID;
const MIN_HEIGHT = Number(process.env.VIPER_MIN_HEIGHT ?? "1000");
const CANARY_ADDRESS =
  process.env.VIPER_CANARY_ADDRESS ??
  "087024f943f46283fbfffd2536313d74a87c39aee943f5b4dce88a6f1ba53cfc";
const client = new ViperClient({ baseUrl: NODE_URL });

// ---------------------------------------------------------------------------
// Utils
// ---------------------------------------------------------------------------

describe("utils", () => {
  test("isValidAddress — 64-char hex", () => {
    expect(isValidAddress("ab".repeat(32))).toBe(true);
    expect(isValidAddress("GG" + "aa".repeat(31))).toBe(false);
    expect(isValidAddress("aa".repeat(31))).toBe(false);
  });

  test("venomToVpr roundtrip", () => {
    const vpr = "1.5";
    const venom = vprToVenom(vpr);
    expect(venomToVpr(venom)).toBe("1.5");
  });

  test("vprToVenom 1 VPR = 10^18 venom", () => {
    expect(vprToVenom("1")).toBe(1_000_000_000_000_000_000n);
  });
});

// ---------------------------------------------------------------------------
// TX builders
// ---------------------------------------------------------------------------

describe("tx builders", () => {
  const ADDR_A = "01".repeat(32);
  const ADDR_B = "02".repeat(32);

  test("buildVaultCreate structure", () => {
    const tx = buildVaultCreate(
      { sender: ADDR_A, nonce: 0, alg_id: "ml-dsa-65", public_key: "cc".repeat(1952) },
      20_000n
    );
    expect(tx.version).toBe(1);
    expect(tx.op_type).toBe("vault_create");
    expect(tx.fee_budget_venom).toBe("20000");
  });

  test("buildVaultTransfer structure", () => {
    const tx = buildVaultTransfer(
      { sender: ADDR_A, nonce: 1, recipient: ADDR_B, amount_venom: vprToVenom("5") },
      30_000n
    );
    expect(tx.op_type).toBe("vault_transfer");
    expect(tx.op_payload.amount_venom).toBe(String(vprToVenom("5")));
  });

  test("buildVaultTransfer rejects zero amount", () => {
    expect(() =>
      buildVaultTransfer(
        { sender: ADDR_A, nonce: 0, recipient: ADDR_B, amount_venom: 0n },
        1n
      )
    ).toThrow();
  });

  test("buildAttestationCreate structure", () => {
    const tx = buildAttestationCreate(
      {
        sender: ADDR_A,
        nonce: 2,
        subject: ADDR_B,
        schema_id: "cc".repeat(32),
        payload_hex: "deadbeef",
      },
      18_512n
    );
    expect(tx.op_type).toBe("attestation_create");
  });
});

// ---------------------------------------------------------------------------
// Live node — read-only
// ---------------------------------------------------------------------------

describe("ViperClient live", () => {
  test("getStatus returns expected fields", async () => {
    const status = await client.getStatus();
    expect(typeof status.height).toBe("number");
    expect(status.height).toBeGreaterThan(MIN_HEIGHT);
    expect(status.chain_id).toBe(EXPECTED_CHAIN_ID);
    expect(typeof status.tip_hash).toBe("string");
    expect(status.tip_hash).toHaveLength(64);
  });

  test("getBlock by height returns valid block", async () => {
    const status = await client.getStatus();
    const block = await client.getBlock(status.height - 1);
    // API returns flat block object (block_hash, height, prev_hash, ...)
    const b = block as unknown as Record<string, unknown>;
    expect(typeof b.height === "number" ? b.height : (b.header as Record<string, number>)?.height)
      .toBe(status.height - 1);
  });

  test("getAccount for known address returns balance", async () => {
    const account = await client.getAccount(CANARY_ADDRESS);
    // API returns `balance` as decimal string; SDK type may say balance_venom
    const raw = account as unknown as Record<string, unknown>;
    const bal = BigInt((raw.balance_venom ?? raw.balance) as string);
    expect(bal).toBeGreaterThan(0n);
  });

  test("getAccount for unknown address throws ViperError 404", async () => {
    await expect(client.getAccount("ff".repeat(32))).rejects.toBeInstanceOf(ViperError);
  });
});

// ---------------------------------------------------------------------------
// Live node — pqcd 880e29c (2026-04-25) public read endpoints
//
// Gated on VIPER_LIVE_TESTS=1 so they don't fire on every `npm test`. Run
// against the public node with:
//   VIPER_LIVE_TESTS=1 VIPER_NODE_URL=https://pqchain.agwswebconsulting.it npm test
// ---------------------------------------------------------------------------

const RUN_LIVE = process.env.VIPER_LIVE_TESTS === "1";
const liveTest = RUN_LIVE ? test : test.skip;
const LIVE_NODE_URL =
  process.env.VIPER_NODE_URL ?? "https://pqchain.agwswebconsulting.it";
const liveClient = new ViperClient({ baseUrl: LIVE_NODE_URL });

describe("ViperClient live — pqcd 880e29c endpoints", () => {
  liveTest("getAlgorithms returns at least one entry", async () => {
    const algs = await liveClient.getAlgorithms();
    expect(Array.isArray(algs)).toBe(true);
    expect(algs.length).toBeGreaterThan(0);
    expect(typeof algs[0].alg_id).toBe("number");
    expect(typeof algs[0].spec_ref).toBe("string");
  });

  liveTest("getAlgorithm(1) returns the FIPS 204 ML-DSA-44 entry", async () => {
    const alg = await liveClient.getAlgorithm(1);
    expect(alg.alg_id).toBe(1);
    expect(alg.spec_ref).toBe("FIPS 204");
  });

  liveTest("getAlgorithm(9999) throws ALGORITHM_NOT_FOUND", async () => {
    await expect(liveClient.getAlgorithm(9999)).rejects.toBeInstanceOf(ViperError);
  });

  liveTest("getValidator returns extended detail with consensus pk", async () => {
    const v = await liveClient.getValidator(CANARY_ADDRESS);
    expect(v.address).toBe(CANARY_ADDRESS);
    expect(typeof v.consensus_pk_hex).toBe("string");
    expect(v.consensus_pk_hex.length).toBeGreaterThan(0);
  });

  liveTest("getAccountAttestations returns an array", async () => {
    const att = await liveClient.getAccountAttestations(CANARY_ADDRESS);
    expect(Array.isArray(att)).toBe(true);
  });

  liveTest("getProposals returns an array", async () => {
    const props = await liveClient.getProposals();
    expect(Array.isArray(props)).toBe(true);
  });

  liveTest("getProposal(unknown) throws ViperError", async () => {
    await expect(liveClient.getProposal("nonexistent-proposal-id"))
      .rejects.toBeInstanceOf(ViperError);
  });

  liveTest("getProposalVotes(unknown) throws ViperError", async () => {
    await expect(liveClient.getProposalVotes("nonexistent-proposal-id"))
      .rejects.toBeInstanceOf(ViperError);
  });
});
