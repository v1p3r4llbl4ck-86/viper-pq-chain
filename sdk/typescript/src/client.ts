/**
 * ViperClient — HTTP client for the Viper PQ Chain node API.
 *
 * Covers all read endpoints defined in API.md and the transaction submission
 * endpoint (POST /v1/txs). All balance/fee values are returned as decimal
 * strings; use BigInt() or the parseVenom() utility for arithmetic.
 *
 * Requires Node.js 18+ (native fetch) or a fetch-compatible environment.
 */

import {
  Account,
  AlgorithmEntry,
  Attestation,
  AttestationSummary,
  Block,
  ChainStatus,
  GovernanceParameters,
  ProposalDetail,
  ProposalSummary,
  ProposalVotes,
  SubmitTxRequest,
  SubmitTxResponse,
  Transaction,
  Validator,
  ValidatorDetail,
  ViperError,
} from "./types.js";
import { FeeCalculator } from "./fee.js";

/**
 * pqcd 880e29c (2026-04-25) wraps the new public read responses in a
 * `{ "data": ... }` envelope. Older endpoints (status, block, account…)
 * still return the bare object; we only unwrap for the methods documented
 * to use the envelope.
 */
type DataEnvelope<T> = { data: T };

export interface ViperClientOptions {
  /** Base URL of the pqcd node, e.g. "http://localhost:9000". No trailing slash. */
  baseUrl: string;
  /** Request timeout in milliseconds. Default: 10_000. */
  timeoutMs?: number;
  /** Custom fetch implementation. Defaults to globalThis.fetch. */
  fetch?: typeof fetch;
}

export class ViperClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly fetchFn: typeof fetch;

  constructor(options: ViperClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.fetchFn = options.fetch ?? globalThis.fetch;

    if (!this.fetchFn) {
      throw new Error(
        "fetch is not available. Use Node.js 18+ or pass a fetch implementation."
      );
    }
  }

  // -------------------------------------------------------------------------
  // Chain status
  // -------------------------------------------------------------------------

  /** GET /v1/status — current chain height, tip hash, and state root. */
  async getStatus(): Promise<ChainStatus> {
    return this.get<ChainStatus>("/v1/status");
  }

  // -------------------------------------------------------------------------
  // Blocks
  // -------------------------------------------------------------------------

  /** GET /v1/blocks/:height — fetch a block by height. */
  async getBlock(height: number): Promise<Block> {
    return this.get<Block>(`/v1/blocks/${height}`);
  }

  /** GET /v1/blocks/:hash — fetch a block by hash (hex). */
  async getBlockByHash(hash: string): Promise<Block> {
    return this.get<Block>(`/v1/blocks/${hash}`);
  }

  // -------------------------------------------------------------------------
  // Transactions
  // -------------------------------------------------------------------------

  /** GET /v1/txs/:tx_hash — fetch a transaction by hash. */
  async getTransaction(txHash: string): Promise<Transaction> {
    return this.get<Transaction>(`/v1/txs/${txHash}`);
  }

  /**
   * POST /v1/txs — submit a signed transaction.
   *
   * @param cborHex - CBOR-encoded signed transaction as hex string.
   *                  Produce this with `pqcd sign-tx` after building an
   *                  unsigned tx with the tx builder in this SDK.
   */
  async submitTx(cborHex: string): Promise<SubmitTxResponse> {
    const body: SubmitTxRequest = { tx_cbor_hex: cborHex };
    return this.post<SubmitTxResponse>("/v1/txs", body);
  }

  // -------------------------------------------------------------------------
  // Accounts
  // -------------------------------------------------------------------------

  /** GET /v1/accounts/:address — fetch account state including keys. */
  async getAccount(address: string): Promise<Account> {
    return this.get<Account>(`/v1/accounts/${address}`);
  }

  // -------------------------------------------------------------------------
  // Attestations
  // -------------------------------------------------------------------------

  /** GET /v1/attestations/:attestation_id — fetch an attestation record. */
  async getAttestation(attestationId: string): Promise<Attestation> {
    return this.get<Attestation>(`/v1/attestations/${attestationId}`);
  }

  /**
   * GET /v1/accounts/:address/attestations — list attestations issued by or
   * targeting this address.
   *
   * pqcd 880e29c (2026-04-25): response now wraps the array in a
   * `{ data: AttestationSummary[] }` envelope. The SDK transparently
   * unwraps; the return type is the richer `AttestationSummary[]` shape.
   */
  async getAccountAttestations(address: string): Promise<AttestationSummary[]> {
    const resp = await this.get<DataEnvelope<AttestationSummary[]>>(
      `/v1/accounts/${address}/attestations`
    );
    return resp.data;
  }

  // -------------------------------------------------------------------------
  // Validators
  // -------------------------------------------------------------------------

  /** GET /v1/validators — list all validators in the active set. */
  async getValidators(): Promise<Validator[]> {
    return this.get<Validator[]>("/v1/validators");
  }

  /**
   * GET /v1/validators/:address — fetch a single validator.
   *
   * pqcd 880e29c (2026-04-25): response wraps detail in `{ data: ValidatorDetail }`
   * with the consensus public key and operator metadata that the list
   * endpoint elides. The SDK unwraps and returns `ValidatorDetail`.
   */
  async getValidator(address: string): Promise<ValidatorDetail> {
    const resp = await this.get<DataEnvelope<ValidatorDetail>>(
      `/v1/validators/${address}`
    );
    return resp.data;
  }

  // -------------------------------------------------------------------------
  // Algorithm registry (pqcd 880e29c — 2026-04-25)
  // -------------------------------------------------------------------------

  /**
   * GET /v1/algorithms — list every algorithm in the on-chain registry.
   *
   * `benchmark_verify_per_sec` and `min_fee` may be redacted by a parallel
   * pqcd commit; the SDK type marks them optional so callers handle both
   * shapes without code changes.
   */
  async getAlgorithms(): Promise<AlgorithmEntry[]> {
    const resp = await this.get<DataEnvelope<AlgorithmEntry[]>>(
      "/v1/algorithms"
    );
    return resp.data;
  }

  /**
   * GET /v1/algorithms/:alg_id — fetch a single algorithm registry entry.
   *
   * Throws `ViperError` (statusCode 404, code `"ALGORITHM_NOT_FOUND"`)
   * when the alg_id is not registered.
   */
  async getAlgorithm(algId: number): Promise<AlgorithmEntry> {
    const resp = await this.get<DataEnvelope<AlgorithmEntry>>(
      `/v1/algorithms/${algId}`
    );
    return resp.data;
  }

  // -------------------------------------------------------------------------
  // Governance
  // -------------------------------------------------------------------------

  /** GET /v1/governance/parameters — fetch current on-chain governance params. */
  async getGovernanceParameters(): Promise<GovernanceParameters> {
    return this.get<GovernanceParameters>("/v1/governance/parameters");
  }

  /**
   * GET /v1/governance/proposals — list all on-chain governance proposals
   * (pqcd 880e29c, 2026-04-25). Returns `[]` if no proposals are open.
   */
  async getProposals(): Promise<ProposalSummary[]> {
    const resp = await this.get<DataEnvelope<ProposalSummary[]>>(
      "/v1/governance/proposals"
    );
    return resp.data;
  }

  /**
   * GET /v1/governance/proposals/:proposal_id — fetch a single proposal
   * including description, payload and live tally (when available).
   */
  async getProposal(proposalId: string): Promise<ProposalDetail> {
    const resp = await this.get<DataEnvelope<ProposalDetail>>(
      `/v1/governance/proposals/${proposalId}`
    );
    return resp.data;
  }

  /**
   * GET /v1/governance/proposals/:proposal_id/votes — fetch the live vote
   * roster for a proposal. The envelope carries the proposal's voting
   * deadline and current status alongside the per-voter rows.
   */
  async getProposalVotes(proposalId: string): Promise<ProposalVotes> {
    const resp = await this.get<DataEnvelope<ProposalVotes>>(
      `/v1/governance/proposals/${proposalId}/votes`
    );
    return resp.data;
  }

  // -------------------------------------------------------------------------
  // Fee estimation
  // -------------------------------------------------------------------------

  /**
   * Fetch current governance parameters and return a FeeCalculator.
   * The calculator is a snapshot — call again if you need fresh values.
   */
  async getFeeCalculator(): Promise<FeeCalculator> {
    const params = await this.getGovernanceParameters();
    return new FeeCalculator(params);
  }

  // -------------------------------------------------------------------------
  // Internal HTTP helpers
  // -------------------------------------------------------------------------

  private async get<T>(path: string): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    let response: Response;
    try {
      response = await this.fetchWithTimeout(url, {
        method: "GET",
        headers: { Accept: "application/json" },
      });
    } catch (err) {
      throw new ViperError(
        `Network error reaching ${url}: ${String(err)}`,
        undefined,
        "NETWORK_ERROR"
      );
    }
    return this.parseResponse<T>(response, url);
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    let response: Response;
    try {
      response = await this.fetchWithTimeout(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify(body),
      });
    } catch (err) {
      throw new ViperError(
        `Network error reaching ${url}: ${String(err)}`,
        undefined,
        "NETWORK_ERROR"
      );
    }
    return this.parseResponse<T>(response, url);
  }

  private async fetchWithTimeout(
    url: string,
    init: RequestInit
  ): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      return await this.fetchFn(url, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
  }

  private async parseResponse<T>(response: Response, url: string): Promise<T> {
    const text = await response.text();
    if (!response.ok) {
      let code: string | undefined;
      try {
        // Two error-body shapes are accepted:
        //   - legacy flat: { error: "...", code: "..." }
        //   - pqcd 880e29c (2026-04-25) nested:
        //       { error: { code: "...", message: "..." } }
        const json = JSON.parse(text) as
          | { error?: string | { code?: string; message?: string }; code?: string };
        if (typeof json.error === "object" && json.error !== null) {
          code = json.error.code;
        } else {
          code = json.code;
        }
      } catch {
        // non-JSON error body
      }
      throw new ViperError(
        `HTTP ${response.status} from ${url}: ${text}`,
        response.status,
        code
      );
    }
    try {
      return JSON.parse(text) as T;
    } catch {
      throw new ViperError(
        `Failed to parse JSON response from ${url}: ${text.slice(0, 200)}`,
        response.status,
        "PARSE_ERROR"
      );
    }
  }
}
