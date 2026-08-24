"""
ViperClient — HTTP client for the Viper PQ Chain node API.

Covers all read endpoints defined in API.md and the transaction submission
endpoint (POST /v1/txs). Uses only the Python standard library (``urllib``);
no third-party dependencies required.

Requires Python 3.9+.

Example::

    from viper_pqchain import ViperClient

    client = ViperClient("http://localhost:9000")
    status = client.get_status()
    print(status.height, status.tip_hash)
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Optional
from urllib.request import Request

from .fee import FeeCalculator
from .types import (
    Account,
    AlgorithmEntry,
    Attestation,
    AttestationSummary,
    Block,
    BlockHeader,
    ChainStatus,
    GovernanceParameters,
    KeyEntry,
    MultiDimFee,
    ProposalDetail,
    ProposalSummary,
    ProposalVotes,
    SubmitTxResponse,
    Transaction,
    Validator,
    ValidatorDetail,
    ViperError,
    VoteRecord,
)


def _parse_chain_status(d: dict[str, Any]) -> ChainStatus:
    return ChainStatus(
        height=d["height"],
        tip_hash=d["tip_hash"],
        state_root=d["state_root"],
        timestamp_ms=d["timestamp_ms"],
        node_version=d.get("node_version", ""),
        chain_id=d.get("chain_id", ""),
    )


def _parse_transaction(d: dict[str, Any]) -> Transaction:
    return Transaction(
        tx_hash=d["tx_hash"],
        sender=d["sender"],
        nonce=d["nonce"],
        op_type=d["op_type"],
        op_payload=d.get("op_payload", ""),
        fee_venom=d.get("fee_venom", "0"),
        signature=d.get("signature", ""),
        alg_id=d.get("alg_id", ""),
    )


def _parse_block_header(d: dict[str, Any]) -> BlockHeader:
    # ADR-053 §T1.1 (TASK-205) — surface ``header_version``, ``timestamp_ns``,
    # and ``extension_root`` when the server provides them. All three are
    # absent on pre-ADR-053 server responses; the dataclass treats them as
    # ``None``-defaulted optional fields.
    return BlockHeader(
        height=d["height"],
        prev_hash=d["prev_hash"],
        state_root=d["state_root"],
        timestamp_ms=d.get("timestamp_ms", 0),
        proposer_address=d.get("proposer_address", ""),
        tx_count=d.get("tx_count", 0),
        header_version=d.get("header_version"),
        timestamp_ns=d.get("timestamp_ns") or d.get("timestamp"),
        extension_root=d.get("extension_root"),
    )


def _parse_block(d: dict[str, Any]) -> Block:
    return Block(
        hash=d["hash"],
        header=_parse_block_header(d["header"]),
        transactions=[_parse_transaction(t) for t in d.get("transactions", [])],
    )


def _parse_key_entry(d: dict[str, Any]) -> KeyEntry:
    return KeyEntry(
        key_version=d["key_version"],
        alg_id=d["alg_id"],
        public_key=d["public_key"],
        added_at_height=d["added_at_height"],
        revoked_at_height=d.get("revoked_at_height"),
    )


def _parse_account(d: dict[str, Any]) -> Account:
    # ADR-053 §T3.5 (TASK-205) — surface ``verifier_template_id`` and
    # ``auth_data``. Pre-ADR-053 servers omit both; defaults to ``None``.
    return Account(
        address=d["address"],
        balance_venom=d["balance_venom"],
        nonce=d["nonce"],
        keys=[_parse_key_entry(k) for k in d.get("keys", [])],
        verifier_template_id=d.get("verifier_template_id"),
        auth_data=d.get("auth_data"),
    )


def _parse_attestation(d: dict[str, Any]) -> Attestation:
    return Attestation(
        attestation_id=d["attestation_id"],
        issuer=d["issuer"],
        subject=d["subject"],
        schema_id=d["schema_id"],
        payload_hash=d["payload_hash"],
        issued_at_height=d["issued_at_height"],
        revoked_at_height=d.get("revoked_at_height"),
    )


def _parse_validator(d: dict[str, Any]) -> Validator:
    return Validator(
        address=d["address"],
        consensus_pk=d["consensus_pk"],
        consensus_alg=d["consensus_alg"],
        stake_venom=d["stake_venom"],
        status=d["status"],
        registered_at_height=d["registered_at_height"],
        jailed_at_height=d.get("jailed_at_height"),
    )


def _parse_multi_dim_fee(d: Optional[dict[str, Any]]) -> Optional[MultiDimFee]:
    # ADR-053 §T2.1 (TASK-201) — multi-dimensional fee market shape.
    if not d:
        return None
    return MultiDimFee(
        compute_base_fee_venom=d["compute_base_fee_venom"],
        storage_base_fee_venom=d["storage_base_fee_venom"],
        witness_base_fee_venom=d["witness_base_fee_venom"],
        contention_base_fee_venom=d["contention_base_fee_venom"],
    )


def _parse_algorithm_entry(d: dict[str, Any]) -> AlgorithmEntry:
    # pqcd 880e29c (2026-04-25). ``benchmark_verify_per_sec`` and ``min_fee``
    # are optional — a parallel pqcd commit may redact them from the public
    # response. ``sig_class`` may be ``null`` for non-signature algorithms
    # (FIPS 203 KEM entries).
    return AlgorithmEntry(
        alg_id=d["alg_id"],
        spec_ref=d["spec_ref"],
        pk_size=d["pk_size"],
        sig_size=d["sig_size"],
        sig_class=d.get("sig_class"),
        lifecycle=d["lifecycle"],
        min_fee=d.get("min_fee"),
        benchmark_verify_per_sec=d.get("benchmark_verify_per_sec"),
    )


def _parse_validator_detail(d: dict[str, Any]) -> ValidatorDetail:
    # pqcd 880e29c (2026-04-25). Distinct from ``Validator`` (list shape):
    # detail surfaces ``consensus_pk_hex``, ``node_id``, ``registered_height``,
    # ``self_bond`` and ``tombstoned``.
    return ValidatorDetail(
        address=d["address"],
        consensus_alg_id=d["consensus_alg_id"],
        consensus_pk_hex=d["consensus_pk_hex"],
        node_id=d.get("node_id", ""),
        registered_height=d.get("registered_height", 0),
        self_bond=d.get("self_bond", "0"),
        status=d.get("status", ""),
        tombstoned=d.get("tombstoned"),
    )


def _parse_attestation_summary(d: dict[str, Any]) -> AttestationSummary:
    # pqcd 880e29c (2026-04-25) listing form is a permissive superset of
    # the per-id ``Attestation`` shape — ``schema_id`` and ``payload_hash``
    # may be elided depending on indexer state.
    return AttestationSummary(
        attestation_id=d["attestation_id"],
        issuer=d["issuer"],
        subject=d["subject"],
        issued_at_height=d.get("issued_at_height", 0),
        schema_id=d.get("schema_id"),
        payload_hash=d.get("payload_hash"),
        revoked_at_height=d.get("revoked_at_height"),
    )


def _parse_proposal_summary(d: dict[str, Any]) -> ProposalSummary:
    return ProposalSummary(
        proposal_id=d["proposal_id"],
        title=d.get("title", ""),
        proposer=d.get("proposer", ""),
        status=d.get("status", ""),
        submitted_at_height=d.get("submitted_at_height", 0),
        voting_deadline=d.get("voting_deadline"),
    )


def _parse_proposal_detail(d: dict[str, Any]) -> ProposalDetail:
    return ProposalDetail(
        proposal_id=d["proposal_id"],
        title=d.get("title", ""),
        proposer=d.get("proposer", ""),
        status=d.get("status", ""),
        submitted_at_height=d.get("submitted_at_height", 0),
        voting_deadline=d.get("voting_deadline"),
        description=d.get("description"),
        payload=d.get("payload"),
        tally=d.get("tally"),
    )


def _parse_vote_record(d: dict[str, Any]) -> VoteRecord:
    return VoteRecord(
        voter=d["voter"],
        option=d["option"],
        weight=d.get("weight", "0"),
        cast_at_height=d.get("cast_at_height", 0),
    )


def _parse_proposal_votes(d: dict[str, Any]) -> ProposalVotes:
    return ProposalVotes(
        proposal_id=d["proposal_id"],
        status=d.get("status", ""),
        voting_deadline=d.get("voting_deadline"),
        votes=[_parse_vote_record(v) for v in d.get("votes", [])],
    )


def _parse_governance(d: dict[str, Any]) -> GovernanceParameters:
    return GovernanceParameters(
        base_fee_venom=d["base_fee_venom"],
        byte_fee_venom=d["byte_fee_venom"],
        sigverify_fee_venom=d["sigverify_fee_venom"],
        min_stake_venom=d["min_stake_venom"],
        unbonding_period_blocks=d["unbonding_period_blocks"],
        slash_double_sign=d["slash_double_sign"],
        slash_liveness=d["slash_liveness"],
        slash_downtime_exit=d["slash_downtime_exit"],
        # ADR-053 §T2.1 / §T2.2 — optional multi-dim fee + storage fund.
        multi_dim_fee=_parse_multi_dim_fee(d.get("multi_dim_fee")),
        storage_perpetual_cost_per_byte_venom=d.get(
            "storage_perpetual_cost_per_byte_venom"
        ),
    )


class ViperClient:
    """
    HTTP client for the Viper PQ Chain node API.

    :param base_url: Base URL of the pqcd node, e.g. ``"http://localhost:9000"``.
                     Trailing slashes are stripped automatically.
    :param timeout: Request timeout in seconds. Default: 10.
    """

    def __init__(self, base_url: str, timeout: float = 10.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    # -------------------------------------------------------------------------
    # Chain status
    # -------------------------------------------------------------------------

    def get_status(self) -> ChainStatus:
        """GET /v1/status — current chain height, tip hash, and state root."""
        return _parse_chain_status(self._get("/v1/status"))

    # -------------------------------------------------------------------------
    # Blocks
    # -------------------------------------------------------------------------

    def get_block(self, height: int) -> Block:
        """GET /v1/blocks/:height — fetch a block by height."""
        return _parse_block(self._get(f"/v1/blocks/{height}"))

    def get_block_by_hash(self, block_hash: str) -> Block:
        """GET /v1/blocks/:hash — fetch a block by hash (hex)."""
        return _parse_block(self._get(f"/v1/blocks/{block_hash}"))

    # -------------------------------------------------------------------------
    # Transactions
    # -------------------------------------------------------------------------

    def get_transaction(self, tx_hash: str) -> Transaction:
        """GET /v1/txs/:tx_hash — fetch a transaction by hash."""
        return _parse_transaction(self._get(f"/v1/txs/{tx_hash}"))

    def submit_tx(self, cbor_hex: str) -> SubmitTxResponse:
        """
        POST /v1/txs — submit a signed transaction.

        :param cbor_hex: CBOR-encoded signed transaction as a hex string.
                         Produce this with ``pqcd sign-tx`` after building an
                         unsigned tx with the builders in ``viper_pqchain.tx``.
        """
        d = self._post("/v1/txs", {"tx_cbor_hex": cbor_hex})
        return SubmitTxResponse(
            tx_hash=d["tx_hash"],
            status=d["status"],
            error=d.get("error"),
        )

    # -------------------------------------------------------------------------
    # Accounts
    # -------------------------------------------------------------------------

    def get_account(self, address: str) -> Account:
        """GET /v1/accounts/:address — fetch account state including keys."""
        return _parse_account(self._get(f"/v1/accounts/{address}"))

    # -------------------------------------------------------------------------
    # Attestations
    # -------------------------------------------------------------------------

    def get_attestation(self, attestation_id: str) -> Attestation:
        """GET /v1/attestations/:attestation_id — fetch an attestation record."""
        return _parse_attestation(self._get(f"/v1/attestations/{attestation_id}"))

    def get_account_attestations(self, address: str) -> list[AttestationSummary]:
        """
        GET /v1/accounts/:address/attestations — list attestations issued by
        or targeting this address.

        pqcd 880e29c (2026-04-25): response now wraps the array in a
        ``{"data": [...]}`` envelope. The SDK transparently unwraps; the
        return type is the richer ``AttestationSummary`` shape.
        """
        raw = self._get(f"/v1/accounts/{address}/attestations")
        rows = raw["data"] if isinstance(raw, dict) and "data" in raw else raw
        return [_parse_attestation_summary(a) for a in rows]

    # -------------------------------------------------------------------------
    # Validators
    # -------------------------------------------------------------------------

    def get_validators(self) -> list[Validator]:
        """GET /v1/validators — list all validators in the active set."""
        raw = self._get("/v1/validators")
        return [_parse_validator(v) for v in raw]

    def get_validator(self, address: str) -> ValidatorDetail:
        """GET /v1/validators/:address — fetch a single validator.

        pqcd 880e29c (2026-04-25): response wraps detail in ``{"data": ...}``
        with the consensus public key and operator metadata that the list
        endpoint elides. The SDK unwraps and returns ``ValidatorDetail``.
        """
        raw = self._get(f"/v1/validators/{address}")
        body = raw["data"] if isinstance(raw, dict) and "data" in raw else raw
        return _parse_validator_detail(body)

    # -------------------------------------------------------------------------
    # Algorithm registry (pqcd 880e29c — 2026-04-25)
    # -------------------------------------------------------------------------

    def get_algorithms(self) -> list[AlgorithmEntry]:
        """GET /v1/algorithms — list every algorithm in the on-chain registry.

        ``benchmark_verify_per_sec`` and ``min_fee`` may be redacted from
        the public response by a parallel pqcd commit; the dataclass marks
        them ``Optional[int]`` so callers handle both shapes uniformly.
        """
        raw = self._get("/v1/algorithms")
        rows = raw["data"] if isinstance(raw, dict) and "data" in raw else raw
        return [_parse_algorithm_entry(a) for a in rows]

    def get_algorithm(self, alg_id: int) -> AlgorithmEntry:
        """GET /v1/algorithms/:alg_id — fetch a single registry entry.

        Raises :class:`ViperError` (status 404, code ``"ALGORITHM_NOT_FOUND"``)
        when the alg_id is not registered.
        """
        raw = self._get(f"/v1/algorithms/{alg_id}")
        body = raw["data"] if isinstance(raw, dict) and "data" in raw else raw
        return _parse_algorithm_entry(body)

    # -------------------------------------------------------------------------
    # Governance
    # -------------------------------------------------------------------------

    def get_governance_parameters(self) -> GovernanceParameters:
        """GET /v1/governance/parameters — fetch current on-chain governance params."""
        return _parse_governance(self._get("/v1/governance/parameters"))

    def get_proposals(self) -> list[ProposalSummary]:
        """GET /v1/governance/proposals — list all on-chain governance proposals.

        Returns an empty list when no proposals are open (pqcd 880e29c,
        2026-04-25).
        """
        raw = self._get("/v1/governance/proposals")
        rows = raw["data"] if isinstance(raw, dict) and "data" in raw else raw
        return [_parse_proposal_summary(p) for p in rows]

    def get_proposal(self, proposal_id: str) -> ProposalDetail:
        """GET /v1/governance/proposals/:proposal_id — fetch a single proposal."""
        raw = self._get(f"/v1/governance/proposals/{proposal_id}")
        body = raw["data"] if isinstance(raw, dict) and "data" in raw else raw
        return _parse_proposal_detail(body)

    def get_proposal_votes(self, proposal_id: str) -> ProposalVotes:
        """GET /v1/governance/proposals/:proposal_id/votes — vote roster.

        The envelope carries the proposal's voting deadline and current
        status alongside the per-voter rows.
        """
        raw = self._get(f"/v1/governance/proposals/{proposal_id}/votes")
        body = raw["data"] if isinstance(raw, dict) and "data" in raw else raw
        return _parse_proposal_votes(body)

    # -------------------------------------------------------------------------
    # Fee estimation
    # -------------------------------------------------------------------------

    def get_fee_calculator(self) -> FeeCalculator:
        """
        Fetch current governance parameters and return a :class:`FeeCalculator`.

        The calculator is a snapshot — call again if you need fresh values.
        """
        params = self.get_governance_parameters()
        return FeeCalculator(params)

    # -------------------------------------------------------------------------
    # Internal HTTP helpers
    # -------------------------------------------------------------------------

    def _get(self, path: str) -> Any:
        url = f"{self._base_url}{path}"
        req = Request(url, headers={"Accept": "application/json"}, method="GET")
        return self._execute(req, url)

    def _post(self, path: str, body: dict[str, Any]) -> Any:
        url = f"{self._base_url}{path}"
        data = json.dumps(body).encode()
        req = Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        return self._execute(req, url)

    def _execute(self, req: Request, url: str) -> Any:
        # Scheme allowlist guard: urllib.request.urlopen happily handles
        # `file://`, `ftp://` etc., which would let a misconfigured caller
        # leak local-file contents through the Viper client. The SDK only
        # ever talks to a pqcd HTTP endpoint, so reject anything else
        # explicitly before we hand the Request off to urlopen.
        # (semgrep python.lang.security.audit.dynamic-urllib-use-detected)
        if not url.startswith(("http://", "https://")):
            raise ViperError(
                f"Refusing to open non-HTTP(S) URL: {url}",
                code="INVALID_URL_SCHEME",
            )
        try:
            # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected — scheme guard above restricts URL to http(s); base_url comes from operator config, no untrusted input reaches this call.
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                body = resp.read().decode()
        except urllib.error.HTTPError as exc:
            body = exc.read().decode()
            code: Optional[str] = None
            try:
                # Two error-body shapes are accepted:
                #   - legacy flat: {"error": "...", "code": "..."}
                #   - pqcd 880e29c (2026-04-25) nested:
                #       {"error": {"code": "...", "message": "..."}}
                parsed = json.loads(body)
                err = parsed.get("error") if isinstance(parsed, dict) else None
                if isinstance(err, dict):
                    code = err.get("code")
                else:
                    code = parsed.get("code") if isinstance(parsed, dict) else None
            except Exception:
                pass
            raise ViperError(
                f"HTTP {exc.code} from {url}: {body}",
                status_code=exc.code,
                code=code,
            ) from exc
        except urllib.error.URLError as exc:
            raise ViperError(
                f"Network error reaching {url}: {exc.reason}",
            ) from exc

        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise ViperError(
                f"Failed to parse JSON response from {url}: {body[:200]}",
                code="PARSE_ERROR",
            ) from exc
