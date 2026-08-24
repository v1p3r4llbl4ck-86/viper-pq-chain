"""Unit tests for the 0.3.0 client extensions.

Covers the 7 new typed read methods aligned to the public endpoints
landed in pqcd 880e29c (2026-04-25):

  - ``get_algorithms`` / ``get_algorithm``
  - ``get_validator``  (now returns ``ValidatorDetail``)
  - ``get_account_attestations``  (now returns ``list[AttestationSummary]``)
  - ``get_proposals`` / ``get_proposal`` / ``get_proposal_votes``

No live network: each test patches ``urllib.request.urlopen`` with a
fixture response so we exercise URL construction + envelope unwrapping
+ JSON-parse + 404 error mapping deterministically.
"""

from __future__ import annotations

import io
import json
import urllib.error
from unittest.mock import patch

import pytest

from viper_pqchain import (
    AlgorithmEntry,
    AttestationSummary,
    ProposalDetail,
    ProposalSummary,
    ProposalVotes,
    ValidatorDetail,
    ViperClient,
    ViperError,
    VoteRecord,
)


# ---------------------------------------------------------------------------
# urlopen fixture helpers
# ---------------------------------------------------------------------------


class _FakeResponse:
    """Minimal stand-in for the urllib response context-manager."""

    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


def _ok(payload: object):
    """Build a urlopen replacement that captures the request URL and returns
    a JSON 200 with ``payload`` as the body."""

    captured: dict[str, str] = {}

    def fake_urlopen(req, timeout: float = 0):  # noqa: ARG001
        captured["url"] = req.full_url
        return _FakeResponse(json.dumps(payload).encode())

    return fake_urlopen, captured


def _http_error(status: int, body: object):
    """Build a urlopen replacement that raises HTTPError(status) with
    ``body`` (dict or str) as the response payload."""

    body_bytes = (
        json.dumps(body).encode() if not isinstance(body, (bytes, str)) else
        (body.encode() if isinstance(body, str) else body)
    )

    def fake_urlopen(req, timeout: float = 0):  # noqa: ARG001
        raise urllib.error.HTTPError(
            req.full_url,
            status,
            "Not Found",
            hdrs=None,  # type: ignore[arg-type]
            fp=io.BytesIO(body_bytes),
        )

    return fake_urlopen


CLIENT = ViperClient("https://node.example.com")


# ---------------------------------------------------------------------------
# get_algorithms / get_algorithm
# ---------------------------------------------------------------------------


def test_get_algorithms_unwraps_envelope_and_handles_optional_fields():
    payload = {
        "data": [
            {
                "alg_id": 1,
                "spec_ref": "FIPS 204",
                "pk_size": 1312,
                "sig_size": 2420,
                "sig_class": "standard",
                "lifecycle": "active",
                "min_fee": 0,
                "benchmark_verify_per_sec": 89000,
            },
            # Redacted shape — both calibration fields absent.
            {
                "alg_id": 256,
                "spec_ref": "FIPS 203",
                "pk_size": 1184,
                "sig_size": 0,
                "sig_class": None,
                "lifecycle": "active",
            },
        ]
    }
    fake, captured = _ok(payload)
    with patch("urllib.request.urlopen", fake):
        algs = CLIENT.get_algorithms()
    assert captured["url"] == "https://node.example.com/v1/algorithms"
    assert len(algs) == 2
    assert isinstance(algs[0], AlgorithmEntry)
    assert algs[0].alg_id == 1
    assert algs[0].benchmark_verify_per_sec == 89000
    # Redacted entry — optional fields default to None.
    assert algs[1].benchmark_verify_per_sec is None
    assert algs[1].min_fee is None
    assert algs[1].sig_class is None


def test_get_algorithm_constructs_correct_url():
    payload = {
        "data": {
            "alg_id": 2,
            "spec_ref": "FIPS 204",
            "pk_size": 1952,
            "sig_size": 3309,
            "sig_class": "standard",
            "lifecycle": "active",
        }
    }
    fake, captured = _ok(payload)
    with patch("urllib.request.urlopen", fake):
        alg = CLIENT.get_algorithm(2)
    assert captured["url"] == "https://node.example.com/v1/algorithms/2"
    assert alg.alg_id == 2
    assert alg.spec_ref == "FIPS 204"


def test_get_algorithm_404_maps_to_viper_error_with_code():
    body = {
        "error": {
            "code": "ALGORITHM_NOT_FOUND",
            "message": "alg_id 9999 not registered",
        }
    }
    with patch("urllib.request.urlopen", _http_error(404, body)):
        with pytest.raises(ViperError) as exc_info:
            CLIENT.get_algorithm(9999)
    assert exc_info.value.status_code == 404
    assert exc_info.value.code == "ALGORITHM_NOT_FOUND"


# ---------------------------------------------------------------------------
# get_validator (now ValidatorDetail)
# ---------------------------------------------------------------------------


def test_get_validator_returns_validator_detail():
    payload = {
        "data": {
            "address": "ab" * 32,
            "consensus_alg_id": 2,
            "consensus_pk_hex": "cd" * 16,
            "node_id": "validator-7",
            "registered_height": 0,
            "self_bond": "0",
            "status": "active",
            "tombstoned": False,
        }
    }
    fake, captured = _ok(payload)
    with patch("urllib.request.urlopen", fake):
        v = CLIENT.get_validator("ab" * 32)
    assert captured["url"] == f"https://node.example.com/v1/validators/{'ab' * 32}"
    assert isinstance(v, ValidatorDetail)
    assert v.consensus_alg_id == 2
    assert v.node_id == "validator-7"
    assert v.tombstoned is False


# ---------------------------------------------------------------------------
# get_account_attestations
# ---------------------------------------------------------------------------


def test_get_account_attestations_unwraps_envelope():
    payload = {"data": []}
    fake, captured = _ok(payload)
    with patch("urllib.request.urlopen", fake):
        att = CLIENT.get_account_attestations("ab" * 32)
    assert captured["url"] == (
        f"https://node.example.com/v1/accounts/{'ab' * 32}/attestations"
    )
    assert att == []


def test_get_account_attestations_parses_summary_rows():
    payload = {
        "data": [
            {
                "attestation_id": "ee" * 32,
                "issuer": "01" * 32,
                "subject": "02" * 32,
                "issued_at_height": 17,
            }
        ]
    }
    fake, _ = _ok(payload)
    with patch("urllib.request.urlopen", fake):
        att = CLIENT.get_account_attestations("ab" * 32)
    assert len(att) == 1
    assert isinstance(att[0], AttestationSummary)
    assert att[0].schema_id is None  # absent in fixture → None


# ---------------------------------------------------------------------------
# get_proposals / get_proposal / get_proposal_votes
# ---------------------------------------------------------------------------


def test_get_proposals_returns_empty_list_on_quiet_chain():
    fake, captured = _ok({"data": []})
    with patch("urllib.request.urlopen", fake):
        props = CLIENT.get_proposals()
    assert captured["url"] == "https://node.example.com/v1/governance/proposals"
    assert props == []


def test_get_proposals_parses_summary():
    payload = {
        "data": [
            {
                "proposal_id": "PRP-1",
                "title": "Bump min stake",
                "proposer": "11" * 32,
                "status": "voting",
                "submitted_at_height": 1000,
                "voting_deadline": 2000,
            }
        ]
    }
    fake, _ = _ok(payload)
    with patch("urllib.request.urlopen", fake):
        props = CLIENT.get_proposals()
    assert isinstance(props[0], ProposalSummary)
    assert props[0].voting_deadline == 2000


def test_get_proposal_returns_detail_with_tally():
    payload = {
        "data": {
            "proposal_id": "PRP-1",
            "title": "Bump min stake",
            "proposer": "11" * 32,
            "status": "voting",
            "submitted_at_height": 1000,
            "voting_deadline": 2000,
            "description": "Increase min_stake to 32k VPR.",
            "payload": "deadbeef",
            "tally": {"yes": "100", "no": "0", "abstain": "5"},
        }
    }
    fake, captured = _ok(payload)
    with patch("urllib.request.urlopen", fake):
        p = CLIENT.get_proposal("PRP-1")
    assert captured["url"] == "https://node.example.com/v1/governance/proposals/PRP-1"
    assert isinstance(p, ProposalDetail)
    assert p.tally == {"yes": "100", "no": "0", "abstain": "5"}
    assert p.payload == "deadbeef"


def test_get_proposal_votes_unwraps_and_parses_records():
    payload = {
        "data": {
            "proposal_id": "PRP-1",
            "voting_deadline": 2000,
            "status": "voting",
            "votes": [
                {
                    "voter": "22" * 32,
                    "option": "yes",
                    "weight": "1000000000000000000",
                    "cast_at_height": 1234,
                }
            ],
        }
    }
    fake, captured = _ok(payload)
    with patch("urllib.request.urlopen", fake):
        pv = CLIENT.get_proposal_votes("PRP-1")
    assert captured["url"] == (
        "https://node.example.com/v1/governance/proposals/PRP-1/votes"
    )
    assert isinstance(pv, ProposalVotes)
    assert len(pv.votes) == 1
    assert isinstance(pv.votes[0], VoteRecord)
    assert pv.votes[0].option == "yes"


def test_get_proposal_404_maps_to_viper_error():
    body = {"error": {"code": "PROPOSAL_NOT_FOUND", "message": "no such proposal"}}
    with patch("urllib.request.urlopen", _http_error(404, body)):
        with pytest.raises(ViperError) as exc_info:
            CLIENT.get_proposal("nonexistent")
    assert exc_info.value.status_code == 404
    assert exc_info.value.code == "PROPOSAL_NOT_FOUND"
