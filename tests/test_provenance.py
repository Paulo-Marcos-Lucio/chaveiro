"""Proveniência do envelope JSON (P1-03): o laudo tem que ser vinculável a um
código e a um conjunto de regras, e autoverificável.

Defeito: o relatório não trazia `commit`, `ruleset_hash` nem `artifact_sha256` —
um laudo solto, impossível de amarrar à versão que o produziu.
"""

from __future__ import annotations

import json
import re

import pytest

from chaveiro.audit import audit_batch
from chaveiro.checks.detectors import run_all
from chaveiro.core.jwt import decode
from chaveiro.core.models import AuditResult
from chaveiro.report.json_report import batch_to_json, to_json
from tests.conftest import raw_token

NOW = 1_800_000_000
_HEX64 = re.compile(r"[0-9a-f]{64}")


def _result() -> AuditResult:
    token = decode(raw_token({"alg": "none"}, {"sub": "admin"}))
    return AuditResult(token=token, findings=run_all(token, NOW))


def test_envelope_traz_commit_ruleset_hash_e_artifact_sha256(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CHAVEIRO_COMMIT", "deadbeefcafe")
    doc = json.loads(to_json(_result()))
    assert doc["commit"] == "deadbeefcafe"
    assert _HEX64.fullmatch(doc["ruleset_hash"])
    assert _HEX64.fullmatch(doc["artifact_sha256"])


def test_commit_e_none_quando_nao_ha_fonte(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CHAVEIRO_COMMIT", raising=False)
    monkeypatch.setattr("chaveiro.report.provenance._git_head", lambda: None)
    doc = json.loads(to_json(_result()))
    assert doc["commit"] is None


def test_artifact_sha256_e_autoverificavel(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CHAVEIRO_COMMIT", "x")
    from chaveiro.report.provenance import artifact_sha256

    doc = json.loads(to_json(_result()))
    # recomputar o hash sobre o documento SEM o próprio campo tem que bater
    assert artifact_sha256(doc) == doc["artifact_sha256"]


def test_ruleset_hash_e_estavel_entre_execucoes() -> None:
    from chaveiro.report.provenance import ruleset_hash

    assert ruleset_hash() == ruleset_hash()


def test_envelope_batch_tambem_traz_proveniencia(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CHAVEIRO_COMMIT", "abc123")
    outcomes = audit_batch(raw_token({"alg": "none"}, {"sub": "a"}) + "\n", NOW)
    doc = json.loads(batch_to_json(outcomes))
    assert doc["commit"] == "abc123"
    assert _HEX64.fullmatch(doc["ruleset_hash"])
    assert _HEX64.fullmatch(doc["artifact_sha256"])
