"""Testes do modo batch: auditoria de vários tokens de um arquivo/stdin."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from chaveiro.audit import audit_batch, iter_candidates, summarize
from chaveiro.cli import app
from chaveiro.core.models import Severity
from tests.conftest import raw_token

runner = CliRunner()
NOW = 1_800_000_000


def _clean_rs256(sub: str = "user") -> str:
    """Token RS256 sem nenhuma fraqueza passiva (exp futuro, iat, aud, iss)."""
    return raw_token(
        {"alg": "RS256", "typ": "JWT"},
        {"sub": sub, "iat": NOW - 60, "exp": NOW + 3600, "aud": "api", "iss": "https://auth"},
    )


def _none_token() -> str:
    return raw_token({"alg": "none"}, {"sub": "admin"})


# --------------------------------------------------------------------------- #
# iter_candidates — extração de candidatos (um por linha)
# --------------------------------------------------------------------------- #


def test_iter_candidates_skips_blanks_and_comments() -> None:
    text = "\n# comentário\n  \nabc\n\n# outro\ndef\n"
    assert iter_candidates(text) == [(4, "abc"), (7, "def")]


def test_iter_candidates_strips_bearer_prefix() -> None:
    text = "Bearer eyJhbGc\nbearer  xyz\nBEARER zzz"
    assert iter_candidates(text) == [(1, "eyJhbGc"), (2, "xyz"), (3, "zzz")]


# --------------------------------------------------------------------------- #
# audit_batch / summarize — agregação
# --------------------------------------------------------------------------- #


def test_audit_batch_mixed_positive_and_clean() -> None:
    text = f"{_none_token()}\n{_clean_rs256()}\n"
    outcomes = audit_batch(text, NOW)
    assert len(outcomes) == 2
    # o token 'none' é crítico; o RS256 limpo não tem achados
    assert outcomes[0].max_severity() is Severity.CRITICAL
    assert outcomes[1].result is not None
    assert outcomes[1].result.findings == []
    summary = summarize(outcomes)
    assert summary.tokens == 2
    assert summary.audited == 2
    assert summary.errors == 0
    assert summary.max_severity is Severity.CRITICAL


def test_audit_batch_clean_only_no_findings() -> None:
    """Sentido negativo: tokens sem fraqueza não geram achados (sem falso positivo)."""
    text = f"{_clean_rs256('a')}\n{_clean_rs256('b')}\n"
    summary = summarize(audit_batch(text, NOW))
    assert summary.audited == 2
    assert summary.errors == 0
    assert summary.by_severity == {}
    assert summary.max_severity is None


def test_audit_batch_reports_malformed_without_crashing() -> None:
    outcomes = audit_batch(f"não-é-jwt\n{_clean_rs256()}\n", NOW)
    assert outcomes[0].result is None
    assert outcomes[0].error is not None
    assert outcomes[1].ok
    assert summarize(outcomes).errors == 1


# --------------------------------------------------------------------------- #
# CLI — saída e exit-codes
# --------------------------------------------------------------------------- #


def test_cli_batch_file_json_exit1(tmp_path: Path) -> None:
    f = tmp_path / "tokens.txt"
    f.write_text(f"# um none e um limpo\n{_none_token()}\n{_clean_rs256()}\n", encoding="utf-8")
    result = runner.invoke(app, ["batch", str(f), "-f", "json", "--now", str(NOW)])
    assert result.exit_code == 1  # o token 'none' (crítico) >= --fail-on high
    doc = json.loads(result.stdout)
    assert doc["mode"] == "batch"
    assert doc["summary"]["tokens"] == 2
    assert doc["summary"]["max_severity"] == "critical"
    assert len(doc["results"]) == 2
    first_audit = doc["results"][0]["audit"]
    assert any(fnd["check"] == "alg-none" for fnd in first_audit["findings"])


def test_cli_batch_clean_only_exit0(tmp_path: Path) -> None:
    f = tmp_path / "clean.txt"
    f.write_text(f"{_clean_rs256('a')}\n{_clean_rs256('b')}\n", encoding="utf-8")
    result = runner.invoke(app, ["batch", str(f), "-f", "json", "--now", str(NOW)])
    assert result.exit_code == 0
    doc = json.loads(result.stdout)
    assert doc["summary"]["max_severity"] is None


def test_cli_batch_stdin(tmp_path: Path) -> None:
    text = f"{_none_token()}\n{_clean_rs256()}\n"
    result = runner.invoke(app, ["batch", "-", "--now", str(NOW)], input=text)
    assert result.exit_code == 1
    assert "Resumo do lote" in result.stdout


def test_cli_batch_malformed_only_exit2(tmp_path: Path) -> None:
    f = tmp_path / "bad.txt"
    f.write_text("não-é-jwt\nfoo.bar\n", encoding="utf-8")
    result = runner.invoke(app, ["batch", str(f), "--now", str(NOW)])
    assert result.exit_code == 2  # malformado, mas nada atingiu o limiar


def test_cli_batch_fail_on_none_disables_gate(tmp_path: Path) -> None:
    f = tmp_path / "tokens.txt"
    f.write_text(f"{_none_token()}\n{_clean_rs256()}\n", encoding="utf-8")
    result = runner.invoke(app, ["batch", str(f), "--now", str(NOW), "--fail-on", "none"])
    assert result.exit_code == 0  # há achados críticos, mas o gate está desligado


def test_cli_batch_empty_input_exit2(tmp_path: Path) -> None:
    f = tmp_path / "empty.txt"
    f.write_text("# só comentário\n\n", encoding="utf-8")
    result = runner.invoke(app, ["batch", str(f), "--now", str(NOW)])
    assert result.exit_code == 2
