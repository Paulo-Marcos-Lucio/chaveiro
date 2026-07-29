"""Testes do modo batch: auditoria de vários tokens de um arquivo/stdin."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

import chaveiro.audit as audit_mod
from chaveiro.audit import audit_batch, audit_token, iter_candidates, summarize
from chaveiro.cli import app
from chaveiro.core.jwt import b64url_encode
from chaveiro.core.models import Severity
from chaveiro.report.console import render_batch
from chaveiro.report.json_report import batch_to_json
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
    # Contrato do relatório: as 5 chaves sempre presentes, zeradas quando não há
    # achado — quem consome não precisa distinguir zero de chave ausente.
    assert summary.by_severity == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    assert summary.max_severity is None


def test_audit_batch_reports_malformed_without_crashing() -> None:
    outcomes = audit_batch(f"não-é-jwt\n{_clean_rs256()}\n", NOW)
    assert outcomes[0].result is None
    assert outcomes[0].error is not None
    assert outcomes[1].ok
    assert summarize(outcomes).errors == 1


def test_audit_batch_token_bomba_nao_derruba_o_lote() -> None:
    """JWT hostil profundamente aninhado não pode apagar a auditoria dos demais.

    Contrato documentado: isolamento por token. A profundidade escolhida (1500)
    é a que expõe o buraco todo: está ABAIXO do limite do json.loads (~2998) mas
    ACIMA do limite do json.dumps (~996) que os relatórios usam — ou seja, sem o
    teto de aninhamento o token DECODIFICA e só depois derruba a serialização do
    lote. Com o teto, ele vira erro por linha e o token legítimo seguinte é
    auditado; render e JSON do lote rodam sem levantar.
    """
    deep = ('{"a":' * 1500 + "1" + "}" * 1500).encode()
    header_b64 = b64url_encode(json.dumps({"alg": "HS256"}).encode("utf-8"))
    bomba = f"{header_b64}.{b64url_encode(deep)}.{b64url_encode(b'x')}"
    outcomes = audit_batch(f"{bomba}\n{_clean_rs256()}\n", NOW)
    assert len(outcomes) == 2
    assert outcomes[0].result is None  # bomba isolada como erro
    assert outcomes[0].error is not None
    assert outcomes[1].ok  # token legítimo auditado
    # render e serialização não podem levantar (o encoder JSON também é recursivo)
    console = Console(file=io.StringIO(), width=200)
    render_batch(outcomes, console)
    assert console.file.getvalue()  # type: ignore[attr-defined]
    assert batch_to_json(outcomes)


def test_audit_batch_isola_qualquer_excecao_nao_so_jwterror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Contrato: isolamento por token para QUALQUER exceção, não só JWTError.

    O `except` largo é a rede que impede a próxima classe de falha imprevista de
    matar o lote inteiro. Aqui forçamos um erro que NÃO é JWTError no primeiro
    token e exigimos que o segundo ainda seja auditado, com o tipo do erro
    registrado no `error`.
    """
    real = audit_token

    def fake(token: str, now: int) -> object:
        if "veneno" in token:
            raise RuntimeError("erro inesperado no meio do lote")
        return real(token, now)

    monkeypatch.setattr(audit_mod, "audit_token", fake)
    outcomes = audit_batch(f"veneno.aaa.bbb\n{_clean_rs256()}\n", NOW)
    assert len(outcomes) == 2
    assert outcomes[0].result is None
    assert outcomes[0].error is not None
    assert "RuntimeError" in outcomes[0].error  # tipo registrado, nada escondido
    assert outcomes[1].ok  # o token legítimo seguinte foi auditado


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
    assert any(fnd["id"] == "alg-none" for fnd in first_audit["findings"])


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


def test_cli_batch_malformed_only_exit0(tmp_path: Path) -> None:
    # Linha malformada é ruído normal em token colhido de log: não derruba o
    # build. A contagem vai para o stderr; o exit code depende só de --fail-on.
    f = tmp_path / "bad.txt"
    f.write_text("não-é-jwt\nfoo.bar\n", encoding="utf-8")
    result = runner.invoke(app, ["batch", str(f), "--now", str(NOW)])
    assert result.exit_code == 0


def test_cli_batch_strict_fails_on_malformed(tmp_path: Path) -> None:
    # Com --strict, quem quer travar em entrada malformada ganha o gate explícito.
    f = tmp_path / "bad.txt"
    f.write_text("não-é-jwt\nfoo.bar\n", encoding="utf-8")
    result = runner.invoke(app, ["batch", str(f), "--now", str(NOW), "--strict"])
    assert result.exit_code == 1


def test_cli_batch_fail_on_none_disables_gate(tmp_path: Path) -> None:
    f = tmp_path / "tokens.txt"
    f.write_text(f"{_none_token()}\n{_clean_rs256()}\n", encoding="utf-8")
    result = runner.invoke(app, ["batch", str(f), "--now", str(NOW), "--fail-on", "none"])
    assert result.exit_code == 0  # há achados críticos, mas o gate está desligado


def test_cli_batch_empty_input_exit0(tmp_path: Path) -> None:
    # Entrada sem token não é erro de uso — sai 0 com uma nota no stderr.
    f = tmp_path / "empty.txt"
    f.write_text("# só comentário\n\n", encoding="utf-8")
    result = runner.invoke(app, ["batch", str(f), "--now", str(NOW)])
    assert result.exit_code == 0
