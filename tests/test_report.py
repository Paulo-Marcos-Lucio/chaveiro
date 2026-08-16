from __future__ import annotations

import io
import json

from rich.console import Console

from chaveiro.checks.detectors import run_all
from chaveiro.core.jwt import decode
from chaveiro.core.models import AuditResult
from chaveiro.report.console import render
from chaveiro.report.json_report import to_json
from tests.conftest import jwe_token, raw_token

NOW = 1_800_000_000


def _result() -> AuditResult:
    token = decode(raw_token({"alg": "none"}, {"sub": "admin"}))
    return AuditResult(token=token, findings=run_all(token, NOW))


def test_json_structure() -> None:
    doc = json.loads(to_json(_result()))
    assert doc["schema"] == "suite-appsec/1"
    assert doc["tool"] == "chaveiro"
    assert doc["owasp_edition"] == "2025"
    assert doc["token"]["alg"] == "none"
    assert doc["summary"]["total"] == len(doc["findings"])
    # Contrato da suíte: identificador do achado em 'id' (não 'check'/'rule').
    assert any(f["id"] == "alg-none" for f in doc["findings"])
    # by_severity sempre com as 5 chaves, mesmo as zeradas.
    assert set(doc["summary"]["by_severity"]) == {"critical", "high", "medium", "low", "info"}


def test_console_render_does_not_crash() -> None:
    console = Console(file=io.StringIO(), width=200)
    render(_result(), console)
    output = console.file.getvalue()  # type: ignore[attr-defined]
    assert "alg-none" in output


def test_console_render_de_jwe_nao_finge_payload_vazio_ser_ausencia_de_claims() -> None:
    """Um JWE sem claims legíveis não pode se confundir com um JWT sem claims —
    o console precisa dizer explicitamente que está cifrado, não decifrável."""
    token = decode(jwe_token({"alg": "RSA1_5", "enc": "A128CBC-HS256"}))
    result = AuditResult(token=token, findings=run_all(token, NOW))
    assert any(f.check_id == "jwe-alg-rsa15" for f in result.findings)
    console = Console(file=io.StringIO(), width=200)
    render(result, console)
    output = console.file.getvalue()  # type: ignore[attr-defined]
    assert "JWE" in output
    assert "cifradas" in output


def test_json_de_jwe_traz_kind_e_claims_vazias() -> None:
    token = decode(jwe_token({"alg": "dir", "enc": "A256GCM"}))
    doc = json.loads(to_json(AuditResult(token=token, findings=run_all(token, NOW))))
    assert doc["token"]["kind"] == "jwe"
    assert doc["token"]["claims"] == {}


def test_console_render_escapes_rich_markup() -> None:
    """Dado do token com marcação do rich (`[/]`, `[bold]`) não pode derrubar o
    relatório nem sair interpretado — tem que sair LITERAL. O crash é o sintoma
    barato; a corrupção silenciosa (cor/link forjado no laudo) é a cara.

    O `alg` hostil entra duas vezes: no TÍTULO do painel do token e no DETALHE do
    achado `alg-unknown` (`f"Algoritmo não reconhecido: {alg!r}."`). Um `[/]` é
    uma tag de fechamento sem par — string interpolada levantaria MarkupError.
    """
    from chaveiro.core.jwt import b64url_encode

    header = b64url_encode(json.dumps({"alg": "[/]bold"}).encode("utf-8"))
    payload = b64url_encode(json.dumps({"sub": "[bold red]x[/]"}).encode("utf-8"))
    token = decode(f"{header}.{payload}.AAAA")
    result = AuditResult(token=token, findings=run_all(token, NOW))
    assert any(f.check_id == "alg-unknown" for f in result.findings)  # detalhe carrega o alg hostil
    console = Console(file=io.StringIO(), width=200)
    render(result, console)  # não deve levantar MarkupError
    output = console.file.getvalue()  # type: ignore[attr-defined]
    assert "[/]bold" in output  # saiu literal, não foi consumido como tag
