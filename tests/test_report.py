from __future__ import annotations

import io
import json

from rich.console import Console

from chaveiro.audit import audit_batch
from chaveiro.checks.catalog import CATALOG
from chaveiro.checks.detectors import run_all
from chaveiro.core.jwt import decode
from chaveiro.core.models import AuditResult
from chaveiro.report.console import render
from chaveiro.report.json_report import to_json
from chaveiro.report.sarif import batch_to_sarif, to_sarif
from tests.conftest import raw_token

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


def test_sarif_structure() -> None:
    doc = json.loads(to_sarif(_result()))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "chaveiro"
    # O catálogo INTEIRO vai para tool.driver.rules, inclusive as regras que não
    # dispararam neste token — não só as que apareceram em `results`.
    assert len(run["tool"]["driver"]["rules"]) == len(CATALOG)
    declared = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert declared == set(CATALOG)
    assert run["results"]  # o token 'none' com claim ausente gera achados
    for res in run["results"]:
        assert res["ruleId"] in declared
        # Sem arquivo/linha (o Chaveiro audita um token, não varre um repositório):
        # a localização é lógica — a SEÇÃO do token de onde a checagem leu.
        loc = res["locations"][0]["logicalLocations"][0]
        assert loc["fullyQualifiedName"]
        assert "physicalLocation" not in res["locations"][0]


def test_sarif_fingerprint_e_estavel() -> None:
    """O mesmo achado, produzido duas vezes a partir do mesmo token, tem que gerar o
    MESMO fingerprint — é o que deixa o GitHub Code Scanning reconhecer o alerta entre
    execuções em vez de abrir (e depois fechar por inatividade) um novo a cada rodada.
    """
    doc1 = json.loads(to_sarif(_result()))
    doc2 = json.loads(to_sarif(_result()))
    fps1 = [r["partialFingerprints"]["chaveiroFindingId/v1"] for r in doc1["runs"][0]["results"]]
    fps2 = [r["partialFingerprints"]["chaveiroFindingId/v1"] for r in doc2["runs"][0]["results"]]
    assert fps1 == fps2
    assert fps1  # o token 'none' realmente gera achado — fingerprint de lista vazia não prova nada
    assert len(fps1) == len(set(fps1))  # achados distintos não colidem entre si


def test_sarif_batch_desambigua_por_token() -> None:
    """Dois tokens idênticos no lote disparam o MESMO achado (mesmo check_id, mesma
    evidência) — sem o índice do token no material do fingerprint, os dois resultados
    colidiriam no mesmo `partialFingerprints` e um consumidor que deduplica por
    fingerprint perderia um achado real do segundo token."""
    token = raw_token({"alg": "none"}, {"sub": "admin"})
    outcomes = audit_batch(f"{token}\n{token}\n", NOW)
    doc = json.loads(batch_to_sarif(outcomes))
    run = doc["runs"][0]
    achados_none = [r for r in run["results"] if r["ruleId"] == "alg-none"]
    assert len(achados_none) == 2
    fps = [r["partialFingerprints"]["chaveiroFindingId/v1"] for r in achados_none]
    assert fps[0] != fps[1]
    indices = [r["properties"]["tokenIndex"] for r in achados_none]
    assert sorted(indices) == [1, 2]
    fqns = [r["locations"][0]["logicalLocations"][0]["fullyQualifiedName"] for r in achados_none]
    assert fqns[0] != fqns[1]
    assert all(fqn.startswith("token[") for fqn in fqns)


def test_sarif_batch_ignora_candidato_malformado() -> None:
    """Um candidato que não decodifica não vira `Finding` nenhum — não há checagem a
    reportar sobre um token que não existe, então ele simplesmente não aparece em
    `results` (e não derruba o lote inteiro, como o resto do `batch` já garante)."""
    token = raw_token({"alg": "none"}, {"sub": "admin"})
    outcomes = audit_batch(f"{token}\nnao-e-um-jwt\n", NOW)
    assert outcomes[1].result is None  # a linha malformada não decodificou
    doc = json.loads(batch_to_sarif(outcomes))
    resultados = doc["runs"][0]["results"]
    assert resultados  # o primeiro token ainda gera achado
    assert all(r["properties"]["tokenIndex"] == 1 for r in resultados)


def test_console_render_does_not_crash() -> None:
    console = Console(file=io.StringIO(), width=200)
    render(_result(), console)
    output = console.file.getvalue()  # type: ignore[attr-defined]
    assert "alg-none" in output


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
