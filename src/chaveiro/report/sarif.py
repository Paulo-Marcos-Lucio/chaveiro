"""Renderizador SARIF 2.1.0 — para a aba Security do GitHub Code Scanning.

Decalcado de ``esteira/report/sarif.py`` (mesmo catálogo declarativo, mesma
receita de proveniência e de fingerprint), com uma diferença estrutural: a
Esteira varre um REPOSITÓRIO, então cada achado aponta um arquivo e uma
linha (``physicalLocation``). O Chaveiro audita um TOKEN — não há arquivo
nem linha, só um header, um payload e uma assinatura. Um achado aqui não tem
ONDE apontar no sentido de caminho de arquivo; tem O QUE apontar: a SEÇÃO do
token de onde a checagem tirou a informação. É para isso que o SARIF tem
``logicalLocations`` em vez de ``physicalLocation``.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from chaveiro import __version__
from chaveiro.audit import TokenOutcome
from chaveiro.checks.catalog import CATALOG, OWASP_EDITION
from chaveiro.core.models import AuditResult, Finding, Severity
from chaveiro.report import provenance

_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}
# Namespace do fingerprint. NÃO renomear: o GitHub casa alertas já abertos pelo par
# chave+valor, então trocar a chave orfaniza todos os alertas existentes de uma vez.
_FINGERPRINT_KEY = "chaveiroFindingId/v1"

# Prefixo do check_id -> seção do token de onde a checagem lê. Cobre os 26 ids do
# catálogo atual (alg-*/signature-*/header-* vêm do header ou da assinatura;
# claim-*/payload-* vêm do payload); um prefixo novo que o catálogo ainda não tem
# cai em "token" (genérico) em vez de quebrar — checagem nova não fica sem SARIF
# só porque este mapa não foi atualizado no mesmo commit.
_SECAO_POR_PREFIXO: dict[str, str] = {
    "alg": "header",
    "signature": "signature",
    "header": "header",
    "claim": "payload",
    "payload": "payload",
}


def _help_uri(cwe: str | None) -> str | None:
    """Página do CWE do achado — o único destino estável que o catálogo já carrega."""
    if cwe is None or not cwe.startswith("CWE-"):
        return None
    return f"https://cwe.mitre.org/data/definitions/{cwe[4:]}.html"


def _rules() -> list[dict[str, Any]]:
    # Catálogo COMPLETO, inclusive as regras que não dispararam nesta auditoria: é o que faz a
    # aba Security mostrar a regra configurada e silenciosa, e é o que fixa
    # tool.driver.rules == len(CATALOG) independente de quantos achados o token gerou.
    rules: list[dict[str, Any]] = []
    for meta in CATALOG.values():
        rule: dict[str, Any] = {
            "id": meta.id,
            "name": meta.title,
            "shortDescription": {"text": meta.title},
            "fullDescription": {"text": meta.recommendation},
            "defaultConfiguration": {"level": _LEVEL[meta.severity]},
            "properties": {
                "tags": ["security", "jwt", "jws"],
                "security-severity": _SECURITY_SEVERITY[meta.severity],
                "cwe": meta.cwe,
                "owasp": meta.owasp,
                "owasp_edition": OWASP_EDITION,
            },
        }
        help_uri = _help_uri(meta.cwe)
        if help_uri is not None:
            rule["helpUri"] = help_uri
        rules.append(rule)
    return rules


def _secao(check_id: str) -> str:
    prefixo = check_id.split("-", 1)[0]
    return _SECAO_POR_PREFIXO.get(prefixo, "token")


def _logical_location(check_id: str, *, token_index: int | None) -> dict[str, Any]:
    secao = _secao(check_id)
    raiz = "token" if token_index is None else f"token[{token_index}]"
    fqn = raiz if secao == "token" else f"{raiz}/{secao}"
    return {"name": secao, "fullyQualifiedName": fqn, "kind": "value"}


def _fingerprint(finding: Finding, ordinal: int, *, token_index: int | None) -> str:
    """Identidade estável do achado.

    Sem caminho de arquivo (não existe aqui), o material é o check_id + a evidência
    (ou o detalhe, quando a checagem não anexa evidência) + o ORDINAL de ocorrência
    (desempata achados repetidos do mesmo check_id/evidência no mesmo token) + o
    ÍNDICE do token no lote, quando aplicável — sem ele, o mesmo achado em dois
    tokens diferentes de um `batch` colidiria no mesmo fingerprint.
    """
    partes = [finding.check_id, finding.evidence or finding.detail, str(ordinal)]
    if token_index is not None:
        partes.append(str(token_index))
    material = "\0".join(partes)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def _result(finding: Finding, ordinal: int, *, token_index: int | None) -> dict[str, Any]:
    message = f"{finding.detail} {finding.recommendation}"
    result: dict[str, Any] = {
        "ruleId": finding.check_id,
        "level": _LEVEL[finding.severity],
        "message": {"text": message},
        "partialFingerprints": {
            _FINGERPRINT_KEY: _fingerprint(finding, ordinal, token_index=token_index)
        },
        "locations": [
            {"logicalLocations": [_logical_location(finding.check_id, token_index=token_index)]}
        ],
    }
    if token_index is not None:
        result["properties"] = {"tokenIndex": token_index}
    return result


def _results(findings: list[Finding], *, token_index: int | None) -> list[dict[str, Any]]:
    vistos: dict[tuple[str, str], int] = {}
    saida: list[dict[str, Any]] = []
    for finding in findings:
        chave = (finding.check_id, finding.evidence or finding.detail)
        ordinal = vistos.get(chave, 0)
        vistos[chave] = ordinal + 1
        saida.append(_result(finding, ordinal, token_index=token_index))
    return saida


def _document(results: list[dict[str, Any]]) -> dict[str, Any]:
    propriedades: dict[str, Any] = {
        "owasp_edition": OWASP_EDITION,
        "commit": provenance.commit(),
        "ruleset_hash": provenance.ruleset_hash(),
        "artifact_sha256": None,
    }
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "chaveiro",
                "informationUri": "https://github.com/Paulo-Marcos-Lucio/chaveiro",
                "version": __version__,
                "rules": _rules(),
            }
        },
        "results": results,
        "properties": propriedades,
    }
    # O campo mora em runs[0].properties, não na raiz do documento (é onde a proveniência
    # do SARIF vive, ao nível do run). Hash sobre o RUN inteiro, com o campo ainda em
    # null, na mesma receita canônica que o JSON usa para o documento inteiro — quem
    # recomputa aplica a mesma receita a um objeto diferente, não a uma receita diferente.
    blob = json.dumps(run, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    propriedades["artifact_sha256"] = hashlib.sha256(blob.encode("utf-8")).hexdigest()
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }


def to_sarif(result: AuditResult) -> str:
    """SARIF de uma única auditoria (`chaveiro inspect --format sarif`)."""
    return json.dumps(
        _document(_results(result.sorted(), token_index=None)), indent=2, ensure_ascii=False
    )


def batch_to_sarif(outcomes: list[TokenOutcome]) -> str:
    """SARIF de um lote (`chaveiro batch --format sarif`): um run, resultados de todos os
    tokens decodificados com sucesso, cada um marcado com o índice do token de origem
    (`properties.tokenIndex` e o prefixo `token[N]/` em `fullyQualifiedName`) — sem isso,
    achados idênticos de tokens diferentes ficariam indistinguíveis no mesmo relatório.
    Candidato que não decodificou (`outcome.result is None`) não gera resultado SARIF: não
    há checagens para reportar sobre um token que não existe.
    """
    resultados: list[dict[str, Any]] = []
    for outcome in outcomes:
        if outcome.result is None:
            continue
        resultados.extend(_results(outcome.result.sorted(), token_index=outcome.index))
    return json.dumps(_document(resultados), indent=2, ensure_ascii=False)
