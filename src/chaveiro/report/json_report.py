"""Renderizador JSON da auditoria.

Contrato comum da suíte (`schema: suite-appsec/1`): identificador do achado em
`id`, severidade em inglês minúsculo com `severity_rank` para ordenar sem tabela
de-para, `by_severity` sempre com as 5 chaves (inclusive zeradas) e a edição do
OWASP declarada como campo, para que um painel não precise fazer parsing do
rótulo.
"""

from __future__ import annotations

import json
from typing import Any

from chaveiro import __version__
from chaveiro.audit import TokenOutcome, summarize
from chaveiro.checks.catalog import OWASP_EDITION
from chaveiro.core.models import AuditResult, Finding, Severity
from chaveiro.report import provenance
from chaveiro.report.redaction import redact_claims

SCHEMA = "suite-appsec/1"


def _provenance(document: dict[str, Any]) -> dict[str, Any]:
    """Acrescenta commit/ruleset_hash/artifact_sha256 ao envelope (P1-03).

    O artifact_sha256 é calculado por ÚLTIMO, sobre o documento já completo menos
    o próprio campo, para ser autoverificável pelo cliente.
    """
    document["commit"] = provenance.commit()
    document["ruleset_hash"] = provenance.ruleset_hash()
    document["artifact_sha256"] = provenance.artifact_sha256(document)
    return document


def finding_to_dict(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.check_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "severity_rank": finding.severity.rank,
        "detail": finding.detail,
        "evidence": finding.evidence,
        "cwe": finding.cwe,
        "owasp": finding.owasp,
        "recommendation": finding.recommendation,
    }


def to_document(
    result: AuditResult, *, redact: bool = False, include_provenance: bool = True
) -> dict[str, Any]:
    findings = result.sorted()
    counts = {s.value: 0 for s in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
    # P1-01: por padrão o CLI grava com redact=True; a claim de identidade do
    # titular final não vai a disco sem opt-in explícito.
    claims = redact_claims(result.token.payload) if redact else result.token.payload
    document = {
        "schema": SCHEMA,
        "tool": "chaveiro",
        "version": __version__,
        "owasp_edition": OWASP_EDITION,
        "token": {
            "alg": result.token.alg,
            "header": result.token.header,
            "claims": claims,
            # Token interno quando a casca é um JWT aninhado (RFC 7519 §5.2).
            "nested": result.token.nested,
        },
        "summary": {"total": len(findings), "by_severity": counts},
        "findings": [finding_to_dict(f) for f in findings],
    }
    # No batch a proveniência fica no envelope de fora — evita um subprocesso git
    # por token e um hash por sub-documento.
    return _provenance(document) if include_provenance else document


def to_json(result: AuditResult, *, redact: bool = False) -> str:
    return json.dumps(to_document(result, redact=redact), indent=2, ensure_ascii=False)


def _outcome_to_dict(outcome: TokenOutcome, *, redact: bool) -> dict[str, Any]:
    return {
        "index": outcome.index,
        "line": outcome.line,
        "error": outcome.error,
        "audit": (
            to_document(outcome.result, redact=redact, include_provenance=False)
            if outcome.result is not None
            else None
        ),
    }


def batch_to_document(outcomes: list[TokenOutcome], *, redact: bool = False) -> dict[str, Any]:
    summary = summarize(outcomes)
    document = {
        "schema": SCHEMA,
        "tool": "chaveiro",
        "version": __version__,
        "owasp_edition": OWASP_EDITION,
        "mode": "batch",
        "summary": {
            "tokens": summary.tokens,
            "audited": summary.audited,
            "errors": summary.errors,
            "by_severity": summary.by_severity,
            "max_severity": summary.max_severity.value if summary.max_severity else None,
        },
        "results": [_outcome_to_dict(o, redact=redact) for o in outcomes],
    }
    return _provenance(document)


def batch_to_json(outcomes: list[TokenOutcome], *, redact: bool = False) -> str:
    return json.dumps(batch_to_document(outcomes, redact=redact), indent=2, ensure_ascii=False)
