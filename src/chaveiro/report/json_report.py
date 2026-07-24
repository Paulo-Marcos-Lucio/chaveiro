"""Renderizador JSON da auditoria."""

from __future__ import annotations

import json
from typing import Any

from chaveiro import __version__
from chaveiro.audit import TokenOutcome, summarize
from chaveiro.core.models import AuditResult, Finding


def finding_to_dict(finding: Finding) -> dict[str, Any]:
    return {
        "check": finding.check_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "detail": finding.detail,
        "evidence": finding.evidence,
        "cwe": finding.cwe,
        "owasp": finding.owasp,
        "recommendation": finding.recommendation,
    }


def to_document(result: AuditResult) -> dict[str, Any]:
    findings = result.sorted()
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
    return {
        "tool": "chaveiro",
        "version": __version__,
        "token": {
            "alg": result.token.alg,
            "header": result.token.header,
            "claims": result.token.payload,
        },
        "summary": {"total": len(findings), "by_severity": counts},
        "findings": [finding_to_dict(f) for f in findings],
    }


def to_json(result: AuditResult) -> str:
    return json.dumps(to_document(result), indent=2, ensure_ascii=False)


def _outcome_to_dict(outcome: TokenOutcome) -> dict[str, Any]:
    return {
        "index": outcome.index,
        "line": outcome.line,
        "error": outcome.error,
        "audit": to_document(outcome.result) if outcome.result is not None else None,
    }


def batch_to_document(outcomes: list[TokenOutcome]) -> dict[str, Any]:
    summary = summarize(outcomes)
    return {
        "tool": "chaveiro",
        "version": __version__,
        "mode": "batch",
        "summary": {
            "tokens": summary.tokens,
            "audited": summary.audited,
            "errors": summary.errors,
            "by_severity": summary.by_severity,
            "max_severity": summary.max_severity.value if summary.max_severity else None,
        },
        "results": [_outcome_to_dict(o) for o in outcomes],
    }


def batch_to_json(outcomes: list[TokenOutcome]) -> str:
    return json.dumps(batch_to_document(outcomes), indent=2, ensure_ascii=False)
