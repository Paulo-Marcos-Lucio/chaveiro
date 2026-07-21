"""Renderizador JSON da auditoria."""

from __future__ import annotations

import json
from typing import Any

from chaveiro import __version__
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
