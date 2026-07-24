"""Orquestração da auditoria passiva — um token e em lote (batch).

Camada acima de `core` e `checks`: compõe `decode` (sem verificar assinatura)
com `run_all` (as checagens passivas). A CLI usa `audit_token` tanto no
`inspect` quanto no `batch`, para que exista uma única fonte da verdade do que
"auditar um token" significa.
"""

from __future__ import annotations

from dataclasses import dataclass

from chaveiro.checks.detectors import run_all
from chaveiro.core.jwt import JWTError, decode
from chaveiro.core.models import AuditResult, Severity

_BEARER = "bearer "


def audit_token(token: str, now: int) -> AuditResult:
    """Decodifica (sem verificar assinatura) e roda todas as checagens passivas.

    Levanta `JWTError` se o token for malformado — o chamador decide o que fazer.
    """
    decoded = decode(token)
    return AuditResult(token=decoded, findings=run_all(decoded, now))


@dataclass(frozen=True)
class TokenOutcome:
    """Resultado da auditoria de um candidato a token vindo de um lote."""

    index: int  # 1-based, ordem de auditoria
    line: int  # 1-based, número da linha no arquivo/stream de origem
    raw: str  # o candidato a token, como lido (após strip e remoção de 'Bearer ')
    result: AuditResult | None  # None quando o candidato não pôde ser decodificado
    error: str | None  # mensagem do JWTError quando `result is None`

    @property
    def ok(self) -> bool:
        return self.error is None

    def max_severity(self) -> Severity | None:
        return self.result.max_severity() if self.result is not None else None


def iter_candidates(text: str) -> list[tuple[int, str]]:
    """Extrai candidatos a token de um texto: **um por linha**.

    Ignora linhas em branco e comentários (que começam com ``#``) e remove um
    prefixo ``Bearer `` opcional (comum em cabeçalhos ``Authorization`` copiados
    de logs). Não faz varredura de subtoken dentro de linhas arbitrárias — o
    contrato é um token por linha.
    """
    candidates: list[tuple[int, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped[:7].lower() == _BEARER:
            stripped = stripped[7:].strip()
        if stripped:
            candidates.append((lineno, stripped))
    return candidates


def audit_batch(text: str, now: int) -> list[TokenOutcome]:
    """Audita todos os candidatos a token do texto, preservando a ordem.

    Um token malformado vira um `TokenOutcome` com `error` — não interrompe o
    lote nem contamina os demais.
    """
    outcomes: list[TokenOutcome] = []
    for index, (lineno, candidate) in enumerate(iter_candidates(text), start=1):
        try:
            result = audit_token(candidate, now)
        except JWTError as exc:
            outcomes.append(TokenOutcome(index, lineno, candidate, None, str(exc)))
        else:
            outcomes.append(TokenOutcome(index, lineno, candidate, result, None))
    return outcomes


@dataclass(frozen=True)
class BatchSummary:
    """Agregado de um lote auditado."""

    tokens: int  # candidatos processados
    audited: int  # decodificados com sucesso
    errors: int  # malformados
    by_severity: dict[str, int]  # contagem de achados por severidade (todos os tokens)
    max_severity: Severity | None  # pior severidade vista no lote


def summarize(outcomes: list[TokenOutcome]) -> BatchSummary:
    by_severity: dict[str, int] = {}
    worst: Severity | None = None
    audited = 0
    errors = 0
    for outcome in outcomes:
        if outcome.result is None:
            errors += 1
            continue
        audited += 1
        for finding in outcome.result.findings:
            key = finding.severity.value
            by_severity[key] = by_severity.get(key, 0) + 1
        top = outcome.result.max_severity()
        if top is not None and (worst is None or top.rank > worst.rank):
            worst = top
    return BatchSummary(len(outcomes), audited, errors, by_severity, worst)
