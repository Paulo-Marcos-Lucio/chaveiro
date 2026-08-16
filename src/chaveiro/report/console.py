"""Renderizador para terminal.

Regra deste módulo: **todo dado que vem do token é `Text`**, nunca string
interpolada. O rich interpreta `[...]` como marcação, e claim, `alg`, `kid` e
mensagem de erro são 100% controlados por quem emitiu o token — um `[/]` numa
claim derrubava o relatório inteiro com `MarkupError`, e um `[green]` fazia o
laudo mentir na cor certa.
"""

from __future__ import annotations

import datetime as dt
import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from chaveiro.audit import TokenOutcome, summarize
from chaveiro.checks.catalog import OWASP_EDITION
from chaveiro.core.models import AuditResult, DecodedToken, Finding, Severity
from chaveiro.report.redaction import REDIGIDO, redact_claims

_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
# O identificador em inglês fica no JSON; o rótulo que o cliente lê é PT-BR,
# como no resto da suíte.
_LABEL: dict[Severity, str] = {
    Severity.CRITICAL: "CRÍTICA",
    Severity.HIGH: "ALTA",
    Severity.MEDIUM: "MÉDIA",
    Severity.LOW: "BAIXA",
    Severity.INFO: "INFO",
}
_TIME_CLAIMS = ("exp", "iat", "nbf")
_TOP_PRIORITIES = 3


def render(result: AuditResult, console: Console | None = None, *, redact: bool = False) -> None:
    console = console or Console()
    _render_token(result, console, redact=redact)
    findings = result.sorted()
    if not findings:
        console.print("[bold green]✓ Nenhuma fraqueza detectada nas checagens passivas.[/]")
        return
    table = Table(show_lines=False, expand=True, header_style="bold")
    table.add_column("Sev", no_wrap=True)
    table.add_column("Checagem", no_wrap=True)
    table.add_column("Detalhe", overflow="fold")
    table.add_column(f"OWASP {OWASP_EDITION} / CWE", no_wrap=True)
    for finding in findings:
        table.add_row(
            Text(_LABEL[finding.severity], style=_STYLE[finding.severity]),
            Text(finding.check_id),
            Text(finding.detail),
            Text(f"{_short_owasp(finding)} · {finding.cwe or '—'}"),
        )
    console.print(table)
    _render_action_plan(findings, console)


def _render_action_plan(findings: list[Finding], console: Console) -> None:
    """O que fazer com os piores achados — a recomendação já existe, mostre-a."""
    body = Text()
    for position, finding in enumerate(findings[:_TOP_PRIORITIES]):
        if position:
            body.append("\n\n")
        body.append(f"{position + 1}. ", style="bold")
        body.append(_LABEL[finding.severity], style=_STYLE[finding.severity])
        body.append(f" · {finding.check_id}\n   → ")
        body.append(finding.recommendation)
    console.print(Panel(body, title="Plano de ação — comece por aqui", border_style="green"))


def _render_token(result: AuditResult, console: Console, *, redact: bool = False) -> None:
    body = Text.assemble(
        ("header\n", "bold cyan"),
        json.dumps(result.token.header, indent=2, ensure_ascii=False),
        ("\n\nclaims\n", "bold cyan"),
        _claims_with_readable_times(result, redact=redact),
    )
    console.print(
        Panel(
            body,
            title=Text.assemble("Token · alg=", (result.token.alg or "—", "bold")),
            border_style="cyan",
        )
    )


def _claims_with_readable_times(result: AuditResult, *, redact: bool = False) -> str:
    if result.token.kind == "jwe":
        return (
            "<claims cifradas — JWE (RFC 7516): o Chaveiro audita o cabeçalho protegido "
            "sem decifrar nada; payload vazio aqui não é 'sem claims', é 'claims ilegíveis "
            "sem a chave'>"
        )
    if result.token.nested is not None:
        return (
            "<JWT aninhado: o payload desta casca é outro JWS compacto>\n"
            "Audite o token interno separadamente: chaveiro inspect <token-interno>"
        )
    # P1-01: mesmo no console a PII do titular é redigida por padrão.
    payload = redact_claims(result.token.payload) if redact else dict(result.token.payload)
    notes = []
    for claim in _TIME_CLAIMS:
        value = payload.get(claim)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            try:
                when = dt.datetime.fromtimestamp(int(value), tz=dt.timezone.utc)
                notes.append(f"{claim} = {when.isoformat()}")
            except (OSError, OverflowError, ValueError):
                notes.append(f"{claim} = {value} (fora do intervalo de datas)")
    body = json.dumps(payload, indent=2, ensure_ascii=False)
    if notes:
        body += "\n\n" + "\n".join(notes)
    return body


def _short_owasp(finding: Finding) -> str:
    if not finding.owasp:
        return "—"
    return finding.owasp.split(":")[0]


def _describe(token: DecodedToken, *, redact: bool = False) -> str:
    """Identificador curto e legível de um token para a tabela do lote.

    Prefere 'iss' (estrutural) a 'sub' (identidade do titular). Se cair no 'sub',
    ele é redigido por padrão — a tabela do lote também não pode vazar PII.
    """
    iss = token.payload.get("iss")
    if isinstance(iss, str) and iss:
        return f"alg={token.alg or '—'} · {iss}"
    sub = token.payload.get("sub")
    if isinstance(sub, str) and sub:
        return f"alg={token.alg or '—'} · {REDIGIDO if redact else sub}"
    return f"alg={token.alg or '—'}"


def render_batch(
    outcomes: list[TokenOutcome], console: Console | None = None, *, redact: bool = False
) -> None:
    console = console or Console()
    table = Table(show_lines=False, expand=True, header_style="bold")
    table.add_column("#", no_wrap=True, justify="right")
    table.add_column("Linha", no_wrap=True, justify="right")
    table.add_column("Token", overflow="fold")
    table.add_column("Pior", no_wrap=True)
    table.add_column("Achados", no_wrap=True, justify="right")
    for outcome in outcomes:
        if outcome.result is None:
            token_desc = Text(f"[não decodificou] {outcome.error}", style="magenta")
            severity = Text("ERRO", style="bold magenta")
            count = "—"
        else:
            token_desc = Text(_describe(outcome.result.token, redact=redact))
            top = outcome.result.max_severity()
            severity = (
                Text(_LABEL[top], style=_STYLE[top])
                if top is not None
                else Text("ok", style="green")
            )
            count = str(len(outcome.result.findings))
        table.add_row(str(outcome.index), str(outcome.line), token_desc, severity, count)
    console.print(table)
    _render_batch_summary(outcomes, console)


def _render_batch_summary(outcomes: list[TokenOutcome], console: Console) -> None:
    summary = summarize(outcomes)
    worst = summary.max_severity
    worst_text = (
        Text(_LABEL[worst], style=_STYLE[worst])
        if worst is not None
        else Text("nenhuma", style="green")
    )
    parts = [f"{sev}={n}" for sev, n in sorted(summary.by_severity.items()) if n]
    breakdown = ("  ·  " + "  ".join(parts)) if parts else ""
    body = Text.assemble(
        f"tokens={summary.tokens}  auditados={summary.audited}  erros={summary.errors}  pior=",
        worst_text,
        breakdown,
    )
    console.print(Panel(body, title="Resumo do lote", border_style="cyan"))
