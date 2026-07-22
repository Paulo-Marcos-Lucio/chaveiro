"""Renderizador para terminal."""

from __future__ import annotations

import datetime as dt
import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from chaveiro.core.models import AuditResult, Finding, Severity

_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
_TIME_CLAIMS = ("exp", "iat", "nbf")


def render(result: AuditResult, console: Console | None = None) -> None:
    console = console or Console()
    _render_token(result, console)
    findings = result.sorted()
    if not findings:
        console.print("[bold green]✓ Nenhuma fraqueza detectada nas checagens passivas.[/]")
        return
    table = Table(show_lines=False, expand=True, header_style="bold")
    table.add_column("Sev", no_wrap=True)
    table.add_column("Checagem", no_wrap=True)
    table.add_column("Detalhe", overflow="fold")
    table.add_column("OWASP/CWE", no_wrap=True)
    for finding in findings:
        table.add_row(
            Text(finding.severity.value.upper(), style=_STYLE[finding.severity]),
            finding.check_id,
            finding.detail,
            f"{_short_owasp(finding)} · {finding.cwe or '—'}",
        )
    console.print(table)


def _render_token(result: AuditResult, console: Console) -> None:
    header = json.dumps(result.token.header, indent=2, ensure_ascii=False)
    claims = _claims_with_readable_times(result)
    console.print(
        Panel(
            f"[bold cyan]header[/]\n{header}\n\n[bold cyan]claims[/]\n{claims}",
            title=f"Token · alg={result.token.alg or '—'}",
            border_style="cyan",
        )
    )


def _claims_with_readable_times(result: AuditResult) -> str:
    payload = dict(result.token.payload)
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
