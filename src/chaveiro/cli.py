"""Interface de linha de comando do Chaveiro."""

from __future__ import annotations

import contextlib
import json
import sys
import time
from enum import Enum
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from chaveiro import __version__
from chaveiro.attacks.confusion import forge_rs_to_hs
from chaveiro.attacks.crack import crack as crack_secret
from chaveiro.attacks.crack import crack_with_defaults
from chaveiro.checks.catalog import CATALOG
from chaveiro.checks.detectors import run_all
from chaveiro.core.jwt import JWTError, decode, encode_hmac
from chaveiro.core.models import AuditResult, Severity
from chaveiro.report import console as console_report
from chaveiro.report.json_report import to_json

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Chaveiro — audita a segurança de tokens JWT/JWS.",
)
err = Console(stderr=True)


class Format(str, Enum):
    console = "console"
    json = "json"


class FailOn(str, Enum):
    none = "none"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

    def rank(self) -> int:
        return 99 if self is FailOn.none else Severity(self.value).rank


def _version_cb(value: bool) -> None:
    if value:
        typer.echo(f"chaveiro {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    _v: bool = typer.Option(
        False, "--version", "-V", callback=_version_cb, is_eager=True, help="Mostra a versão."
    ),
) -> None:
    pass


def _decode_or_die(token: str) -> Any:
    try:
        return decode(token)
    except JWTError as exc:
        err.print(f"[red]Token inválido:[/] {exc}")
        raise typer.Exit(2) from exc


def _parse_set(pairs: list[str]) -> dict[str, Any]:
    edits: dict[str, Any] = {}
    for pair in pairs:
        if "=" not in pair:
            err.print(f"[red]--set espera chave=valor, recebi {pair!r}[/]")
            raise typer.Exit(2)
        key, _, raw = pair.partition("=")
        edits[key] = _coerce(raw)
    return edits


def _coerce(raw: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


@app.command()
def inspect(
    token: str = typer.Argument(..., help="O JWT a auditar."),
    fmt: Format = typer.Option(Format.console, "--format", "-f", help="Formato de saída."),
    now: int | None = typer.Option(None, "--now", help="Epoch a usar como 'agora' (para testes)."),
    fail_on: FailOn = typer.Option(FailOn.high, "--fail-on", help="Severidade que faz sair com 1."),
) -> None:
    """Decodifica e roda todas as checagens passivas de segurança."""
    decoded = _decode_or_die(token)
    result = AuditResult(
        token=decoded, findings=run_all(decoded, now if now is not None else int(time.time()))
    )
    if fmt is Format.json:
        typer.echo(to_json(result))
    else:
        console_report.render(result)
    top = result.max_severity()
    raise typer.Exit(1 if top is not None and top.rank >= fail_on.rank() else 0)


@app.command()
def crack(
    token: str = typer.Argument(..., help="Um JWT assinado com HS256/384/512."),
    wordlist: Path | None = typer.Option(
        None, "--wordlist", "-w", help="Arquivo de candidatos (um por linha)."
    ),
    no_defaults: bool = typer.Option(
        False, "--no-defaults", help="Não testar a lista embutida de segredos fracos."
    ),
) -> None:
    """Testa se o segredo HMAC é fraco (ataque de dicionário)."""
    decoded = _decode_or_die(token)
    if decoded.alg not in {"HS256", "HS384", "HS512"}:
        err.print(
            f"[yellow]O token usa alg={decoded.alg!r}, não HMAC.[/] O crack por dicionário só se "
            "aplica a HS256/384/512. Para RS*/ES*/none use 'inspect' ou 'forge-confusion' — "
            "[bold]isto NÃO é evidência de segredo forte[/]."
        )
        raise typer.Exit(2)
    extra: list[str] = []
    if wordlist is not None:
        extra = [
            line.strip()
            for line in wordlist.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    found = crack_secret(decoded, extra) if no_defaults else crack_with_defaults(decoded, extra)
    if found is not None:
        err.print(f"[bold red]Segredo fraco encontrado:[/] [yellow]{found!r}[/]")
        err.print(
            "[dim]O token pode ser forjado. Troque por um segredo forte e aleatório (>= 256 bits).[/]"
        )
        raise typer.Exit(1)
    err.print("[green]Nenhum candidato funcionou.[/] (Isso não prova que o segredo é forte.)")
    raise typer.Exit(0)


@app.command("forge-confusion")
def forge_confusion(
    token: str = typer.Argument(..., help="Token de origem (tipicamente RS*/ES*)."),
    public_key: Path = typer.Option(
        ..., "--public-key", "-k", help="Chave pública PEM do servidor."
    ),
    alg: str = typer.Option("HS256", "--alg", help="Algoritmo HMAC para forjar."),
    set_claims: list[str] = typer.Option(
        [], "--set", help="Edita claims: --set sub=admin (repetível)."
    ),
) -> None:
    """Forja um token (RS→HS) usando a chave pública como segredo HMAC — PoC de confusão de algoritmo."""
    decoded = _decode_or_die(token)
    pem = public_key.read_bytes()
    forged = forge_rs_to_hs(decoded, pem, alg=alg, edits=_parse_set(set_claims))
    typer.echo(forged)
    err.print(
        "\n[dim]Teste este token contra o seu verificador. Se ele aceitar, o servidor está "
        "vulnerável à confusão de algoritmo — fixe o algoritmo esperado e separe as chaves.[/]"
    )


@app.command()
def forge(
    token: str = typer.Argument(..., help="Token de origem."),
    secret: str = typer.Option(..., "--secret", "-s", help="Segredo HMAC conhecido/quebrado."),
    alg: str = typer.Option("HS256", "--alg", help="Algoritmo HS*."),
    set_claims: list[str] = typer.Option(
        [], "--set", help="Edita claims: --set role=admin (repetível)."
    ),
) -> None:
    """Reassina um token modificado com um segredo conhecido (teste autorizado)."""
    decoded = _decode_or_die(token)
    header = {**decoded.header, "alg": alg}
    payload = {**decoded.payload, **_parse_set(set_claims)}
    typer.echo(encode_hmac(header, payload, secret.encode("utf-8")))


@app.command()
def rules() -> None:
    """Lista todas as checagens."""
    table = Table(title="Checagens do Chaveiro", header_style="bold")
    table.add_column("ID", no_wrap=True)
    table.add_column("Severidade", no_wrap=True)
    table.add_column("Título")
    table.add_column("OWASP / CWE", no_wrap=True)
    for meta in CATALOG.values():
        table.add_row(
            meta.id,
            meta.severity.value,
            meta.title,
            f"{(meta.owasp or '—').split(':')[0]} · {meta.cwe or '—'}",
        )
    Console().print(table)


def _force_utf8() -> None:
    """Evita UnicodeEncodeError no console legado do Windows (cp1252)."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(ValueError, OSError):
                reconfigure(encoding="utf-8", errors="replace")


def main() -> None:
    _force_utf8()
    app()
