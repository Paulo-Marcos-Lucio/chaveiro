"""Interface de linha de comando do Chaveiro."""

from __future__ import annotations

import contextlib
import json
import sys
import time
from collections.abc import Iterator
from enum import Enum
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from chaveiro import __version__
from chaveiro.attacks.confusion import forge_rs_to_hs
from chaveiro.attacks.crack import crack as crack_secret
from chaveiro.attacks.crack import crack_with_defaults
from chaveiro.audit import audit_batch, audit_token, summarize
from chaveiro.checks.catalog import CATALOG, OWASP_EDITION
from chaveiro.core.jwt import JWTError, decode, encode_hmac
from chaveiro.core.models import DecodedToken, Severity
from chaveiro.report import console as console_report
from chaveiro.report.json_report import batch_to_json, to_json

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Chaveiro — audita a segurança de tokens JWT/JWS.",
)
err = Console(stderr=True)

_AVISO_AUTORIZACAO = (
    "⚠ Comando ofensivo. Use apenas em sistema que você possui ou tem autorização "
    "explícita e por escrito para testar. No Brasil, acesso não autorizado a dispositivo "
    "informático é crime (Lei 12.737/2012, agravada pela Lei 14.155/2021)."
)
# P1-02: token por argv vaza no histórico do shell e na lista de processos (ps/EDR).
_AVISO_ARGV = (
    "⚠ Token recebido por argumento — ele fica gravado no histórico do shell e "
    "visível na lista de processos (ps/EDR). Prefira o stdin: passe '-' e canalize "
    'o token, ex.: `echo "$TOKEN" | chaveiro inspect -`.'
)
# P1-01: aviso ao ligar --claims-completas (PII do titular sai em claro).
_AVISO_CLAIMS_COMPLETAS = (
    "⚠ --claims-completas: as claims saem em CLARO, incluindo PII do titular final "
    "(sub/email/cpf/nome). Você é o operador LGPD desse dado — use só se necessário "
    "e não deixe o laudo em claro em repositório ou canal compartilhado."
)


class Format(str, Enum):
    console = "console"
    json = "json"


class FailOn(str, Enum):
    none = "none"
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

    def rank(self) -> int:
        return 99 if self is FailOn.none else Severity(self.value).rank


def _aviso_autorizacao() -> None:
    err.print(f"[yellow]{_AVISO_AUTORIZACAO}[/]")


def _resolve_token(token: str) -> str:
    """Resolve o token do argumento ou do stdin ('-'), avisando sobre o argv.

    O caminho seguro (stdin) é silencioso; o inseguro (argv) sempre sinaliza o
    risco e o comando alternativo — o defeito P1-02 era justamente o argv ser o
    padrão sem qualquer aviso.
    """
    if token.strip() == "-":
        data = sys.stdin.read().strip()
        if not data:
            err.print("[red]Nenhum token recebido no stdin.[/]")
            raise typer.Exit(2)
        return data
    err.print(f"[yellow]{_AVISO_ARGV}[/]")
    return token


def _txt(value: object) -> Text:
    """Dado externo vira `Text` — o rich não interpreta `[...]` dentro de `Text`."""
    return Text(str(value))


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


def _decode_or_die(token: str) -> DecodedToken:
    try:
        return decode(token)
    except JWTError as exc:
        err.print("[red]Token inválido:[/]", _txt(exc))
        raise typer.Exit(2) from exc


def _parse_set(pairs: list[str]) -> dict[str, Any]:
    edits: dict[str, Any] = {}
    for pair in pairs:
        if "=" not in pair:
            err.print("[red]--set espera chave=valor, recebi[/]", _txt(repr(pair)))
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
    token: str = typer.Argument(..., help="O JWT a auditar; use '-' para ler do stdin."),
    fmt: Format = typer.Option(Format.console, "--format", "-f", help="Formato de saída."),
    now: int | None = typer.Option(None, "--now", help="Epoch a usar como 'agora' (para testes)."),
    fail_on: FailOn = typer.Option(FailOn.high, "--fail-on", help="Severidade que faz sair com 1."),
    claims_completas: bool = typer.Option(
        False,
        "--claims-completas",
        help="Mostra as claims em CLARO (PII do titular). Por padrão são redigidas.",
    ),
) -> None:
    """Decodifica e roda todas as checagens passivas de segurança."""
    token = _resolve_token(token)
    if claims_completas:
        err.print(f"[yellow]{_AVISO_CLAIMS_COMPLETAS}[/]")
    try:
        result = audit_token(token, now if now is not None else int(time.time()))
    except JWTError as exc:
        err.print("[red]Token inválido:[/]", _txt(exc))
        raise typer.Exit(2) from exc
    redact = not claims_completas
    if fmt is Format.json:
        typer.echo(to_json(result, redact=redact))
    else:
        console_report.render(result, redact=redact)
    top = result.max_severity()
    raise typer.Exit(1 if top is not None and top.rank >= fail_on.rank() else 0)


def _read_source(path: Path | None) -> str:
    if path is None or str(path) == "-":
        return sys.stdin.read()
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        err.print("[red]Não consegui ler o arquivo:[/]", _txt(exc))
        raise typer.Exit(2) from exc


@app.command()
def batch(
    path: Path | None = typer.Argument(
        None, help="Arquivo com um token por linha; '-' ou omitir lê do stdin."
    ),
    fmt: Format = typer.Option(Format.console, "--format", "-f", help="Formato de saída."),
    now: int | None = typer.Option(None, "--now", help="Epoch a usar como 'agora' (para testes)."),
    fail_on: FailOn = typer.Option(
        FailOn.high, "--fail-on", help="Pior severidade do lote que faz sair com 1."
    ),
    strict: bool = typer.Option(
        False, "--strict", help="Também falha (1) se alguma linha estiver malformada."
    ),
    claims_completas: bool = typer.Option(
        False,
        "--claims-completas",
        help="Mostra as claims em CLARO (PII do titular). Por padrão são redigidas.",
    ),
) -> None:
    """Audita vários tokens (um por linha) de um arquivo ou stdin.

    Ignora linhas em branco e comentários (#) e remove um prefixo 'Bearer '
    opcional. Reporta cada token e um resumo agregado.

    Código de saída: 1 se a pior severidade do lote atingir --fail-on (ou, com
    --strict, se houver linha malformada); 0 caso contrário. Linha malformada é
    ruído normal em token colhido de log, então por padrão ela vai para o stderr
    e não derruba o build. O 2 fica reservado a erro de uso (opção inválida,
    arquivo ilegível), como manda a convenção do Click.
    """
    text = _read_source(path)
    if claims_completas:
        err.print(f"[yellow]{_AVISO_CLAIMS_COMPLETAS}[/]")
    outcomes = audit_batch(text, now if now is not None else int(time.time()))
    if not outcomes:
        err.print("[yellow]Nenhum token encontrado na entrada.[/] (um token por linha)")
        raise typer.Exit(0)
    redact = not claims_completas
    if fmt is Format.json:
        typer.echo(batch_to_json(outcomes, redact=redact))
    else:
        console_report.render_batch(outcomes, redact=redact)
    summary = summarize(outcomes)
    if summary.errors:
        err.print(f"[yellow]{summary.errors} linha(s) malformada(s) ignorada(s).[/]")
    worst = summary.max_severity
    atingiu = worst is not None and worst.rank >= fail_on.rank()
    raise typer.Exit(1 if atingiu or (strict and summary.errors) else 0)


@app.command()
def crack(
    token: str = typer.Argument(
        ..., help="Um JWT assinado com HS256/384/512; use '-' para ler do stdin."
    ),
    wordlist: Path | None = typer.Option(
        None, "--wordlist", "-w", exists=True, help="Arquivo de candidatos (um por linha)."
    ),
    no_defaults: bool = typer.Option(
        False, "--no-defaults", help="Não testar a lista embutida de segredos fracos."
    ),
) -> None:
    """Testa se o segredo HMAC é fraco (ataque de dicionário)."""
    _aviso_autorizacao()
    token = _resolve_token(token)
    decoded = _decode_or_die(token)
    if decoded.alg not in {"HS256", "HS384", "HS512"}:
        err.print(
            "[yellow]O token não usa HMAC[/] (alg=",
            _txt(repr(decoded.alg)),
            "[yellow]). O crack por dicionário só se aplica a HS256/384/512. Para RS*/ES*/none "
            "use 'inspect' ou 'forge-confusion' — [bold]isto NÃO é evidência de segredo forte[/].",
            sep="",
        )
        raise typer.Exit(2)
    extra = _iter_wordlist(wordlist) if wordlist is not None else []
    found = crack_secret(decoded, extra) if no_defaults else crack_with_defaults(decoded, extra)
    if found is not None:
        err.print("[bold red]Segredo fraco encontrado:[/]", _txt(repr(found)), style="yellow")
        err.print(
            "[dim]O token pode ser forjado. Troque por um segredo forte e aleatório (>= 256 bits).[/]"
        )
        raise typer.Exit(1)
    err.print("[green]Nenhum candidato funcionou.[/] (Isso não prova que o segredo é forte.)")
    raise typer.Exit(0)


def _iter_wordlist(path: Path) -> Iterator[str]:
    """Gera candidatos linha a linha — memória O(1) e o 1º acerto encerra a leitura.

    Materializar a wordlist inteira (``read_text().splitlines()``) anulava o
    short-circuit do ``crack`` e, com uma lista grande (rockyou ~140 MB), gastava
    centenas de MB antes do primeiro palpite.
    """
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            candidate = line.strip()
            if candidate:
                yield candidate


@app.command("forge-confusion")
def forge_confusion(
    token: str = typer.Argument(
        ..., help="Token de origem (tipicamente RS*/ES*); use '-' para ler do stdin."
    ),
    public_key: Path = typer.Option(
        ..., "--public-key", "-k", help="Chave pública PEM do servidor."
    ),
    alg: str = typer.Option("HS256", "--alg", help="Algoritmo HMAC para forjar."),
    set_claims: list[str] = typer.Option(
        [], "--set", help="Edita claims: --set sub=admin (repetível)."
    ),
) -> None:
    """Forja um token (RS→HS) usando a chave pública como segredo HMAC — PoC de confusão de algoritmo."""
    _aviso_autorizacao()
    token = _resolve_token(token)
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
    token: str = typer.Argument(..., help="Token de origem; use '-' para ler do stdin."),
    secret: str = typer.Option(..., "--secret", "-s", help="Segredo HMAC conhecido/quebrado."),
    alg: str = typer.Option("HS256", "--alg", help="Algoritmo HS*."),
    set_claims: list[str] = typer.Option(
        [], "--set", help="Edita claims: --set role=admin (repetível)."
    ),
) -> None:
    """Reassina um token modificado com um segredo conhecido (teste autorizado)."""
    _aviso_autorizacao()
    token = _resolve_token(token)
    decoded = _decode_or_die(token)
    header = {**decoded.header, "alg": alg}
    payload = {**decoded.payload, **_parse_set(set_claims)}
    typer.echo(encode_hmac(header, payload, secret.encode("utf-8")))


@app.command("regras")
def regras() -> None:
    """Lista todas as checagens."""
    table = Table(title="Checagens do Chaveiro", header_style="bold")
    table.add_column("ID", no_wrap=True)
    table.add_column("Severidade", no_wrap=True)
    table.add_column("Título")
    table.add_column(f"OWASP {OWASP_EDITION} / CWE", no_wrap=True)
    for meta in CATALOG.values():
        table.add_row(
            meta.id,
            meta.severity.value,
            meta.title,
            f"{(meta.owasp or '—').split(':')[0]} · {meta.cwe or '—'}",
        )
    Console().print(table)


# Alias histórico: `rules` continua funcionando para não quebrar scripts.
app.command("rules", hidden=True)(regras)


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
