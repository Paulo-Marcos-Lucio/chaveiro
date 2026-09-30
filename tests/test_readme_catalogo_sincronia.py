"""Meta-teste: a tabela de checagens do README não pode divergir do CATALOG.

Defeito que este teste tranca: o `CATALOG` em `checks/catalog.py` é a fonte
única de verdade dos metadados (severidade, OWASP, CWE) — mas a tabela do
README é texto solto, mantida à mão. Nada barra alguém de adicionar uma
checagem nova ao catálogo e esquecer a linha no README, ou de copiar um
OWASP/CWE errado ao digitar a tabela. Sem este teste, essa divergência só
aparece quando um cliente lê o README, compara com o achado que recebeu, e
desconfia do resto do laudo — o pior lugar para descobrir isso.

A invariante: toda checagem do CATALOG aparece na tabela do README, com o
mesmo símbolo de severidade e o mesmo código OWASP/CWE (quando o CATALOG tem
um). Isso vale para as 22 checagens de hoje e para qualquer checagem futura —
o teste é parametrizado sobre o CATALOG, não sobre uma lista fixa de ids.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from chaveiro.checks.catalog import CATALOG
from chaveiro.core.models import Severity

README = Path(__file__).resolve().parent.parent / "README.md"

# Convenção usada na tabela do README: um emoji por nível de severidade.
_EMOJI_POR_SEVERIDADE: dict[Severity, str] = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

_LINHA = re.compile(
    r"^\|(?P<checagem>[^|]+)\|(?P<risco>[^|]+)\|(?P<severidade>[^|]+)\|(?P<owasp>[^|]+)\|$"
)
_ID_ENTRE_CRASES = re.compile(r"`([a-z0-9-]+)`")
_OWASP_CODIGO = re.compile(r"\bA\d{2}\b")
_CWE_CODIGO = re.compile(r"CWE-\d+")


def _linhas_da_tabela_de_checagens() -> list[str]:
    """Extrai as linhas de dados da tabela sob '## 🔎 O que ele audita'."""
    texto = README.read_text(encoding="utf-8").splitlines()
    inicio = next(i for i, linha in enumerate(texto) if linha.startswith("| Checagem"))
    linhas = []
    # texto[inicio] é o cabeçalho, texto[inicio + 1] é o separador '| --- | ... |'
    for linha in texto[inicio + 2 :]:
        if not linha.startswith("|"):
            break
        linhas.append(linha)
    return linhas


def _tabela_do_readme() -> dict[str, dict[str, str | None]]:
    """Mapeia check_id -> {emoji, owasp, cwe} lidos da tabela do README.

    Uma linha pode listar várias checagens (`` `a` / `b` ``); a coluna de
    severidade então lista um emoji por checagem, na mesma ordem
    (`` 🟠/🟡 ``). Quando há um único emoji para várias checagens, ele vale
    para todas. A coluna OWASP/CWE é compartilhada por toda a linha.
    """
    dados: dict[str, dict[str, str | None]] = {}
    for linha in _linhas_da_tabela_de_checagens():
        m = _LINHA.match(linha)
        if not m:
            continue
        ids = _ID_ENTRE_CRASES.findall(m.group("checagem"))
        if not ids:
            continue
        emojis = [c for c in m.group("severidade") if c in _EMOJI_POR_SEVERIDADE.values()]
        owasp_cwe = m.group("owasp")
        owasp_m = _OWASP_CODIGO.search(owasp_cwe)
        cwe_m = _CWE_CODIGO.search(owasp_cwe)
        owasp = owasp_m.group(0) if owasp_m else None
        cwe = cwe_m.group(0) if cwe_m else None
        for idx, check_id in enumerate(ids):
            emoji = emojis[idx] if idx < len(emojis) else (emojis[0] if emojis else None)
            dados[check_id] = {"emoji": emoji, "owasp": owasp, "cwe": cwe}
    return dados


def test_tabela_do_readme_nao_referencia_checagem_inexistente() -> None:
    """Guarda contra o erro inverso: id digitado errado ou checagem removida do CATALOG."""
    ids_invalidos = sorted(set(_tabela_do_readme()) - set(CATALOG))
    assert not ids_invalidos, (
        f"a tabela do README cita checagens que não existem em CATALOG: {ids_invalidos}"
    )


@pytest.mark.parametrize("check_id", sorted(CATALOG))
def test_checagem_do_catalog_esta_na_tabela_com_severidade_e_owasp_cwe_coerentes(
    check_id: str,
) -> None:
    tabela = _tabela_do_readme()
    meta = CATALOG[check_id]

    assert check_id in tabela, (
        f"'{check_id}' existe em CATALOG mas não aparece na tabela de checagens do README.md "
        "(seção '## 🔎 O que ele audita')"
    )
    linha = tabela[check_id]

    emoji_esperado = _EMOJI_POR_SEVERIDADE[meta.severity]
    assert linha["emoji"] == emoji_esperado, (
        f"'{check_id}' é severidade {meta.severity.value!r} no CATALOG (emoji {emoji_esperado!r}), "
        f"mas a linha do README usa {linha['emoji']!r}"
    )

    if meta.owasp is not None:
        codigo_esperado = meta.owasp.split(":", 1)[0]
        assert linha["owasp"] == codigo_esperado, (
            f"'{check_id}' é {meta.owasp!r} no CATALOG, mas a coluna OWASP/CWE do README "
            f"traz {linha['owasp']!r}"
        )

    if meta.cwe is not None:
        assert linha["cwe"] == meta.cwe, (
            f"'{check_id}' é {meta.cwe!r} no CATALOG, mas a coluna OWASP/CWE do README "
            f"traz {linha['cwe']!r}"
        )
