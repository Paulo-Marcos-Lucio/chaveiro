"""Guarda de e-mail pessoal (Classe B — auditoria cruzada 2026-09-12).

Causa-raiz da classe: o e-mail PESSOAL do Paulo vazou, versionado e pushado, no
README client-facing do ``sentinela-pro``. O e-mail publico de contato e
``contatopml26@gmail.com``; o pessoal NUNCA pode aparecer em arquivo versionado
(regra de memoria ``reference-email-contato-clientes``). Sentinela e guardiao ja
tinham este portao; o Chaveiro nao — esta rodada fecha a lacuna nos quatro.

Invariante B: 0 ocorrencias do e-mail pessoal em arquivos rastreados, travado por
teste. Ataca a classe (qualquer arquivo), nao um README especifico.

A AGULHA e montada em pedacos (``"pml" + "sp" + ...``) de proposito: o literal
contiguo do e-mail pessoal NUNCA aparece no codigo-fonte deste teste, entao o
proprio portao nao gera um falso positivo contra si mesmo.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

_RAIZ = Path(__file__).resolve().parent.parent

# Montada em partes: o substring contiguo nao existe no fonte deste arquivo.
_AGULHA = "pml" + "sp" + "23" + "@" + "gmail.com"


def _arquivos_rastreados() -> list[str]:
    proc = subprocess.run(
        ["git", "-C", str(_RAIZ), "ls-files"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return []
    return [linha for linha in proc.stdout.splitlines() if linha]


def test_email_pessoal_nunca_em_arquivo_rastreado() -> None:
    arquivos = _arquivos_rastreados()
    if not arquivos:
        pytest.skip("fora de um checkout git — o portao real roda no CI")
    alvo = _AGULHA.encode("utf-8")
    culpados = []
    for rel in arquivos:
        caminho = _RAIZ / rel
        try:
            if alvo in caminho.read_bytes():
                culpados.append(rel)
        except OSError:
            continue
    assert not culpados, (
        f"e-mail PESSOAL versionado em: {culpados}. Use contatopml26@gmail.com "
        f"(regra reference-email-contato-clientes)."
    )


def test_a_agulha_esta_bem_montada() -> None:
    """Meta-teste: a agulha remonta o e-mail pessoal completo em runtime (senao o
    portao acima estaria procurando a string errada e passaria vazio)."""
    assert _AGULHA.endswith("@gmail.com")
    assert _AGULHA.startswith("pml")
    assert len(_AGULHA) == len("xxxxxxx@gmail.com")
