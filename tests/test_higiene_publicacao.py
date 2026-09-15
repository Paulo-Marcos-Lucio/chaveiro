"""Higiene de publicacao (Classe A — auditoria cruzada 2026-09-12).

A rodada 1 reescreveu o bloco "Versao Pro" para o enquadramento honesto, mas
NENHUM teste travava a classe — e o proprio README EN ainda carregava os
absolutos em ingles. Este portao FALHA se qualquer README publico voltar a
afirmar, em ABSOLUTO, que "nao ha motor escondido / a engine e identica / nem
checagem que so nasce na versao paga", enquanto a branch ``pro/motor-chaveiro``
carrega deteccao exclusiva (``fapi``, ``jku_probe``, ``weak_hmac``, ``--profile``).

Invariante A: README publico (PT e EN) nunca afirma absolutismo de "engine
identica" enquanto o Pro tem deteccao exclusiva. Mutacao de validacao: inserir
uma das frases abaixo em qualquer README faz este teste FALHAR — se passasse,
seria decorativo.

O honesto e permitido (e desejado): "detecccao passiva completa e honesta para o
que se propoe" + "a edicao Pro ACRESCENTA codigo de confirmacao ativa que nao
esta aqui". O proibido e o ABSOLUTO que o codigo Pro desmente.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_RAIZ = Path(__file__).resolve().parent.parent

# Substrings absolutistas PROIBIDAS (case-insensitive), PT e EN. Cada uma e desmentida
# por um arquivo de deteccao/flag que so existe na branch Pro.
_FRASES_ABSOLUTISTAS_PROIBIDAS = (
    # --- PT ---
    "sem uma linha a mais",
    "não há motor",
    "nao ha motor",
    "não existe engine turbinada",
    "nao existe engine turbinada",
    "nem checagem que só nasce",
    "nem checagem que so nasce",
    "a mesma engine",
    "engine idêntica",
    "engine identica",
    "a engine pública é a mesma",
    "a engine publica e a mesma",
    "nenhuma capacidade escondida",
    # --- EN (o README.en.md tinha estes vivos ate esta rodada) ---
    "not a different engine",
    "the engine is the same",
    "engine is the same on both",
    "souped-up engine",
    "born only in the paid",
    "hidden technical feature",
    "no hidden engine",
    "same engine on both",
)

_READMES = ("README.md", "README.en.md")


@pytest.mark.parametrize("nome", _READMES)
def test_readme_publico_nao_afirma_absolutismo_de_engine_identica(nome: str) -> None:
    caminho = _RAIZ / nome
    assert caminho.exists(), f"{nome} ausente"
    texto = caminho.read_text(encoding="utf-8").lower()
    achadas = [f for f in _FRASES_ABSOLUTISTAS_PROIBIDAS if f.lower() in texto]
    assert not achadas, (
        f"{nome} afirma absolutismo de 'engine identica' contradito pelo motor Pro "
        f"(fapi/jku_probe/weak_hmac): {achadas}. Use o enquadramento honesto "
        f"(publico faz deteccao passiva completa; Pro ACRESCENTA confirmacao ativa)."
    )


def test_a_lista_de_frases_proibidas_realmente_pega() -> None:
    """Meta-teste anti-decorativo: uma frase proibida injetada num texto tem que ser
    detectada. Garante que o gate acima nao passa por acidente de matching."""
    texto = "bla bla A mesma engine bla".lower()
    assert any(f.lower() in texto for f in _FRASES_ABSOLUTISTAS_PROIBIDAS)
