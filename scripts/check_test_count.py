#!/usr/bin/env python3
"""Portão anti-deriva: o número de testes anunciado é GERADO, não digitado à mão.

Defeito de classe (auditoria cruzada 2026-09-12): o badge do README dizia "191 tests"
enquanto `pytest --collect-only` coletava 240 — um número escrito à mão que apodrece a
cada teste novo. Este portão reprova o build quando qualquer contagem declarada (o badge
SVG, a alt-text do badge e a prosa dos "Portões") diverge da coleta real do pytest.

Uso:
    python scripts/check_test_count.py

Sai com 0 se tudo bate; 1 na divergência (com a mensagem do que corrigir); 2 em erro de
ambiente (não conseguiu coletar, arquivo ausente).
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

_RAIZ = Path(__file__).resolve().parent.parent
_README = _RAIZ / "README.md"
_BADGE_SVG = _RAIZ / "assets" / "chip-tests.svg"

# "240 tests collected in 0.47s" — a última linha do --collect-only -q.
_COLETADOS = re.compile(r"(\d+)\s+tests?\s+collected")
# Fontes declaradas no repo, cada uma com o rótulo para a mensagem de erro.
_FONTES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("README badge (alt-text)", re.compile(r"(\d+)\s+tests?\s+passing", re.IGNORECASE)),
    ("README prosa dos Portões", re.compile(r"\*\*(\d+)\s+testes\*\*")),
    ("assets/chip-tests.svg", re.compile(r"(\d+)\s+TESTS\s+PASSING", re.IGNORECASE)),
)


def _coletar() -> int:
    """Conta os testes via `pytest --collect-only`, sem o addopts de cobertura."""
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-o", "addopts="],
        cwd=_RAIZ,
        capture_output=True,
        text=True,
        check=False,
    )
    achado = _COLETADOS.search(proc.stdout)
    if achado is None:
        sys.stderr.write(
            "não consegui ler a contagem de `pytest --collect-only`.\n"
            f"stdout final:\n{proc.stdout[-500:]}\n{proc.stderr[-500:]}\n"
        )
        raise SystemExit(2)
    return int(achado.group(1))


def _declarados() -> list[tuple[str, int]]:
    """Extrai cada contagem declarada nas fontes versionadas do repo."""
    if not _README.exists() or not _BADGE_SVG.exists():
        sys.stderr.write("README.md ou assets/chip-tests.svg ausente.\n")
        raise SystemExit(2)
    readme = _README.read_text(encoding="utf-8")
    svg = _BADGE_SVG.read_text(encoding="utf-8")
    textos = {
        "README badge (alt-text)": readme,
        "README prosa dos Portões": readme,
        "assets/chip-tests.svg": svg,
    }
    achados: list[tuple[str, int]] = []
    for rotulo, padrao in _FONTES:
        casado = padrao.search(textos[rotulo])
        if casado is None:
            sys.stderr.write(f"não achei a contagem de testes em: {rotulo}\n")
            raise SystemExit(2)
        achados.append((rotulo, int(casado.group(1))))
    return achados


def main() -> int:
    real = _coletar()
    divergentes = [(rotulo, n) for rotulo, n in _declarados() if n != real]
    if divergentes:
        sys.stderr.write(f"contagem de testes divergente — pytest coleta {real}:\n")
        for rotulo, n in divergentes:
            sys.stderr.write(f"  - {rotulo}: diz {n}, deveria dizer {real}\n")
        sys.stderr.write("atualize o badge/prosa (o número é GERADO, não digitado).\n")
        return 1
    print(f"contagem de testes OK: {real} em todas as fontes declaradas.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
