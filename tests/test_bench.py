"""O corpus rotulado tem que sustentar o número publicado (P2-05).

O perfil dizia "22/22 vetores, medido" sem corpus público. Este teste É o corpus
executável: reconstrói os vetores, roda a auditoria e exige recall total nos
ataques e zero falso-positivo nos tokens legítimos. Se um detector regredir, o
número cai aqui — não num README que ninguém reproduz.
"""

from __future__ import annotations

import importlib.util
import os
import sys

_BENCH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bench")
if _BENCH not in sys.path:
    sys.path.insert(0, _BENCH)


def _load(nome: str) -> object:
    spec = importlib.util.spec_from_file_location(nome, os.path.join(_BENCH, f"{nome}.py"))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[nome] = module
    spec.loader.exec_module(module)
    return module


def test_corpus_tem_22_vetores_positivos_e_6_negativos() -> None:
    gerar = _load("gerar")
    assert len(gerar.positivos()) == 22  # type: ignore[attr-defined]
    assert len(gerar.negativos()) == 6  # type: ignore[attr-defined]


def test_recall_total_nos_ataques_e_zero_falso_positivo() -> None:
    avaliar = _load("avaliar")
    m = avaliar.medir()  # type: ignore[attr-defined]
    # Se algum vetor escapar, a mensagem lista qual — não um assert cego.
    assert m.tp == m.total_pos == 22, f"escaparam: {m.escaparam}"
    assert m.fp == 0, f"ruído em negativos: {m.ruidosos}"


def test_gerar_materializa_e_manifest_bate_com_o_corpus(tmp_path: object) -> None:
    import json

    gerar = _load("gerar")
    gerar.main()  # type: ignore[attr-defined]
    with open(os.path.join(_BENCH, "manifest.json"), encoding="utf-8") as fh:
        manifesto = json.load(fh)
    esperados_manifest = [p["esperado"] for p in manifesto["positivos"]]
    esperados_corpus = [p["esperado"] for p in gerar.positivos()]  # type: ignore[attr-defined]
    assert esperados_manifest == esperados_corpus
    emissores_manifest = [n["emissor"] for n in manifesto["negativos"]]
    emissores_corpus = [n["emissor"] for n in gerar.negativos()]  # type: ignore[attr-defined]
    assert emissores_manifest == emissores_corpus


def test_todo_negativo_tem_emissor_rotulado() -> None:
    """Trava a classe: um negativo novo sem 'emissor' não pode entrar no corpus.

    P2-05 publicava um total de FP sem quebra por emissor. A quebra só é
    honesta se TODO negativo carregar o rótulo — um esquecimento silencioso
    faria `fp_por_emissor` somar menos que `total_neg` sem avisar ninguém.
    """
    gerar = _load("gerar")
    negs = gerar.negativos()  # type: ignore[attr-defined]
    assert negs, "corpus de negativos vazio"
    for n in negs:
        assert n.get("emissor"), f"negativo sem emissor: {n['vetor']}"


def test_fp_por_emissor_soma_bate_com_o_total() -> None:
    """Invariante de contabilidade: a quebra por emissor não pode perder nem
    duplicar um caso do total agregado — para qualquer tamanho de corpus.
    """
    avaliar = _load("avaliar")
    m = avaliar.medir()  # type: ignore[attr-defined]
    soma_total = sum(c.total for c in m.fp_por_emissor.values())
    soma_fp = sum(c.fp for c in m.fp_por_emissor.values())
    assert soma_total == m.total_neg
    assert soma_fp == m.fp
