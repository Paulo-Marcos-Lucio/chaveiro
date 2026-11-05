"""Perfis de auditoria (CH-11b): a infraestrutura genérica que um item futuro
(CH-03b) vai usar para relaxar uma checagem só num emissor específico, sem
afetar a régua padrão de ninguém mais.

INVARIANTE DE CLASSE, nos dois sentidos:
  1. Sem perfil (``None``) o laudo é IDÊNTICO ao de antes deste módulo existir —
     nem a adição da infraestrutura pode mudar o caminho padrão.
  2. Dois perfis que DIFEREM em conteúdo produzem ``ruleset_hash`` DIFERENTES —
     senão um cliente que fixou o hash não percebe a troca de régua.
Revert→vermelho: um `if perfil` mal colocado em `_run_camada`/`run_all` quebra (1);
tirar `perfil` do blob hasheado em `ruleset_hash` quebra (2).
"""

from __future__ import annotations

from bench.gerar import negativos, positivos
from hypothesis import given, settings
from hypothesis import strategies as st

from chaveiro.checks.catalog import CATALOG
from chaveiro.checks.detectors import run_all
from chaveiro.checks.perfil import PERFIS, Perfil, registrar
from chaveiro.core.jwt import decode
from chaveiro.core.models import Finding, Severity
from chaveiro.report.provenance import ruleset_hash

NOW = 1_800_000_000
_CORPUS = [item["token"] for item in positivos()] + [item["token"] for item in negativos()]
_CHECK_IDS = sorted(CATALOG)


def _regra_extra_fixa(token: object, now: int) -> list[Finding]:
    return [
        Finding(
            check_id="alg-missing",
            title="x",
            severity=Severity.LOW,
            detail="achado da regra extra de teste",
            recommendation="x",
        )
    ]


def test_sem_perfil_e_identico_ao_comportamento_anterior_para_todo_o_corpus() -> None:
    """run_all(t, now) == run_all(t, now, perfil=None), para cada token do corpus
    rotulado (bench/gerar.py: 22 positivos + 6 negativos)."""
    assert _CORPUS, "corpus vazio invalidaria o teste sem provar nada"
    for raw in _CORPUS:
        token = decode(raw)
        assert run_all(token, NOW) == run_all(token, NOW, perfil=None)


def test_perfil_aplica_teto_de_severidade() -> None:
    token = decode(positivos()[0]["token"])  # vetor "alg:none" -> achado CRITICAL
    perfil = Perfil(nome="teste-teto", overrides_severidade={"alg-none": Severity.LOW})
    [achado] = [f for f in run_all(token, NOW, perfil) if f.check_id == "alg-none"]
    assert achado.severity is Severity.LOW


def test_teto_nunca_eleva_severidade() -> None:
    """overrides_severidade é um TETO, não um piso: mapear um check_id para uma
    severidade ACIMA da original não eleva o achado — um perfil tolera uma
    particularidade conhecida, não fabrica gravidade que a checagem base não viu."""
    # vetor "sem iat" dispara 'claim-no-iat', severidade LOW no catálogo.
    token = decode(next(p["token"] for p in positivos() if p["esperado"] == "claim-no-iat"))
    perfil = Perfil(
        nome="teste-teto-nao-eleva", overrides_severidade={"claim-no-iat": Severity.CRITICAL}
    )
    [achado] = [f for f in run_all(token, NOW, perfil) if f.check_id == "claim-no-iat"]
    assert achado.severity is Severity.LOW


def test_perfil_sem_overrides_nem_regras_extra_nao_muda_os_achados() -> None:
    token = decode(positivos()[0]["token"])
    perfil = Perfil(nome="vazio")
    assert run_all(token, NOW, perfil) == run_all(token, NOW)


def test_perfil_roda_regra_extra_em_cada_camada() -> None:
    perfil = Perfil(nome="teste-extra", regras_extra=(_regra_extra_fixa,))
    token = decode(positivos()[0]["token"])
    achados = run_all(token, NOW, perfil)
    extras = [f for f in achados if f.detail == "achado da regra extra de teste"]
    assert len(extras) == 1


def test_laudos_de_perfis_distintos_tem_ruleset_hash_distintos() -> None:
    base = ruleset_hash()
    a = ruleset_hash(Perfil(nome="a", overrides_severidade={"alg-none": Severity.LOW}))
    b = ruleset_hash(Perfil(nome="b", overrides_severidade={"alg-none": Severity.MEDIUM}))
    assert len({base, a, b}) == 3


def test_ruleset_hash_sem_perfil_e_igual_ao_de_antes_do_ch_11b() -> None:
    """Chamar ruleset_hash() sem argumento (toda a API existente antes deste item)
    continua devolvendo exatamente o hash de sempre — a introdução do parâmetro
    `perfil` com default None não pode virar uma mudança silenciosa de proveniência
    para quem nunca usou perfil."""
    assert ruleset_hash() == ruleset_hash(perfil=None)


@given(
    overrides=st.dictionaries(
        st.sampled_from(_CHECK_IDS), st.sampled_from(list(Severity)), min_size=1, max_size=5
    )
)
@settings(max_examples=50)
def test_qualquer_perfil_com_override_nao_vazio_muda_o_ruleset_hash(
    overrides: dict[str, Severity],
) -> None:
    """Invariante de classe (property-based): NENHUM override não-vazio pode deixar
    o hash igual ao padrão — senão um laudo medido com régua relaxada se disfarçaria
    de laudo medido com a régua padrão."""
    perfil = Perfil(nome="hipotese", overrides_severidade=overrides)
    assert ruleset_hash(perfil) != ruleset_hash()


def test_registrar_poe_o_perfil_no_catalogo_publico() -> None:
    perfil = Perfil(nome="teste-registrar-unico-9f3a")
    try:
        devolvido = registrar(perfil)
        assert devolvido is perfil
        assert PERFIS["teste-registrar-unico-9f3a"] is perfil
    finally:
        del PERFIS["teste-registrar-unico-9f3a"]
