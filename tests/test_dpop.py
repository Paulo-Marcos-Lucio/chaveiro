"""Perfil DPoP (RFC 9449) — prova de posse e o `cnf.jkt` do token vinculado.

Chaveiro audita um token de cada vez, então o perfil se divide em dois papéis
que nunca aparecem no mesmo JWT em produção, mas que o auditor reconhece cada
um pela sua própria forma:

- a **prova** (`typ: dpop+jwt`) carrega `htm`/`htu`/`jti`/`iat`;
- o **token vinculado** (o access token, sem `typ` especial) carrega
  `cnf.jkt` — o thumbprint da chave que assinou a prova.

Os testes por exemplo cobrem os casos de cada checagem; a propriedade no fim
cobre a invariante da janela de frescor do `iat` para qualquer deslocamento,
não só o exemplo que apareceu primeiro.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from chaveiro.checks.detectors import _DPOP_IAT_MAX_AGE_S, run_all
from chaveiro.core.jwt import decode
from tests.conftest import raw_token

NOW = 1_800_000_000
_DPOP_HEADER = {"alg": "ES256", "typ": "dpop+jwt"}
_DPOP_PAYLOAD_OK = {
    "htm": "POST",
    "htu": "https://as.example.com/token",
    "jti": "9a8a-guid",
    "iat": NOW,
}


def _ids(header: dict, payload: dict, now: int = NOW) -> set[str]:
    """IDs do perfil DPoP disparados — filtra fora as checagens genéricas de
    claim (claim-no-exp/aud/iss...) que disparam em qualquer payload minimalista
    e não têm nada a ver com o que este arquivo testa."""
    all_ids = {f.check_id for f in run_all(decode(raw_token(header, payload)), now)}
    return {i for i in all_ids if i.startswith("dpop-")}


# --------------------------------------------------------------------------- #
# reconhecimento por 'typ' — só uma prova DPoP é auditada como prova
# --------------------------------------------------------------------------- #


def test_prova_conforme_nao_dispara_nada() -> None:
    assert _ids(_DPOP_HEADER, _DPOP_PAYLOAD_OK) == set()


def test_typ_dpop_case_insensitive_e_com_espaco() -> None:
    # RFC 7515 §4.1.9: 'typ' é dica, não normativa — mas um verificador
    # leniente aceita variação de caixa/espaço, então o auditor tem que
    # reconhecer a mesma forma que ele reconhece (mesma leniência já usada
    # para 'alg: none').
    for typ in ("DPoP+JWT", " dpop+jwt ", "Dpop+Jwt"):
        assert _ids({"alg": "ES256", "typ": typ}, _DPOP_PAYLOAD_OK) == set(), typ


def test_token_sem_typ_dpop_nao_e_auditado_como_prova() -> None:
    # Um JWT comum, sem 'typ: dpop+jwt', não deve ganhar achado de "prova sem
    # htm/htu/jti" só porque não tem esses campos — eles não fazem sentido
    # fora do papel de prova.
    assert _ids({"alg": "HS256"}, {"sub": "a"}) == set()


# --------------------------------------------------------------------------- #
# prova incompleta: cada campo ausente dispara o achado certo, isoladamente
# --------------------------------------------------------------------------- #


def test_falta_htm() -> None:
    payload = {k: v for k, v in _DPOP_PAYLOAD_OK.items() if k != "htm"}
    ids = _ids(_DPOP_HEADER, payload)
    assert "dpop-proof-missing-htm" in ids
    assert "dpop-proof-missing-htu" not in ids
    assert "dpop-proof-missing-jti" not in ids


def test_falta_htu() -> None:
    payload = {k: v for k, v in _DPOP_PAYLOAD_OK.items() if k != "htu"}
    assert _ids(_DPOP_HEADER, payload) == {"dpop-proof-missing-htu"}


def test_falta_jti() -> None:
    payload = {k: v for k, v in _DPOP_PAYLOAD_OK.items() if k != "jti"}
    assert _ids(_DPOP_HEADER, payload) == {"dpop-proof-missing-jti"}


def test_htm_vazio_conta_como_ausente() -> None:
    # Uma string vazia passaria por 'isinstance(str)' — o vazio não é campo.
    payload = {**_DPOP_PAYLOAD_OK, "htm": "  "}
    assert "dpop-proof-missing-htm" in _ids(_DPOP_HEADER, payload)


def test_falta_todos_os_campos_dispara_os_tres() -> None:
    ids = _ids(_DPOP_HEADER, {})
    assert {"dpop-proof-missing-htm", "dpop-proof-missing-htu", "dpop-proof-missing-jti"} <= ids
    assert "dpop-proof-stale-iat" in ids  # sem 'iat' também


# --------------------------------------------------------------------------- #
# janela de frescor do 'iat' — casos por exemplo (a propriedade fica no fim)
# --------------------------------------------------------------------------- #


def test_iat_ausente_dispara_stale() -> None:
    payload = {k: v for k, v in _DPOP_PAYLOAD_OK.items() if k != "iat"}
    assert "dpop-proof-stale-iat" in _ids(_DPOP_HEADER, payload)


def test_iat_muito_no_passado_dispara_stale() -> None:
    payload = {**_DPOP_PAYLOAD_OK, "iat": NOW - 10_000}
    assert "dpop-proof-stale-iat" in _ids(_DPOP_HEADER, payload)


def test_iat_no_futuro_tambem_dispara_stale() -> None:
    # Relógio adiantado do emissor não é menos suspeito que um velho — os dois
    # lados da janela contam.
    payload = {**_DPOP_PAYLOAD_OK, "iat": NOW + 10_000}
    assert "dpop-proof-stale-iat" in _ids(_DPOP_HEADER, payload)


def test_iat_dentro_da_janela_nao_dispara() -> None:
    payload = {**_DPOP_PAYLOAD_OK, "iat": NOW - (_DPOP_IAT_MAX_AGE_S - 1)}
    assert "dpop-proof-stale-iat" not in _ids(_DPOP_HEADER, payload)


# --------------------------------------------------------------------------- #
# cnf.jkt — o lado do token vinculado (access token), independente de 'typ'
# --------------------------------------------------------------------------- #


def test_cnf_jkt_bem_formado_nao_dispara() -> None:
    payload = {"sub": "user-1", "cnf": {"jkt": "x" * 43}}
    assert "dpop-cnf-jkt-malformed" not in _ids({"alg": "RS256"}, payload)


def test_cnf_jkt_curto_demais_dispara() -> None:
    payload = {"sub": "user-1", "cnf": {"jkt": "x" * 20}}
    assert "dpop-cnf-jkt-malformed" in _ids({"alg": "RS256"}, payload)


def test_cnf_jkt_caractere_fora_do_alfabeto_base64url_dispara() -> None:
    # '+' e '/' são base64 padrão, não base64url (RFC 7515 §2) — um thumbprint
    # nessa forma não é o que o RFC 7638 pede.
    payload = {"sub": "user-1", "cnf": {"jkt": "+" + "x" * 42}}
    assert "dpop-cnf-jkt-malformed" in _ids({"alg": "RS256"}, payload)


def test_cnf_sem_jkt_nao_dispara() -> None:
    # 'cnf' existe para outros mecanismos de prova de posse além de DPoP
    # (ex.: mTLS usa 'cnf.x5t#S256') — só 'jkt' é vocabulário DPoP.
    payload = {"sub": "user-1", "cnf": {"x5t#S256": "abc"}}
    assert "dpop-cnf-jkt-malformed" not in _ids({"alg": "RS256"}, payload)


def test_cnf_nao_e_objeto_nao_dispara() -> None:
    payload = {"sub": "user-1", "cnf": "nao-e-um-objeto"}
    assert "dpop-cnf-jkt-malformed" not in _ids({"alg": "RS256"}, payload)


def test_jkt_nao_string_dispara_malformado() -> None:
    payload = {"sub": "user-1", "cnf": {"jkt": 12345}}
    assert "dpop-cnf-jkt-malformed" in _ids({"alg": "RS256"}, payload)


def test_prova_dpop_pode_tambem_ser_o_token_vinculado() -> None:
    # Os dois papéis não são mutuamente exclusivos na FORMA do token, só no uso
    # real — o auditor aplica as duas checagens sem que uma desligue a outra.
    payload = {**_DPOP_PAYLOAD_OK, "cnf": {"jkt": "y" * 10}}
    ids = _ids(_DPOP_HEADER, payload)
    assert "dpop-cnf-jkt-malformed" in ids
    assert "dpop-proof-missing-htm" not in ids


# --------------------------------------------------------------------------- #
# INVARIANTE: a janela de frescor do 'iat' vale para qualquer deslocamento,
# não só os exemplos acima. Corrigir o exemplo e deixar `> _DPOP_IAT_MAX_AGE_S`
# virar `>=` (ou o sinal do abs() se perder num refactor futuro) sobrevive a
# um teste por exemplo isolado — não sobrevive a esta propriedade.
# --------------------------------------------------------------------------- #


@settings(max_examples=200)
@given(deslocamento=st.integers(min_value=-_DPOP_IAT_MAX_AGE_S, max_value=_DPOP_IAT_MAX_AGE_S))
def test_iat_dentro_da_janela_nunca_dispara_stale(deslocamento: int) -> None:
    payload = {**_DPOP_PAYLOAD_OK, "iat": NOW + deslocamento}
    assert "dpop-proof-stale-iat" not in _ids(_DPOP_HEADER, payload)


@settings(max_examples=200)
@given(
    deslocamento=st.integers(min_value=_DPOP_IAT_MAX_AGE_S + 1, max_value=_DPOP_IAT_MAX_AGE_S * 100)
    | st.integers(min_value=-_DPOP_IAT_MAX_AGE_S * 100, max_value=-_DPOP_IAT_MAX_AGE_S - 1)
)
def test_iat_fora_da_janela_sempre_dispara_stale(deslocamento: int) -> None:
    payload = {**_DPOP_PAYLOAD_OK, "iat": NOW + deslocamento}
    assert "dpop-proof-stale-iat" in _ids(_DPOP_HEADER, payload)
