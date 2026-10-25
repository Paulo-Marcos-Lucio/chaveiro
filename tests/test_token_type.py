"""Testes do item CH-03a: ``checks/token_type.py`` — ``classify(token) -> TokenKind``."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from chaveiro.checks.token_type import TokenKind, classify
from chaveiro.core.jwt import decode
from tests.conftest import raw_token


def _classify(header: dict, payload: dict) -> TokenKind:
    return classify(decode(raw_token(header, payload)))


# -- os quatro casos literais do critério de aceite -------------------------- #


def test_typ_at_jwt_e_access_jwt() -> None:
    """RFC 9068 §2.1: `at+jwt` é o identificador reservado do perfil de Access Token."""
    assert _classify({"alg": "HS256", "typ": "at+jwt"}, {"sub": "u"}) == TokenKind.ACCESS_JWT


def test_nonce_e_id_token() -> None:
    """OIDC Core §2: `nonce` é claim de ID Token; Access Token nunca carrega."""
    assert _classify({"alg": "HS256", "typ": "JWT"}, {"nonce": "abc"}) == TokenKind.ID_TOKEN


def test_at_hash_e_id_token() -> None:
    assert _classify({"alg": "HS256", "typ": "JWT"}, {"at_hash": "xyz"}) == TokenKind.ID_TOKEN


def test_typ_logout_jwt_e_logout() -> None:
    """OIDC Back-Channel Logout 1.0 §2.4: `logout+jwt` identifica o Logout Token."""
    assert _classify({"alg": "HS256", "typ": "logout+jwt"}, {"sub": "u"}) == TokenKind.LOGOUT


def test_sem_typ_reconhecivel_e_generic() -> None:
    assert _classify({"alg": "HS256", "typ": "JWT"}, {"sub": "u"}) == TokenKind.GENERIC


def test_sem_header_typ_nenhum_e_generic() -> None:
    assert _classify({"alg": "HS256"}, {"sub": "u"}) == TokenKind.GENERIC


# -- typ reconhecido é insensível a maiúsculas e a espaço nas pontas -------- #


def test_typ_header_normaliza_case_e_espaco() -> None:
    assert _classify({"alg": "HS256", "typ": " AT+JWT "}, {"sub": "u"}) == TokenKind.ACCESS_JWT


# -- DPOP (RFC 9449) e REFRESH (heurística existente de detectors.py) ------- #


def test_typ_dpop_jwt_e_dpop() -> None:
    """RFC 9449 §4.2: `dpop+jwt` é EXIGIDO no header da prova DPoP."""
    assert _classify({"alg": "ES256", "typ": "dpop+jwt"}, {"htm": "GET"}) == TokenKind.DPOP


def test_typ_header_refresh_e_refresh() -> None:
    assert _classify({"alg": "HS256", "typ": "refresh"}, {"sub": "u"}) == TokenKind.REFRESH


def test_payload_type_refresh_e_refresh() -> None:
    """Flask-JWT-Extended emite a claim `type` (não o header `typ`)."""
    assert _classify({"alg": "HS256", "typ": "JWT"}, {"type": "refresh"}) == TokenKind.REFRESH


def test_payload_token_type_refresh_e_refresh() -> None:
    """djangorestframework-simplejwt emite a claim `token_type`."""
    assert _classify({"alg": "HS256", "typ": "JWT"}, {"token_type": "refresh"}) == TokenKind.REFRESH


def test_refresh_self_asserted_nao_vence_sinal_de_acesso() -> None:
    """`typ`/`type`/`token_type` é SELF-ASSERTED: um token com `scope` (sinal de
    access token) não vira REFRESH só por também carregar a claim — mesma
    nuance de `checks/detectors.py` (`e_refresh`), reaproveitada aqui."""
    resultado = _classify(
        {"alg": "HS256", "typ": "JWT"}, {"token_type": "refresh", "scope": "read write"}
    )
    assert resultado != TokenKind.REFRESH
    assert resultado == TokenKind.GENERIC


# -- precedência: typ reservado (header) vence claim de ID Token (payload) -- #


def test_typ_reservado_tem_precedencia_sobre_nonce() -> None:
    """Um `at+jwt` com `nonce` (incomum, mas não impossível) é classificado pelo
    header — o sinal mais forte, porque é o identificador de perfil assinado
    pelo emissor, não uma claim que pode coexistir por acidente."""
    resultado = _classify({"alg": "HS256", "typ": "at+jwt"}, {"nonce": "abc"})
    assert resultado == TokenKind.ACCESS_JWT


# -- round-trip do enum: toda saída de `classify` é um `TokenKind` válido --- #


@given(
    typ=st.one_of(st.none(), st.text(max_size=20)),
    payload_extra=st.dictionaries(
        st.sampled_from(["nonce", "at_hash", "type", "token_type", "scope", "scp", "azp", "sub"]),
        st.text(max_size=20),
        max_size=5,
    ),
)
def test_classify_sempre_devolve_um_tokenkind_e_nunca_lanca(
    typ: str | None, payload_extra: dict[str, str]
) -> None:
    """Invariante de classe: para qualquer combinação de `typ` e claims comuns,
    `classify` sempre devolve um `TokenKind` do enum — nunca levanta, nunca
    devolve algo fora do conjunto fechado (o que quebraria qualquer código que
    despache por `TokenKind`, ex.: o `_CLAIMS_POR_TIPO` do item seguinte)."""
    header = {"alg": "HS256"} if typ is None else {"alg": "HS256", "typ": typ}
    payload = {"sub": "u", **payload_extra}
    resultado = _classify(header, payload)
    assert isinstance(resultado, TokenKind)
    assert resultado in set(TokenKind)
