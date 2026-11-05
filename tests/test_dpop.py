"""Testes de ``checks/dpop.py::validate_dpop`` (RFC 9449 — prova DPoP).

Uma prova DPoP não é um JWT comum: o cabeçalho carrega a chave PÚBLICA em
``jwk`` e o payload amarra método+URI+instante da requisição. Os casos por
exemplo cobrem cada checagem do catálogo; a propriedade final trava a
INVARIANTE central do item — nenhuma combinação de componente privado no
``jwk`` escapa de ``dpop-jwk-private``, e nenhum ``jwk`` puramente público o
dispara.
"""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from chaveiro.checks.dpop import DEFAULT_IAT_WINDOW_S, validate_dpop
from chaveiro.core.jwt import decode
from tests.conftest import raw_token

NOW = 1_800_000_000

_HEADER_OK: dict[str, Any] = {
    "typ": "dpop+jwt",
    "alg": "ES256",
    "jwk": {"kty": "EC", "crv": "P-256", "x": "eA", "y": "eQ"},
}
_PAYLOAD_OK: dict[str, Any] = {
    "jti": "abc123",
    "htm": "POST",
    "htu": "https://api.example/token",
    "iat": NOW,
}


def _dpop_ids(header: dict[str, Any], payload: dict[str, Any], now: int = NOW) -> set[str]:
    token = decode(raw_token(header, payload))
    return {f.check_id for f in validate_dpop(token, now)}


def test_prova_valida_nao_gera_nenhum_achado() -> None:
    """Caminho feliz: prova bem formada não dispara checagem nenhuma."""
    assert _dpop_ids(_HEADER_OK, _PAYLOAD_OK) == set()


# --------------------------------------------------------------------------- #
# Cobertura por ID dos casos explícitos do critério de aceite do item.
# --------------------------------------------------------------------------- #

_CASOS_POSITIVOS: list[tuple[str, dict[str, Any], dict[str, Any]]] = [
    ("dpop-typ-wrong", {**_HEADER_OK, "typ": "JWT"}, _PAYLOAD_OK),
    ("dpop-typ-wrong", {**_HEADER_OK, "typ": None}, _PAYLOAD_OK),
    ("dpop-alg-symmetric", {**_HEADER_OK, "alg": "HS256"}, _PAYLOAD_OK),
    ("dpop-alg-symmetric", {**_HEADER_OK, "alg": "none"}, _PAYLOAD_OK),
    ("dpop-alg-symmetric", {k: v for k, v in _HEADER_OK.items() if k != "alg"}, _PAYLOAD_OK),
    ("dpop-jwk-missing", {k: v for k, v in _HEADER_OK.items() if k != "jwk"}, _PAYLOAD_OK),
    ("dpop-jwk-missing", {**_HEADER_OK, "jwk": "não é objeto"}, _PAYLOAD_OK),
    (
        "dpop-jwk-private",
        {**_HEADER_OK, "jwk": {"kty": "EC", "crv": "P-256", "x": "eA", "y": "eQ", "d": "seg"}},
        _PAYLOAD_OK,
    ),
    (
        "dpop-jwk-private",
        {**_HEADER_OK, "jwk": {"kty": "RSA", "n": "..", "e": "AQAB", "p": "seg"}},
        _PAYLOAD_OK,
    ),
    ("dpop-no-jti", _HEADER_OK, {k: v for k, v in _PAYLOAD_OK.items() if k != "jti"}),
    ("dpop-no-htm", _HEADER_OK, {k: v for k, v in _PAYLOAD_OK.items() if k != "htm"}),
    ("dpop-no-htu", _HEADER_OK, {k: v for k, v in _PAYLOAD_OK.items() if k != "htu"}),
    ("dpop-no-iat", _HEADER_OK, {k: v for k, v in _PAYLOAD_OK.items() if k != "iat"}),
    ("dpop-htu-query", _HEADER_OK, {**_PAYLOAD_OK, "htu": "https://api.example/token?x=1"}),
    ("dpop-htu-query", _HEADER_OK, {**_PAYLOAD_OK, "htu": "https://api.example/token#frag"}),
    ("dpop-iat-window", _HEADER_OK, {**_PAYLOAD_OK, "iat": NOW - 3600}),
    ("dpop-iat-window", _HEADER_OK, {**_PAYLOAD_OK, "iat": NOW + 3600}),
]


@pytest.mark.parametrize("check_id,header,payload", _CASOS_POSITIVOS)
def test_caso_dispara_o_id_esperado(
    check_id: str, header: dict[str, Any], payload: dict[str, Any]
) -> None:
    assert check_id in _dpop_ids(header, payload)


def test_iat_na_borda_da_janela_nao_dispara() -> None:
    """Os extremos EXATOS da janela (+-window_s) ainda contam como dentro — só o que
    excede dispara. Fecha o off-by-one que uma comparação '<' em vez de '<=' causaria."""
    ids_passado = _dpop_ids(_HEADER_OK, {**_PAYLOAD_OK, "iat": NOW - DEFAULT_IAT_WINDOW_S})
    ids_futuro = _dpop_ids(_HEADER_OK, {**_PAYLOAD_OK, "iat": NOW + DEFAULT_IAT_WINDOW_S})
    assert "dpop-iat-window" not in ids_passado
    assert "dpop-iat-window" not in ids_futuro


def test_iat_booleano_nao_e_tratado_como_numero() -> None:
    """``bool`` é subclasse de ``int`` em Python — um 'iat': true não pode colar como 0/1."""
    assert "dpop-iat-window" not in _dpop_ids(_HEADER_OK, {**_PAYLOAD_OK, "iat": True})


def test_jwk_sem_componente_privada_nunca_dispara_mesmo_com_outros_achados() -> None:
    """Um jwk só-público não deve, por si, acusar 'dpop-jwk-private' — mesmo quando a
    prova tem outros problemas (alg simétrico) no mesmo cabeçalho."""
    header = {**_HEADER_OK, "alg": "HS256"}
    assert "dpop-jwk-private" not in _dpop_ids(header, _PAYLOAD_OK)


# --------------------------------------------------------------------------- #
# INVARIANTE (property-based): nenhuma combinação de componente privado no jwk
# escapa de dpop-jwk-private, e nenhum jwk puramente público o dispara.
# --------------------------------------------------------------------------- #

_CAMPOS_PRIVADOS = st.sampled_from(["d", "p", "q", "dp", "dq", "qi"])
_CAMPOS_PUBLICOS = {"kty": "RSA", "n": "modulo", "e": "AQAB", "alg": "RS256", "use": "sig"}


@given(privados=st.lists(_CAMPOS_PRIVADOS, min_size=1, max_size=6, unique=True))
def test_qualquer_componente_privado_dispara_dpop_jwk_private(privados: list[str]) -> None:
    jwk = {**_CAMPOS_PUBLICOS, **dict.fromkeys(privados, "segredo")}
    token = decode(raw_token({**_HEADER_OK, "jwk": jwk}, _PAYLOAD_OK))
    ids = {f.check_id for f in validate_dpop(token, NOW)}
    assert "dpop-jwk-private" in ids


@given(
    extra_publicos=st.dictionaries(
        st.sampled_from(["kid", "use", "alg", "crv", "x", "y"]), st.text(min_size=1, max_size=8)
    )
)
def test_jwk_so_com_campos_publicos_nunca_dispara_dpop_jwk_private(
    extra_publicos: dict[str, str],
) -> None:
    jwk = {**_CAMPOS_PUBLICOS, **extra_publicos}
    token = decode(raw_token({**_HEADER_OK, "jwk": jwk}, _PAYLOAD_OK))
    ids = {f.check_id for f in validate_dpop(token, NOW)}
    assert "dpop-jwk-private" not in ids
