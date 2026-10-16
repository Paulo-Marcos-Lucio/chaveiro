"""Testes de ``checks/dpop.py`` — binding prova↔access token (CH-12b).

``validate_dpop`` (CH-12a) audita a prova isolada; esta checagem adicional
confirma que a prova foi feita PARA o access token em questão: ``ath``
(hash do access token) e ``cnf.jkt`` (thumbprint RFC 7638 da chave pública da
prova, carimbado no access token). Sem essas duas, uma prova DPoP capturada
serve para qualquer access token do mesmo cliente.
"""

from __future__ import annotations

from typing import Any

from chaveiro.checks.dpop import compute_ath, jwk_thumbprint, validate_dpop_binding
from chaveiro.core.jwt import decode
from tests.conftest import hs_token, raw_token

NOW = 1_800_000_000

# Vetor oficial — RFC 7638 §3.1 (Apêndice A).
_RFC7638_JWK: dict[str, Any] = {
    "kty": "RSA",
    "n": (
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_"
        "BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_"
        "FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI"
        "4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
    ),
    "e": "AQAB",
    "alg": "RS256",
    "kid": "2011-04-29",
}
_RFC7638_THUMBPRINT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

_HEADER_OK: dict[str, Any] = {"typ": "dpop+jwt", "alg": "ES256", "jwk": {"kty": "EC"}}


def _proof(payload: dict[str, Any], jwk: dict[str, Any] | None = None) -> Any:
    header = {**_HEADER_OK, "jwk": jwk} if jwk is not None else _HEADER_OK
    return decode(raw_token(header, payload))


# --------------------------------------------------------------------------- #
# jwk_thumbprint — RFC 7638
# --------------------------------------------------------------------------- #


def test_thumbprint_bate_com_vetor_oficial_do_rfc_7638() -> None:
    assert jwk_thumbprint(_RFC7638_JWK) == _RFC7638_THUMBPRINT


def test_thumbprint_e_estavel_a_ordem_dos_campos_no_dict() -> None:
    """RFC 7638 exige ordenação lexicográfica dos membros — não a ordem de inserção."""
    invertido = {
        "kid": "x",
        "e": _RFC7638_JWK["e"],
        "alg": "RS256",
        "n": _RFC7638_JWK["n"],
        "kty": "RSA",
    }
    assert jwk_thumbprint(invertido) == _RFC7638_THUMBPRINT


def test_thumbprint_kty_desconhecido_retorna_none() -> None:
    assert jwk_thumbprint({"kty": "XYZ", "x": "a"}) is None


def test_thumbprint_sem_kty_retorna_none() -> None:
    assert jwk_thumbprint({"n": "a", "e": "b"}) is None


def test_thumbprint_membro_obrigatorio_faltante_retorna_none() -> None:
    assert jwk_thumbprint({"kty": "RSA", "n": "a"}) is None  # falta 'e'


def test_thumbprint_ec_e_oct_tambem_calculam() -> None:
    ec = jwk_thumbprint({"kty": "EC", "crv": "P-256", "x": "eA", "y": "eQ"})
    oct_ = jwk_thumbprint({"kty": "oct", "k": "c2VncmVkbw"})
    assert isinstance(ec, str) and ec
    assert isinstance(oct_, str) and oct_
    assert ec != oct_


# --------------------------------------------------------------------------- #
# compute_ath
# --------------------------------------------------------------------------- #


def test_compute_ath_e_deterministico_e_sensivel_ao_token() -> None:
    a = compute_ath("token-1")
    b = compute_ath("token-1")
    c = compute_ath("token-2")
    assert a == b
    assert a != c


# --------------------------------------------------------------------------- #
# validate_dpop_binding — 'ath'
# --------------------------------------------------------------------------- #


def test_ath_ausente_gera_dpop_ath_missing() -> None:
    proof = _proof({"htm": "GET"})
    ids = {f.check_id for f in validate_dpop_binding(proof, "access-token-xyz")}
    assert "dpop-ath-missing" in ids


def test_ath_correto_nao_gera_mismatch() -> None:
    at = "access-token-xyz"
    proof = _proof({"ath": compute_ath(at)})
    ids = {f.check_id for f in validate_dpop_binding(proof, at)}
    assert "dpop-ath-missing" not in ids
    assert "dpop-ath-mismatch" not in ids


def test_ath_divergente_gera_dpop_ath_mismatch() -> None:
    proof = _proof({"ath": compute_ath("outro-token")})
    ids = {f.check_id for f in validate_dpop_binding(proof, "access-token-xyz")}
    assert "dpop-ath-mismatch" in ids


# --------------------------------------------------------------------------- #
# validate_dpop_binding — 'cnf.jkt'
# --------------------------------------------------------------------------- #


def test_access_token_opaco_gera_dpop_access_token_opaque() -> None:
    proof = _proof({"ath": compute_ath("opaco-123")})
    ids = {f.check_id for f in validate_dpop_binding(proof, "opaco-123")}
    assert "dpop-access-token-opaque" in ids


def test_access_token_jwt_sem_cnf_gera_dpop_cnf_missing() -> None:
    at = hs_token({"sub": "cliente"}, secret="s")
    proof = _proof({"ath": compute_ath(at)})
    ids = {f.check_id for f in validate_dpop_binding(proof, at)}
    assert "dpop-cnf-missing" in ids


def test_cnf_sem_jkt_gera_dpop_jkt_missing() -> None:
    at = hs_token({"sub": "cliente", "cnf": {}}, secret="s")
    proof = _proof({"ath": compute_ath(at)})
    ids = {f.check_id for f in validate_dpop_binding(proof, at)}
    assert "dpop-jkt-missing" in ids


def test_jkt_correto_nao_gera_nenhum_achado_de_binding() -> None:
    jwk = {"kty": "EC", "crv": "P-256", "x": "eA", "y": "eQ"}
    thumbprint = jwk_thumbprint(jwk)
    at = hs_token({"sub": "cliente", "cnf": {"jkt": thumbprint}}, secret="s")
    proof = _proof({"ath": compute_ath(at)}, jwk=jwk)
    assert validate_dpop_binding(proof, at) == []


def test_jkt_divergente_gera_dpop_jkt_mismatch() -> None:
    jwk = {"kty": "EC", "crv": "P-256", "x": "eA", "y": "eQ"}
    at = hs_token({"sub": "cliente", "cnf": {"jkt": "thumbprint-errado"}}, secret="s")
    proof = _proof({"ath": compute_ath(at)}, jwk=jwk)
    ids = {f.check_id for f in validate_dpop_binding(proof, at)}
    assert "dpop-jkt-mismatch" in ids


def test_jwk_com_kty_nao_suportado_gera_dpop_jkt_unsupported_kty() -> None:
    at = hs_token({"sub": "cliente", "cnf": {"jkt": "qualquer"}}, secret="s")
    proof = _proof({"ath": compute_ath(at)}, jwk={"kty": "XYZ"})
    ids = {f.check_id for f in validate_dpop_binding(proof, at)}
    assert "dpop-jkt-unsupported-kty" in ids
