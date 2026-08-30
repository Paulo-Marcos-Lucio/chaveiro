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
