from __future__ import annotations

from chaveiro.checks.detectors import run_all
from chaveiro.core.jwt import decode
from chaveiro.core.models import Severity
from tests.conftest import hs_token, raw_token

NOW = 1_800_000_000


def _ids(token: str, now: int = NOW) -> set[str]:
    return {f.check_id for f in run_all(decode(token), now)}


def test_alg_none_is_critical() -> None:
    token = raw_token({"alg": "none", "typ": "JWT"}, {"sub": "admin"})
    findings = run_all(decode(token), NOW)
    assert any(f.check_id == "alg-none" and f.severity is Severity.CRITICAL for f in findings)


def test_missing_exp() -> None:
    token = hs_token({"sub": "a", "iat": NOW, "aud": "x", "iss": "y"})
    assert "claim-no-exp" in _ids(token)


def test_expired_token() -> None:
    token = hs_token({"exp": NOW - 10, "iat": NOW - 70, "aud": "x", "iss": "y"})
    assert "claim-expired" in _ids(token)


def test_long_lifetime() -> None:
    token = hs_token({"iat": NOW, "exp": NOW + 90 * 24 * 3600, "aud": "x", "iss": "y"})
    assert "claim-long-lifetime" in _ids(token)


def test_header_jku_and_kid_injection() -> None:
    token = raw_token(
        {"alg": "HS256", "jku": "http://evil/keys", "kid": "../../etc/passwd"},
        {"exp": NOW + 60, "iat": NOW, "aud": "x", "iss": "y"},
    )
    ids = _ids(token)
    assert "header-jku" in ids
    assert "header-kid-injection" in ids


def test_sensitive_payload() -> None:
    token = hs_token({"exp": NOW + 60, "iat": NOW, "aud": "x", "iss": "y", "password": "hunter2"})
    assert "payload-sensitive" in _ids(token)


def test_cpf_in_payload() -> None:
    token = hs_token({"exp": NOW + 60, "iat": NOW, "aud": "x", "iss": "y", "doc": "123.456.789-09"})
    assert "payload-sensitive" in _ids(token)


def test_hmac_advisory() -> None:
    token = hs_token({"exp": NOW + 60, "iat": NOW, "aud": "x", "iss": "y"})
    assert "alg-hmac-advisory" in _ids(token)


def test_cty_jwt_flags_nested() -> None:
    token = hs_token({"exp": NOW + 60, "iat": NOW, "aud": "x", "iss": "y"}, cty="JWT")
    assert "header-cty-nested" in _ids(token)


def test_cty_application_jwt_variation_flags_nested() -> None:
    # RFC 7515 §4.1.10: "application/" pode ser omitido e a comparação é case-insensitive.
    token = hs_token({"exp": NOW + 60, "iat": NOW, "aud": "x", "iss": "y"}, cty="application/jwt")
    assert "header-cty-nested" in _ids(token)


def test_nested_jwt_in_claim_flags() -> None:
    inner = hs_token({"exp": NOW + 60, "iat": NOW, "aud": "x", "iss": "y", "role": "admin"})
    outer = hs_token({"exp": NOW + 60, "iat": NOW, "aud": "x", "iss": "y", "assertion": inner})
    assert "payload-nested-jwt" in _ids(outer)


def test_normal_token_has_no_nesting_findings() -> None:
    # Negativo: sem 'cty' e sem claim parecida com JWT — nenhum sinal de aninhamento.
    token = hs_token({"exp": NOW + 60, "iat": NOW, "aud": "x", "iss": "y", "sub": "a.b.c"})
    ids = _ids(token)
    assert "header-cty-nested" not in ids
    assert "payload-nested-jwt" not in ids


def test_well_formed_rs_token_is_clean() -> None:
    token = raw_token(
        {"alg": "RS256", "typ": "JWT"},
        {"sub": "z", "exp": NOW + 60, "iat": NOW, "aud": "api", "iss": "auth"},
    )
    assert run_all(decode(token), NOW) == []
