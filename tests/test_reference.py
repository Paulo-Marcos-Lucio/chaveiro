from __future__ import annotations

import pytest
from tests.conftest import hs_token, raw_token, sign_rs256

from chaveiro.reference.secure_validation import InvalidToken, validate

NOW = 1_800_000_000
SECRET = b"a-strong-random-secret-value-01"


def _good_hs() -> str:
    return hs_token(
        {"sub": "a", "exp": NOW + 60, "iat": NOW, "aud": "api", "iss": "auth"},
        secret=SECRET.decode(),
    )


def test_accepts_valid_hs_token() -> None:
    payload = validate(
        _good_hs(), key=SECRET, algorithms=["HS256"], audience="api", issuer="auth", now=NOW
    )
    assert payload["sub"] == "a"


def test_rejects_alg_none() -> None:
    token = raw_token({"alg": "none"}, {"sub": "admin"})
    with pytest.raises(InvalidToken):
        validate(token, key=SECRET, algorithms=["HS256"], now=NOW)


def test_rejects_none_in_allowlist() -> None:
    with pytest.raises(InvalidToken):
        validate(_good_hs(), key=SECRET, algorithms=["none"], now=NOW)


def test_rejects_expired() -> None:
    token = hs_token({"exp": NOW - 1, "iat": NOW - 60}, secret=SECRET.decode())
    with pytest.raises(InvalidToken):
        validate(token, key=SECRET, algorithms=["HS256"], now=NOW)


def test_rejects_wrong_audience() -> None:
    with pytest.raises(InvalidToken):
        validate(_good_hs(), key=SECRET, algorithms=["HS256"], audience="outra", now=NOW)


def test_rejects_tampered_signature() -> None:
    token = _good_hs()
    tampered = token[:-2] + ("aa" if not token.endswith("aa") else "bb")
    with pytest.raises(InvalidToken):
        validate(tampered, key=SECRET, algorithms=["HS256"], now=NOW)


def test_accepts_valid_rs256(rsa_keys: tuple[bytes, bytes]) -> None:
    private_pem, public_pem = rsa_keys
    token = sign_rs256({"sub": "z", "exp": NOW + 60, "iat": NOW}, private_pem)
    payload = validate(token, key=public_pem, algorithms=["RS256"], now=NOW)
    assert payload["sub"] == "z"


def test_rs256_confusion_is_rejected_by_reference(rsa_keys: tuple[bytes, bytes]) -> None:
    # o ataque de confusão é barrado quando a allowlist é só RS256
    from chaveiro.attacks.confusion import forge_rs_to_hs
    from chaveiro.core.jwt import decode

    private_pem, public_pem = rsa_keys
    original = decode(sign_rs256({"sub": "z", "exp": NOW + 60, "iat": NOW}, private_pem))
    forged = forge_rs_to_hs(original, public_pem, edits={"sub": "admin"})
    with pytest.raises(InvalidToken):
        validate(forged, key=public_pem, algorithms=["RS256"], now=NOW)
