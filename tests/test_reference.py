from __future__ import annotations

import json

import pytest

from chaveiro.core.jwt import b64url_encode, sign_hmac
from chaveiro.reference.secure_validation import InvalidToken, validate
from tests.conftest import hs_token, raw_token, sign_eddsa, sign_ps256, sign_rs256

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


def test_rejects_exp_as_string_fail_closed() -> None:
    # RFC 7519 §2: NumericDate é numérico. exp="9999999999" (string) NÃO pode ser
    # tratado como ausente — senão o token com exp em string nunca expira.
    token = hs_token({"exp": "9999999999", "iat": NOW}, secret=SECRET.decode())
    with pytest.raises(InvalidToken):
        validate(token, key=SECRET, algorithms=["HS256"], now=NOW)


def test_rejects_nbf_as_string_fail_closed() -> None:
    token = hs_token({"nbf": "9999999999", "exp": NOW + 60}, secret=SECRET.decode())
    with pytest.raises(InvalidToken):
        validate(token, key=SECRET, algorithms=["HS256"], now=NOW)


def test_rejects_exp_infinity() -> None:
    # json.dumps/loads aceitam o literal Infinity; com ele toda comparação
    # temporal daria False e o token nunca expiraria. Fail-closed.
    signed = hs_token({"exp": float("inf"), "iat": NOW}, secret=SECRET.decode())
    with pytest.raises(InvalidToken):
        validate(signed, key=SECRET, algorithms=["HS256"], now=NOW)


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


def test_accepts_valid_ps256(rsa_keys: tuple[bytes, bytes]) -> None:
    private_pem, public_pem = rsa_keys
    token = sign_ps256({"sub": "ps", "exp": NOW + 60, "iat": NOW}, private_pem)
    payload = validate(token, key=public_pem, algorithms=["PS256"], now=NOW)
    assert payload["sub"] == "ps"


def test_rejects_tampered_ps256(rsa_keys: tuple[bytes, bytes]) -> None:
    private_pem, public_pem = rsa_keys
    token = sign_ps256({"sub": "ps", "exp": NOW + 60, "iat": NOW}, private_pem)
    tampered = token[:-3] + ("aaa" if not token.endswith("aaa") else "bbb")
    with pytest.raises(InvalidToken):
        validate(tampered, key=public_pem, algorithms=["PS256"], now=NOW)


def test_accepts_valid_eddsa(ed25519_keys: tuple[bytes, bytes]) -> None:
    private_pem, public_pem = ed25519_keys
    token = sign_eddsa({"sub": "ed", "exp": NOW + 60, "iat": NOW}, private_pem)
    payload = validate(token, key=public_pem, algorithms=["EdDSA"], now=NOW)
    assert payload["sub"] == "ed"


def test_rejects_tampered_eddsa(ed25519_keys: tuple[bytes, bytes]) -> None:
    private_pem, public_pem = ed25519_keys
    token = sign_eddsa({"sub": "ed", "exp": NOW + 60, "iat": NOW}, private_pem)
    tampered = token[:-3] + ("aaa" if not token.endswith("aaa") else "bbb")
    with pytest.raises(InvalidToken):
        validate(tampered, key=public_pem, algorithms=["EdDSA"], now=NOW)


def test_eddsa_rejected_by_wrong_public_key(ed25519_keys: tuple[bytes, bytes]) -> None:
    # assinatura Ed25519 válida, mas verificada com outra chave pública -> rejeita
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    private_pem, _ = ed25519_keys
    other_pub = (
        ed25519.Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    token = sign_eddsa({"sub": "ed", "exp": NOW + 60, "iat": NOW}, private_pem)
    with pytest.raises(InvalidToken):
        validate(token, key=other_pub, algorithms=["EdDSA"], now=NOW)


def test_eddsa_not_in_allowlist_is_rejected(ed25519_keys: tuple[bytes, bytes]) -> None:
    # token EdDSA legítimo, mas allowlist só permite RS256 -> fora da allowlist
    private_pem, public_pem = ed25519_keys
    token = sign_eddsa({"sub": "ed", "exp": NOW + 60, "iat": NOW}, private_pem)
    with pytest.raises(InvalidToken):
        validate(token, key=public_pem, algorithms=["RS256"], now=NOW)


def test_valida_typ() -> None:
    # P2-04: quando o chamador exige um 'typ', a referência tem que conferi-lo —
    # antes ela ignorava o cabeçalho e aceitava qualquer 'typ' em silêncio.
    at_jwt = hs_token({"exp": NOW + 60}, secret=SECRET.decode(), typ="at+jwt")
    # typ conferido e igual: aceita
    assert validate(at_jwt, key=SECRET, algorithms=["HS256"], now=NOW, typ="at+jwt")
    # typ conferido e diferente do declarado: rejeita explicitamente
    with pytest.raises(InvalidToken):
        validate(at_jwt, key=SECRET, algorithms=["HS256"], now=NOW, typ="JWT")
    # typ exigido mas ausente no token: rejeita (não trata ausência como ok)
    header = b64url_encode(json.dumps({"alg": "HS256"}).encode())
    payload = b64url_encode(json.dumps({"exp": NOW + 60}).encode())
    sig = sign_hmac(f"{header}.{payload}".encode("ascii"), SECRET, "HS256")
    sem_typ = f"{header}.{payload}.{b64url_encode(sig)}"
    with pytest.raises(InvalidToken):
        validate(sem_typ, key=SECRET, algorithms=["HS256"], now=NOW, typ="JWT")


def test_jwt_aninhado_falha_explicitamente() -> None:
    # P2-04: para um JWT aninhado (cty:JWT, payload = outro JWS) a referência
    # devolvia {} em silêncio — fail-open que trata "casca sem claims" como token
    # válido de payload vazio. Agora tem que falhar ALTO.
    inner = hs_token({"sub": "a", "exp": NOW + 60}, secret="k")
    header = b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT", "cty": "JWT"}).encode())
    payload = b64url_encode(inner.encode())
    sig = sign_hmac(f"{header}.{payload}".encode("ascii"), SECRET, "HS256")
    outer = f"{header}.{payload}.{b64url_encode(sig)}"
    with pytest.raises(InvalidToken):
        validate(outer, key=SECRET, algorithms=["HS256"], now=NOW)
