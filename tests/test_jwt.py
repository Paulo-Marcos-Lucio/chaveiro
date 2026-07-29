from __future__ import annotations

import pytest

from chaveiro.core.jwt import (
    JWTError,
    b64url_decode,
    b64url_encode,
    decode,
    encode_hmac,
    verify_asymmetric,
    verify_hmac,
)
from tests.conftest import hs_token, sign_eddsa, sign_ps256


def test_b64url_roundtrip() -> None:
    for data in (b"", b"a", b"ab", b"abc", b"\x00\xff\x10hello"):
        assert b64url_decode(b64url_encode(data)) == data


def test_b64url_has_no_padding() -> None:
    assert "=" not in b64url_encode(b"abcabc")


def test_decode_parts() -> None:
    token = hs_token({"sub": "alice", "role": "user"}, secret="k")
    decoded = decode(token)
    assert decoded.alg == "HS256"
    assert decoded.payload["sub"] == "alice"
    assert decoded.header["typ"] == "JWT"


def test_encode_then_verify() -> None:
    token = encode_hmac({"alg": "HS256"}, {"sub": "x"}, b"topsecret")
    decoded = decode(token)
    assert verify_hmac(decoded, b"topsecret")
    assert not verify_hmac(decoded, b"wrong")


def test_decode_rejects_malformed() -> None:
    with pytest.raises(JWTError):
        decode("only.two")
    with pytest.raises(JWTError):
        decode("not-a-jwt")


def _raw(header_bytes: bytes, payload_bytes: bytes) -> str:
    return f"{b64url_encode(header_bytes)}.{b64url_encode(payload_bytes)}.{b64url_encode(b'sig')}"


def test_header_array_raises_jwterror_not_attributeerror() -> None:
    # Header que é array JSON: sem o guard, viraria AttributeError na cara do
    # usuário quando o detector faz header.get(...). Tem que ser JWTError tratado.
    with pytest.raises(JWTError):
        decode(_raw(b"[1,2,3]", b'{"sub":"a"}'))


def test_payload_object_or_nested_but_not_array() -> None:
    # Payload array não é objeto JSON nem JWS compacto -> JWTError, nunca traceback.
    with pytest.raises(JWTError):
        decode(_raw(b'{"alg":"HS256"}', b"[1,2,3]"))


def test_b64url_strict_rejects_out_of_alphabet() -> None:
    # RFC 7515 §2: alfabeto estrito. urlsafe_b64decode descartaria '!!!' em
    # silêncio; um auditor tolerante lauda um token que verificador nenhum aceita.
    good = _raw(b'{"alg":"HS256"}', b'{"sub":"a"}')
    header_b64 = good.split(".")[0]
    poisoned = header_b64[:4] + "!!!" + header_b64[4:] + "." + good.split(".", 1)[1]
    with pytest.raises(JWTError):
        decode(poisoned)


def test_b64url_strict_rejects_standard_base64_plus_slash() -> None:
    with pytest.raises(JWTError):
        b64url_decode("ab+/cd")


def test_b64url_strict_rejects_whitespace() -> None:
    with pytest.raises(JWTError):
        b64url_decode("ab cd")


def test_decode_deeply_nested_payload_is_bounded() -> None:
    # Teto de aninhamento: protege decode, render e json.dumps de RecursionError.
    deep = ('{"a":' * 200 + "1" + "}" * 200).encode()
    with pytest.raises(JWTError):
        decode(_raw(b'{"alg":"HS256"}', deep))


def test_decode_real_nested_jwt() -> None:
    # JWT aninhado REAL (RFC 7519 §5.2): payload da casca É outro JWS compacto.
    inner = encode_hmac({"alg": "HS256", "typ": "JWT"}, {"sub": "admin"}, b"k")
    outer = _raw(b'{"alg":"HS256","cty":"JWT"}', inner.encode("ascii"))
    decoded = decode(outer)
    assert decoded.nested == inner
    assert decoded.payload == {}  # a casca não tem claims próprias


def test_verify_asymmetric_ps256_roundtrip(rsa_keys: tuple[bytes, bytes]) -> None:
    private_pem, public_pem = rsa_keys
    token = sign_ps256({"sub": "x"}, private_pem)
    assert verify_asymmetric(decode(token), public_pem)
    # assinatura adulterada não passa
    bad = decode(token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB"))
    assert not verify_asymmetric(bad, public_pem)


def test_verify_asymmetric_eddsa_roundtrip(ed25519_keys: tuple[bytes, bytes]) -> None:
    private_pem, public_pem = ed25519_keys
    decoded = decode(sign_eddsa({"sub": "x"}, private_pem))
    assert verify_asymmetric(decoded, public_pem)


def test_verify_asymmetric_eddsa_rejects_tampered(ed25519_keys: tuple[bytes, bytes]) -> None:
    private_pem, public_pem = ed25519_keys
    token = sign_eddsa({"sub": "x"}, private_pem)
    tampered = decode(token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB"))
    assert not verify_asymmetric(tampered, public_pem)


def test_verify_asymmetric_alg_key_mismatch_is_false(ed25519_keys: tuple[bytes, bytes]) -> None:
    # token EdDSA verificado contra chave RSA (mismatch alg/chave) -> False, sem exceção
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    ed_priv, _ = ed25519_keys
    decoded = decode(sign_eddsa({"sub": "x"}, ed_priv))
    rsa_pub = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    assert not verify_asymmetric(decoded, rsa_pub)
