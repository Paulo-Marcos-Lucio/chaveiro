from __future__ import annotations

import pytest
from tests.conftest import hs_token

from chaveiro.core.jwt import (
    JWTError,
    b64url_decode,
    b64url_encode,
    decode,
    encode_hmac,
    verify_hmac,
)


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
