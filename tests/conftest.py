"""Fixtures e helpers de teste."""

from __future__ import annotations

import json
import os

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from chaveiro.core.jwt import b64url_encode, encode_hmac

os.environ["COLUMNS"] = "200"


def raw_token(header: dict, payload: dict, signature: bytes = b"") -> str:
    """Monta um JWS compacto arbitrário (para tokens 'none' ou malformados)."""
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return f"{h}.{p}.{b64url_encode(signature)}"


def hs_token(
    payload: dict, secret: str = "secret", alg: str = "HS256", **header_extra: object
) -> str:
    header = {"alg": alg, "typ": "JWT", **header_extra}
    return encode_hmac(header, payload, secret.encode("utf-8"))


@pytest.fixture(scope="session")
def rsa_keys() -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    public_pem = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return private_pem, public_pem


def sign_rs256(payload: dict, private_pem: bytes) -> str:
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    key = load_pem_private_key(private_pem, password=None)
    assert isinstance(key, rsa.RSAPrivateKey)
    header = {"alg": "RS256", "typ": "JWT"}
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h}.{p}".encode("ascii")
    sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{b64url_encode(sig)}"
