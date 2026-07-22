"""Testes de regressão dos bugs achados na revisão adversarial."""

from __future__ import annotations

import io
import json

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from rich.console import Console

from chaveiro.checks.detectors import run_all
from chaveiro.core.jwt import JWTError, b64url_encode, decode
from chaveiro.core.models import AuditResult
from chaveiro.reference.secure_validation import validate
from chaveiro.report.console import render

NOW = 1_800_000_000


def _sign_es256(payload: dict, private_key: ec.EllipticCurvePrivateKey) -> str:
    header = {"alg": "ES256", "typ": "JWT"}
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h}.{p}".encode("ascii")
    der = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    n = (private_key.curve.key_size + 7) // 8
    raw = r.to_bytes(n, "big") + s.to_bytes(n, "big")  # assinatura JOSE (R||S)
    return f"{h}.{p}.{b64url_encode(raw)}"


# HIGH — ES256/384/512 rejeitava TODOS os tokens válidos (R||S vs DER).
def test_es256_valid_token_is_accepted() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    pub = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    token = _sign_es256({"sub": "z", "exp": NOW + 60, "iat": NOW}, key)
    payload = validate(token, key=pub, algorithms=["ES256"], now=NOW)
    assert payload["sub"] == "z"


# MEDIUM — payload não-UTF-8 gerava UnicodeDecodeError cru.
def test_non_utf8_payload_raises_jwterror() -> None:
    header = b64url_encode(json.dumps({"alg": "HS256"}).encode("utf-8"))
    bad = b64url_encode(b"\x80\x81\x82\x83")  # bytes inválidos como UTF-8/JSON
    with pytest.raises(JWTError):
        decode(f"{header}.{bad}.AAAA")


# MEDIUM — Infinity/NaN em exp derrubava a auditoria (int(inf) crash).
def test_infinity_exp_does_not_crash_audit() -> None:
    header = b64url_encode(json.dumps({"alg": "HS256"}).encode("utf-8"))
    payload = b64url_encode(b'{"exp": Infinity, "sub": "a"}')  # json.loads aceita Infinity
    decoded = decode(f"{header}.{payload}.AAAA")
    findings = run_all(decoded, NOW)  # não deve levantar
    assert isinstance(findings, list)


# MEDIUM — NumericDate fora de faixa derrubava o report console.
def test_console_render_handles_out_of_range_date() -> None:
    header = b64url_encode(json.dumps({"alg": "HS256"}).encode("utf-8"))
    payload = b64url_encode(b'{"exp": 99999999999999999999}')
    decoded = decode(f"{header}.{payload}.AAAA")
    result = AuditResult(token=decoded, findings=run_all(decoded, NOW))
    console = Console(file=io.StringIO(), width=200)
    render(result, console)  # não deve levantar
    assert console.file.getvalue()  # type: ignore[attr-defined]
