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
from chaveiro.reference.secure_validation import InvalidToken, validate
from chaveiro.report.console import render
from chaveiro.report.json_report import to_json

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


# =========================================================================== #
# Bateria de campo (2026-07-22) — auditoria adversarial multidimensional.
# =========================================================================== #

from typer.testing import CliRunner  # noqa: E402

from chaveiro.attacks.crack import crack_with_defaults  # noqa: E402
from chaveiro.cli import app  # noqa: E402
from chaveiro.core.jwt import encode_hmac  # noqa: E402

_runner = CliRunner()


def _none_token() -> str:
    h = b64url_encode(json.dumps({"alg": "none"}).encode("utf-8"))
    p = b64url_encode(json.dumps({"sub": "x"}).encode("utf-8"))
    return f"{h}.{p}."


# C1 — segredo HMAC VAZIO (env var não setada) é a falha mais grave e passava batida.
def test_empty_hmac_secret_is_cracked() -> None:
    token = encode_hmac({"alg": "HS256", "typ": "JWT"}, {"sub": "admin"}, b"")
    assert crack_with_defaults(decode(token)) == ""


def test_crack_cli_reports_empty_secret() -> None:
    token = encode_hmac({"alg": "HS256", "typ": "JWT"}, {"sub": "admin"}, b"")
    result = _runner.invoke(app, ["crack", token])
    assert result.exit_code == 1  # segredo fraco encontrado


# C2 — crack em token não-HS* dava a MESMA mensagem 'nenhum candidato' + exit 0 (enganoso).
def test_crack_non_hmac_exits_2_not_misleading_0() -> None:
    result = _runner.invoke(app, ["crack", _none_token()])
    assert result.exit_code == 2  # 'não se aplica', não o exit 0 de 'segredo forte'


# R1 — exp inteiro gigante (dentro do limite de dígitos do JSON, mas além do float)
# fazia `round(lifetime / 3600, 1)` levantar OverflowError e DERRUBAR a auditoria:
# traceback no `inspect`; no `batch` o token era engolido como "malformado" e o
# achado de validade-longa-demais sumia (fail-open, gate verde). Agora audita.
def test_exp_inteiro_gigante_nao_derruba_auditoria() -> None:
    huge = 10**400  # 401 dígitos: json.loads decodifica, mas não cabe em float
    header = b64url_encode(json.dumps({"alg": "HS256"}).encode("utf-8"))
    payload = b64url_encode(json.dumps({"exp": huge, "iat": NOW}).encode("utf-8"))
    decoded = decode(f"{header}.{payload}.AAAA")
    findings = run_all(decoded, NOW)  # não pode levantar OverflowError
    ids = {f.check_id for f in findings}
    assert "claim-long-lifetime" in ids  # achado preservado, não perdido
    result = AuditResult(token=decoded, findings=findings)
    assert to_json(result)  # serialização JSON não levanta
    console = Console(file=io.StringIO(), width=200)
    render(result, console)  # render console não levanta
    assert console.file.getvalue()  # type: ignore[attr-defined]


# R2 — inteiro literal além de sys.get_int_max_str_digits() (~4300) faz json.loads
# levantar um ValueError CRU (não JSONDecodeError) que vazava do decode: crash no
# `inspect`. Agora vira JWTError, e no batch é isolado sem contaminar o token bom.
def test_inteiro_alem_do_limite_de_digitos_vira_jwterror() -> None:
    big = "1" + "0" * 5000  # 5001 dígitos > limite -> json.loads levanta ValueError cru
    header = b64url_encode(json.dumps({"alg": "HS256"}).encode("utf-8"))
    payload = b64url_encode(('{"exp":' + big + '}').encode("utf-8"))
    hostil = f"{header}.{payload}.AAAA"
    with pytest.raises(JWTError):  # falha ALTO, nunca ValueError cru / traceback
        decode(hostil)

    from chaveiro.audit import audit_batch, summarize

    bom = encode_hmac(
        {"alg": "HS256"}, {"sub": "x", "exp": NOW + 60, "iat": NOW, "aud": "a", "iss": "i"}, b"s"
    )
    outcomes = audit_batch(f"{hostil}\n{bom}\n", NOW)
    assert outcomes[0].result is None and outcomes[0].error is not None  # hostil isolado
    assert outcomes[1].ok  # token legítimo ainda auditado
    assert summarize(outcomes).errors == 1


# R3 — validador de REFERÊNCIA (o "jeito certo") estourava OverflowError com um
# exp/nbf inteiro gigante: `math.isfinite(10**400)` / `float(10**400)` não cabem
# em double. Um token hostil não pode derrubar a validação; a comparação temporal
# tem que rodar em int de precisão arbitrária, sem virar FN nas claims malformadas.
def test_validador_referencia_nao_estoura_com_exp_gigante() -> None:
    # exp astronômico: token NÃO expirado -> aceito, sem OverflowError.
    aceito = encode_hmac({"alg": "HS256"}, {"exp": 10**400, "sub": "a"}, b"k")
    assert validate(aceito, key=b"k", algorithms=["HS256"], now=NOW)["sub"] == "a"
    # nbf astronômico: token ainda-não-válido -> InvalidToken (não crash).
    futuro = encode_hmac({"alg": "HS256"}, {"nbf": 10**400, "sub": "a"}, b"k")
    with pytest.raises(InvalidToken):
        validate(futuro, key=b"k", algorithms=["HS256"], now=NOW)
    # sem FN: exp em string continua rejeitado como NumericDate inválido.
    string_exp = encode_hmac({"alg": "HS256"}, {"exp": "1700", "sub": "a"}, b"k")
    with pytest.raises(InvalidToken):
        validate(string_exp, key=b"k", algorithms=["HS256"], now=NOW)
