"""As checagens em si — passivas, sobre um token já decodificado."""

from __future__ import annotations

import re
from typing import Any

from chaveiro.checks.catalog import make_finding
from chaveiro.core.models import DecodedToken, Finding

_KNOWN_ALGS = {
    "HS256", "HS384", "HS512",
    "RS256", "RS384", "RS512",
    "ES256", "ES384", "ES512",
    "PS256", "PS384", "PS512",
    "EdDSA",
}  # fmt: skip
_HMAC_ALGS = {"HS256", "HS384", "HS512"}
_LONG_LIFETIME_S = 24 * 3600

_KID_DANGEROUS = ("..", "/", "\\", "'", '"', ";", "`", "$(", "|", "<", ">", "\x00", "\n")
_SENSITIVE_KEYS = {
    "password", "passwd", "pwd", "senha",
    "secret", "client_secret", "api_key", "apikey",
    "token", "access_token", "refresh_token", "private_key",
}  # fmt: skip
_CPF = re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b")


def run_all(token: DecodedToken, now: int) -> list[Finding]:
    findings: list[Finding] = []
    findings += check_alg(token)
    findings += check_header(token)
    findings += check_claims(token, now)
    findings += check_payload(token)
    return findings


def check_alg(token: DecodedToken) -> list[Finding]:
    out: list[Finding] = []
    alg = token.header.get("alg")
    if not isinstance(alg, str) or alg == "":
        out.append(make_finding("alg-missing", "O cabeçalho não declara 'alg'."))
        return out
    if alg.lower() == "none":
        out.append(
            make_finding(
                "alg-none",
                "O token declara 'alg: none' — não há assinatura. Qualquer um pode forjar claims "
                "se o verificador aceitar tokens não assinados.",
                evidence=f"alg={alg!r}",
            )
        )
        return out
    if alg not in _KNOWN_ALGS:
        out.append(
            make_finding("alg-unknown", f"Algoritmo não reconhecido: {alg!r}.", evidence=alg)
        )
    elif alg in _HMAC_ALGS:
        out.append(
            make_finding(
                "alg-hmac-advisory",
                f"Token assinado com {alg} (segredo compartilhado).",
                evidence=alg,
            )
        )
    return out


def check_header(token: DecodedToken) -> list[Finding]:
    out: list[Finding] = []
    header = token.header
    for field_name, check_id in (("jku", "header-jku"), ("x5u", "header-x5u")):
        if field_name in header:
            out.append(
                make_finding(
                    check_id,
                    f"'{field_name}' aponta para material de chave externo.",
                    evidence=str(header[field_name])[:200],
                )
            )
    if "jwk" in header:
        out.append(make_finding("header-jwk", "Chave pública embutida no próprio token ('jwk')."))
    if "x5c" in header:
        out.append(make_finding("header-x5c", "Cadeia de certificados embutida ('x5c')."))
    if "crit" in header:
        out.append(make_finding("header-crit", f"Extensões críticas: {header['crit']!r}."))
    kid = header.get("kid")
    if isinstance(kid, str) and any(token_ in kid for token_ in _KID_DANGEROUS):
        out.append(
            make_finding(
                "header-kid-injection",
                "O 'kid' contém caracteres típicos de path traversal ou injeção.",
                evidence=f"kid={kid!r}",
            )
        )
    return out


def check_claims(token: DecodedToken, now: int) -> list[Finding]:
    out: list[Finding] = []
    payload = token.payload
    exp = _as_epoch(payload.get("exp"))
    iat = _as_epoch(payload.get("iat"))
    nbf = _as_epoch(payload.get("nbf"))

    if "exp" not in payload:
        out.append(make_finding("claim-no-exp", "O token não tem 'exp' — nunca expira."))
    elif exp is not None and exp < now:
        out.append(make_finding("claim-expired", f"'exp' já passou (exp={exp}, agora={now})."))

    if exp is not None and iat is not None and (exp - iat) > _LONG_LIFETIME_S:
        hours = round((exp - iat) / 3600, 1)
        out.append(make_finding("claim-long-lifetime", f"Validade de ~{hours}h (exp - iat)."))

    if "iat" not in payload:
        out.append(make_finding("claim-no-iat", "Sem 'iat'."))
    if "aud" not in payload:
        out.append(make_finding("claim-no-aud", "Sem 'aud'."))
    if "iss" not in payload:
        out.append(make_finding("claim-no-iss", "Sem 'iss'."))
    if nbf is not None and nbf > now:
        out.append(make_finding("claim-nbf-future", f"'nbf' no futuro (nbf={nbf}, agora={now})."))
    return out


def check_payload(token: DecodedToken) -> list[Finding]:
    out: list[Finding] = []
    for key, value in token.payload.items():
        if key.lower() in _SENSITIVE_KEYS and value not in (None, "", []):
            out.append(
                make_finding(
                    "payload-sensitive",
                    f"A claim {key!r} parece carregar um segredo em texto claro.",
                    evidence=f"{key}=…",
                )
            )
        elif isinstance(value, str) and _CPF.search(value):
            out.append(
                make_finding(
                    "payload-sensitive",
                    f"A claim {key!r} contém um CPF (dado pessoal — LGPD) no payload.",
                    evidence=f"{key}=<cpf>",
                )
            )
    return out


def _as_epoch(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    return None
