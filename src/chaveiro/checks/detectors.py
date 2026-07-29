"""As checagens em si — passivas, sobre um token já decodificado."""

from __future__ import annotations

import math
import re
from collections.abc import Iterator
from typing import Any

from chaveiro.checks.catalog import make_finding
from chaveiro.core.jwt import looks_like_jws
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
_TIME_CLAIMS = ("exp", "iat", "nbf")
# Igualdade exata: termos que só são sinal quando são a chave inteira ('token'
# como substring casaria com 'token_type: Bearer', que é ruído de OAuth).
_SENSITIVE_KEYS = {
    "password", "passwd", "pwd", "senha",
    "secret", "client_secret", "api_key", "apikey",
    "token", "access_token", "refresh_token", "private_key",
}  # fmt: skip
# Substring sobre a chave normalizada (minúscula, sem separadores): pega
# 'user_password', 'dbSecret', 'x-api-key' — as formas compostas reais.
_SENSITIVE_PARTS = ("password", "passwd", "pwd", "senha", "secret", "apikey", "privatekey")
_NOT_ALNUM = re.compile(r"[^a-z0-9]")
_NOT_DIGIT = re.compile(r"\D")
# CPF nas duas formas de campo: pontuada e 11 dígitos crus. Os dígitos
# verificadores são conferidos depois — sem isso, todo número de 11 dígitos
# (telefone, id) viraria achado de LGPD.
_CPF = re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b|\b\d{11}\b")
# RFC 7515 §4.1.10 / RFC 7519 §5.2: comparação case-insensitive e o prefixo
# "application/" pode ser omitido — "JWT" marca um token aninhado.
_CTY_NESTED = {"jwt", "application/jwt"}


def run_all(token: DecodedToken, now: int) -> list[Finding]:
    findings: list[Finding] = []
    findings += check_alg(token)
    findings += check_header(token)
    findings += check_nesting(token)
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


def check_nesting(token: DecodedToken) -> list[Finding]:
    """Sinaliza o vetor de JWT confusion por aninhamento (cty / token embutido).

    Passiva: observa que o cabeçalho declara um JWT aninhado ('cty: JWT'), que o
    payload da casca **é** outro JWS compacto (aninhamento real, RFC 7519 §5.2)
    e/ou que alguma claim carrega o que aparenta ser outro JWT. Não valida
    assinatura nem faz rede — só aponta a superfície de confusão.
    """
    out: list[Finding] = []
    cty = token.header.get("cty")
    if isinstance(cty, str) and cty.strip().lower() in _CTY_NESTED:
        out.append(
            make_finding(
                "header-cty-nested",
                "O cabeçalho declara 'cty' de JWT aninhado — o payload deveria ser outro JWT. "
                "Um verificador que valida só a casca e confia no miolo sem checá-lo é enganável.",
                evidence=f"cty={cty!r}",
            )
        )
    if token.nested is not None:
        out.append(
            make_finding(
                "payload-nested-jwt",
                "O payload desta casca É outro JWS compacto (JWT aninhado, RFC 7519 §5.2): as "
                "claims estão no token interno. Audite o token interno separadamente — a casca "
                "sozinha não diz nada sobre expiração, emissor ou destinatário.",
                evidence=f"payload = JWS compacto de {len(token.nested)} caracteres",
            )
        )
    for key, value in token.payload.items():
        if isinstance(value, str) and looks_like_jws(value):
            out.append(
                make_finding(
                    "payload-nested-jwt",
                    f"A claim {key!r} contém o que aparenta ser outro JWT (token aninhado).",
                    evidence=f"{key}=<jwt>",
                )
            )
    return out


def check_claims(token: DecodedToken, now: int) -> list[Finding]:
    out: list[Finding] = []
    payload = token.payload
    if token.nested is not None:
        # Casca de JWT aninhado: as claims vivem no token interno. Cobrar
        # 'exp'/'aud'/'iss' da casca produziria quatro achados falsos.
        return out
    exp = _as_epoch(payload.get("exp"))
    iat = _as_epoch(payload.get("iat"))
    nbf = _as_epoch(payload.get("nbf"))

    for name in _TIME_CLAIMS:
        if name in payload and _as_epoch(payload[name]) is None:
            out.append(
                make_finding(
                    "claim-malformed-time",
                    f"A claim {name!r} existe mas não é um NumericDate (RFC 7519 §2). Muitos "
                    f"verificadores tratam claim temporal inválida como AUSENTE e seguem em "
                    f"frente — o token deixa de expirar.",
                    evidence=f"{name}={str(payload[name])[:60]!r}",
                )
            )

    if "exp" not in payload:
        out.append(make_finding("claim-no-exp", "O token não tem 'exp' — nunca expira."))
    elif exp is not None and exp < now:
        out.append(make_finding("claim-expired", f"'exp' já passou (exp={exp}, agora={now})."))

    # Sem 'iat' a vida útil é aproximada por 'agora': um token de 10 anos sem
    # 'iat' é MAIS perigoso, e era justo aí que a checagem se desligava.
    if exp is not None:
        base = "exp - iat" if iat is not None else "exp - agora, sem 'iat'"
        lifetime = exp - iat if iat is not None else exp - now
        if lifetime > _LONG_LIFETIME_S:
            out.append(
                make_finding(
                    "claim-long-lifetime", f"Validade de ~{round(lifetime / 3600, 1)}h ({base})."
                )
            )

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
    """Procura segredo e dado pessoal em **qualquer profundidade** do payload.

    `{"user": {"cpf": ...}}` é a forma mais comum de payload JWT no Brasil, então
    varrer só o primeiro nível seria falso negativo na forma que mais aparece.
    """
    out: list[Finding] = []
    for path, key, value in _walk(token.payload):
        if _is_sensitive_key(key) and value not in (None, "", [], {}):
            out.append(
                make_finding(
                    "payload-sensitive",
                    f"A claim {path!r} parece carregar um segredo em texto claro.",
                    evidence=f"{path}=…",
                )
            )
        elif isinstance(value, str) and _has_cpf(value):
            out.append(
                make_finding(
                    "payload-sensitive",
                    f"A claim {path!r} contém um CPF (dado pessoal — LGPD) no payload.",
                    evidence=f"{path}=<cpf>",
                )
            )
    return out


def _walk(payload: dict[str, Any]) -> Iterator[tuple[str, str, Any]]:
    """Percorre o payload inteiro — dicts e listas aninhados — **sem recursão**.

    Devolve ``(caminho, chave, valor)``; itens de lista vêm com chave vazia (não
    têm nome, só posição). A profundidade já é limitada no decode
    (``MAX_JSON_DEPTH``), mas a pilha explícita torna isso independente disso.
    """
    stack: list[tuple[str, Any]] = [("", payload)]
    while stack:
        prefix, node = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                yield path, str(key), value
                if isinstance(value, (dict, list)):
                    stack.append((path, value))
        elif isinstance(node, list):
            for position, value in enumerate(node):
                path = f"{prefix}[{position}]"
                if isinstance(value, (dict, list)):
                    stack.append((path, value))
                else:
                    yield path, "", value


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    if lowered in _SENSITIVE_KEYS:
        return True
    normalized = _NOT_ALNUM.sub("", lowered)
    return any(term in normalized for term in _SENSITIVE_PARTS)


def _has_cpf(value: str) -> bool:
    return any(_cpf_digits_ok(_NOT_DIGIT.sub("", m.group())) for m in _CPF.finditer(value))


def _cpf_digits_ok(digits: str) -> bool:
    """Confere os dois dígitos verificadores do CPF (módulo 11)."""
    if len(digits) != 11 or digits == digits[0] * 11:
        return False
    for size in (9, 10):
        total = sum(int(d) * (size + 1 - i) for i, d in enumerate(digits[:size]))
        if (total * 10) % 11 % 10 != int(digits[size]):
            return False
    return True


def _as_epoch(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None  # Infinity/NaN (json.loads aceita esses literais)
    if isinstance(value, (int, float)):
        return int(value)
    return None
