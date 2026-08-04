"""Referência: validação **correta** de um JWT.

Este módulo é didático — é o lado da *correção*. A maioria dos bypasses de JWT
explora um verificador que:

- lê o algoritmo **do próprio token** (permitindo `none` ou confusão RS→HS);
- não confere `exp`/`nbf`;
- não valida `aud`/`iss`.

A função :func:`validate` faz o oposto: **allowlist fixa de algoritmos**,
rejeição explícita de `none`, verificação de assinatura e de claims temporais e
de destinatário. Use-a como espelho ao revisar o código de um cliente.
"""

from __future__ import annotations

import math
import time
from typing import Any

from chaveiro.core.jwt import decode, verify_asymmetric, verify_hmac

_HS = {"HS256", "HS384", "HS512"}
# RFC 7519 §4.1.10 / §5.2: 'cty' com valor JWT marca um JWT aninhado — o payload é
# outro JWS. Comparação case-insensitive, com o prefixo "application/" opcional.
_CTY_NESTED = {"jwt", "application/jwt"}
_ASYM = {
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "EdDSA",
}


class InvalidToken(Exception):
    """O token não passou na validação segura."""


def validate(
    token_str: str,
    *,
    key: bytes,
    algorithms: list[str],
    audience: str | None = None,
    issuer: str | None = None,
    now: int | None = None,
    leeway: int = 0,
    typ: str | None = None,
) -> dict[str, Any]:
    """Valida um JWT com política estrita e devolve o payload confiável.

    ``algorithms`` é uma **allowlist obrigatória** — sem ela, tudo o mais é
    inútil. ``key`` é o segredo HMAC (para HS*) ou a chave pública PEM
    (RS*/PS*/ES*/EdDSA).

    ``typ`` é opcional: quando informado, o cabeçalho ``typ`` do token tem que
    existir e casar (case-insensitive) — útil para fixar ``at+jwt`` (RFC 9068) e
    impedir a confusão entre tipos de token. **JWT aninhado** (``cty: JWT``, RFC
    7519 §5.2) é rejeitado explicitamente: esta referência valida uma camada, e
    devolver o payload vazio da casca como se fosse confiável seria fail-open —
    valide as duas camadas separadamente.
    """
    if not algorithms:
        raise InvalidToken("defina uma allowlist de algoritmos (nunca aceite o alg do token)")
    if any(a.lower() == "none" for a in algorithms):
        raise InvalidToken("'none' jamais deve estar na allowlist")

    decoded = decode(token_str)
    _check_not_nested(decoded)
    _check_typ(decoded.header, typ)
    alg = decoded.alg
    if alg not in algorithms:
        raise InvalidToken(f"algoritmo {alg!r} fora da allowlist {algorithms}")

    if alg in _HS:
        if not verify_hmac(decoded, key):
            raise InvalidToken("assinatura HMAC inválida")
    elif alg in _ASYM:
        if not verify_asymmetric(decoded, key):
            raise InvalidToken("assinatura assimétrica inválida")
    else:
        raise InvalidToken(f"algoritmo não suportado pela referência: {alg!r}")

    _check_time(decoded.payload, now if now is not None else int(time.time()), leeway)
    _check_audience(decoded.payload, audience)
    _check_issuer(decoded.payload, issuer)
    return decoded.payload


def _check_not_nested(decoded: Any) -> None:
    """Rejeita JWT aninhado — a referência não repassa o miolo como confiável.

    Dois sinais: o ``decode`` já detectou que o payload é outro JWS (``nested``),
    ou o cabeçalho declara ``cty: JWT``. Antes desta checagem, um token aninhado
    tinha payload ``{}`` e a função devolvia esse dict vazio em silêncio: um
    verificador que confiasse no retorno trataria "sem claims" como válido.
    """
    if decoded.nested is not None:
        raise InvalidToken(
            "JWT aninhado (payload é outro JWS, RFC 7519 §5.2): valide cada camada "
            "separadamente; esta referência não repassa o token interno como confiável"
        )
    cty = decoded.header.get("cty")
    if isinstance(cty, str) and cty.strip().lower() in _CTY_NESTED:
        raise InvalidToken(
            "cabeçalho declara 'cty: JWT' (JWT aninhado): valide as duas camadas separadamente"
        )


def _check_typ(header: dict[str, Any], expected: str | None) -> None:
    """Confere o cabeçalho ``typ`` quando o chamador o exige.

    RFC 7519 §5.1: ``typ`` é opcional, então só é checado quando ``expected`` é
    dado. Ausência com ``expected`` definido é erro — não pode ser tratada como
    'ok' (fail-open). A comparação é case-insensitive (RFC 7515: 'JWT' == 'jwt').
    """
    if expected is None:
        return
    actual = header.get("typ")
    if not isinstance(actual, str) or actual.strip().lower() != expected.strip().lower():
        raise InvalidToken(f"cabeçalho 'typ' inválido: esperava {expected!r}, veio {actual!r}")


def _check_time(payload: dict[str, Any], now: int, leeway: int) -> None:
    """Confere 'exp'/'nbf' — e **rejeita** claim temporal malformada.

    RFC 7519 §2 define NumericDate como número. Uma claim presente mas não
    numérica (``exp: "1"``) tem que ser erro, nunca ausência: tratá-la como
    ausente é falhar aberto, e um token com ``exp`` em string passaria a nunca
    expirar. ``bool`` é `int` em Python e também não é NumericDate.
    """
    exp = _numeric_date(payload, "exp")
    if exp is not None and now > exp + leeway:
        raise InvalidToken("token expirado (exp)")
    nbf = _numeric_date(payload, "nbf")
    if nbf is not None and now + leeway < nbf:
        raise InvalidToken("token ainda não válido (nbf)")


def _numeric_date(payload: dict[str, Any], claim: str) -> int | float | None:
    if claim not in payload:
        return None
    value = payload[claim]
    # RFC 7519 §2: NumericDate é número (bool é int em Python, mas não é data).
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidToken(f"claim {claim!r} presente mas não é um NumericDate (RFC 7519 §2)")
    # `json.loads` aceita os literais Infinity/NaN: com eles toda comparação
    # temporal daria False e o token nunca expiraria — a checagem de finitude fica
    # SÓ no ramo float, porque `math.isfinite`/`float()` estouram (OverflowError)
    # ao converter um inteiro gigante (ex.: exp = 10**400) para double, e um exp
    # hostil não pode DERRUBAR o validador de referência. Devolvemos o número CRU,
    # sem conversão: a comparação em `_check_time` já opera com int de precisão
    # arbitrária (um exp astronômico é, corretamente, "ainda não expirado").
    if isinstance(value, float) and not math.isfinite(value):
        raise InvalidToken(f"claim {claim!r} presente mas não é um NumericDate (RFC 7519 §2)")
    return value


def _check_audience(payload: dict[str, Any], audience: str | None) -> None:
    if audience is None:
        return
    aud = payload.get("aud")
    valid = audience == aud or (isinstance(aud, list) and audience in aud)
    if not valid:
        raise InvalidToken(f"audiência inválida: esperava {audience!r}")


def _check_issuer(payload: dict[str, Any], issuer: str | None) -> None:
    if issuer is not None and payload.get("iss") != issuer:
        raise InvalidToken(f"emissor inválido: esperava {issuer!r}")
