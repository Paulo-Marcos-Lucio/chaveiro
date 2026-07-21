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

import time
from typing import Any

from chaveiro.core.jwt import decode, verify_asymmetric, verify_hmac

_HS = {"HS256", "HS384", "HS512"}
_ASYM = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}


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
) -> dict[str, Any]:
    """Valida um JWT com política estrita e devolve o payload confiável.

    ``algorithms`` é uma **allowlist obrigatória** — sem ela, tudo o mais é
    inútil. ``key`` é o segredo HMAC (para HS*) ou a chave pública PEM (RS*/ES*).
    """
    if not algorithms:
        raise InvalidToken("defina uma allowlist de algoritmos (nunca aceite o alg do token)")
    if any(a.lower() == "none" for a in algorithms):
        raise InvalidToken("'none' jamais deve estar na allowlist")

    decoded = decode(token_str)
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


def _check_time(payload: dict[str, Any], now: int, leeway: int) -> None:
    exp = payload.get("exp")
    if isinstance(exp, (int, float)) and now > exp + leeway:
        raise InvalidToken("token expirado (exp)")
    nbf = payload.get("nbf")
    if isinstance(nbf, (int, float)) and now + leeway < nbf:
        raise InvalidToken("token ainda não válido (nbf)")


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
