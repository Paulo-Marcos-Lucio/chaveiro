"""Ataque de dicionário ao segredo HMAC (HS256/384/512).

Uso legítimo: testar, em um sistema que você controla ou tem autorização para
avaliar, se o segredo de assinatura é fraco/adivinhável — a falha real por trás
de tantos bypasses de JWT.
"""

from __future__ import annotations

from collections.abc import Iterable

from chaveiro.core.jwt import verify_hmac
from chaveiro.core.models import DecodedToken

# Segredos fracos vistos em tutoriais, exemplos e libs — o primeiro lugar a olhar.
DEFAULT_WEAK_SECRETS: tuple[str, ...] = (
    "secret",
    "secret123",
    "password",
    "changeme",
    "admin",
    "jwt",
    "token",
    "key",
    "test",
    "12345678",
    "your-256-bit-secret",
    "your_jwt_secret",
    "supersecret",
    "s3cr3t",
    "qwerty",
    "letmein",
)


def crack(token: DecodedToken, candidates: Iterable[str]) -> str | None:
    """Devolve o primeiro segredo que valida a assinatura, ou ``None``."""
    if token.alg not in {"HS256", "HS384", "HS512"}:
        return None
    for candidate in candidates:
        if verify_hmac(token, candidate.encode("utf-8")):
            return candidate
    return None


def crack_with_defaults(token: DecodedToken, extra: Iterable[str] | None = None) -> str | None:
    def _stream() -> Iterable[str]:
        yield from DEFAULT_WEAK_SECRETS
        if extra is not None:
            yield from extra

    return crack(token, _stream())
