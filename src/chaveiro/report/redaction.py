"""Redação de PII do titular final antes de gravar o laudo (P1-01).

Doutrina. Um JWT de cliente carrega rotineiramente dado pessoal do **titular
final** — `sub`, `email`, `name`, `cpf`, telefone. Gravar isso 100% no JSON e no
console faz do auditor o operador LGPD guardando PII de terceiro **sem
necessidade**: a auditoria de segurança do token não depende do valor da
identidade, só da estrutura. Por padrão redigimos as claims de IDENTIDADE (pelo
nome) e qualquer VALOR que aparente e-mail ou CPF, em qualquer profundidade,
mantendo visíveis as claims ESTRUTURAIS que a auditoria realmente usa (`exp`,
`iat`, `nbf`, `iss`, `aud`, `jti`, `typ`, `kid`, `alg`). Ver tudo é opt-in
explícito via `--claims-completas`.
"""

from __future__ import annotations

import re
from typing import Any

from chaveiro.checks.detectors import has_cpf

# Marcador visível — deixa claro que houve redação e como reverter, em vez de
# apagar a claim (o que esconderia a própria existência do dado).
REDIGIDO = "«redigido (LGPD) — use --claims-completas para ver»"

# Claims cujo NOME denuncia identidade do titular. Comparação em minúsculas.
_IDENTITY_KEYS = frozenset(
    {
        "sub",
        "email",
        "name",
        "preferred_username",
        "phone_number",
        "cpf",
        "given_name",
        "family_name",
        "nome",
        "telefone",
    }
)
# Claims estruturais: a auditoria precisa delas e não são PII — nunca redigidas.
_STRUCTURAL_KEYS = frozenset({"alg", "exp", "iat", "nbf", "iss", "aud", "typ", "kid", "jti"})
# E-mail em qualquer valor de string, mesmo sob uma chave de nome inocente.
_EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


def redact_claims(payload: dict[str, Any]) -> dict[str, Any]:
    """Devolve uma cópia do payload com as claims de identidade/PII redigidas."""
    return {key: _redact(key, value) for key, value in payload.items()}


def _redact(key: str, value: Any) -> Any:
    lowered = key.lower()
    if lowered in _STRUCTURAL_KEYS:
        return value  # estrutural: mantém como está (inclusive listas de aud)
    if lowered in _IDENTITY_KEYS:
        return REDIGIDO
    return _redact_value(value)


def _redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _redact(k, v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, str) and _is_pii(value):
        return REDIGIDO
    return value


def _is_pii(text: str) -> bool:
    return bool(_EMAIL.search(text)) or has_cpf(text)
