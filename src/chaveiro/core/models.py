"""Modelos de domínio do Chaveiro."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _RANK[self]


_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True)
class DecodedToken:
    """Um JWS ou JWE decodificado — **sem** verificar assinatura nem decifrar nada."""

    raw: str
    header: dict[str, Any]
    payload: dict[str, Any]
    signature: bytes
    signing_input: bytes  # header_b64 + "." + payload_b64 (bytes ASCII)
    # JWT aninhado (RFC 7519 §5.2): o token interno, quando o payload da casca é
    # outro JWS compacto em vez de um objeto JSON. Nesse caso `payload` fica
    # vazio — a casca não tem claims próprias.
    nested: str | None = None
    # "jws" (3 segmentos, RFC 7515) ou "jwe" (5 segmentos, RFC 7516). Num JWE só
    # o cabeçalho protegido é legível sem a chave — `payload` fica vazio (não é
    # "sem claims", é "claims cifradas") e `header['alg']` muda de sentido: não é
    # o algoritmo de ASSINATURA, é o de GERENCIAMENTO DE CHAVE. As checagens de
    # JWS (`check_alg`, `check_claims`, ...) não se aplicam a um `kind="jwe"`.
    kind: str = "jws"

    @property
    def alg(self) -> str:
        value = self.header.get("alg", "")
        return value if isinstance(value, str) else ""

    @property
    def is_unsecured(self) -> bool:
        return self.kind == "jws" and self.alg.lower() == "none"


@dataclass(frozen=True)
class Finding:
    """Uma fraqueza encontrada na auditoria de um token."""

    check_id: str
    title: str
    severity: Severity
    detail: str
    recommendation: str
    cwe: str | None = None
    owasp: str | None = None
    evidence: str | None = None


@dataclass
class AuditResult:
    token: DecodedToken
    findings: list[Finding] = field(default_factory=list)

    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def sorted(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity.rank, f.check_id))
