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


class Profile(str, Enum):
    """Qual contrato de claims a checagem de claims cobra.

    O genérico é a base comum de qualquer JWT (exp/iat/aud/iss). O perfil
    ``access-token`` segue o RFC 9068 (JWT Profile for OAuth 2.0 Access
    Tokens): ``aud`` deixa de ser exigido — na prática, muitas implantações
    de access token legítimas não a incluem — e em troca o perfil cobra
    ``sub`` e ``client_id``, que o genérico nunca verificava.
    """

    GENERICO = "generico"
    ACCESS_TOKEN = "access-token"


@dataclass(frozen=True)
class DecodedToken:
    """Um JWS/JWT decodificado — **sem** verificação de assinatura."""

    raw: str
    header: dict[str, Any]
    payload: dict[str, Any]
    signature: bytes
    signing_input: bytes  # header_b64 + "." + payload_b64 (bytes ASCII)
    # JWT aninhado (RFC 7519 §5.2): o token interno, quando o payload da casca é
    # outro JWS compacto em vez de um objeto JSON. Nesse caso `payload` fica
    # vazio — a casca não tem claims próprias.
    nested: str | None = None

    @property
    def alg(self) -> str:
        value = self.header.get("alg", "")
        return value if isinstance(value, str) else ""

    @property
    def is_unsecured(self) -> bool:
        return self.alg.lower() == "none"


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
    # Qual perfil decidiu o contrato de claims (explícito via --perfil ou
    # detectado por 'typ'). Fica no resultado para o laudo dizer POR QUE um
    # achado de claim ausente não apareceu, em vez de deixar isso implícito.
    profile: Profile = Profile.GENERICO

    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def sorted(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity.rank, f.check_id))
