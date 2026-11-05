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
    # Chaves que apareceram repetidas no JSON do header e/ou do payload (em
    # qualquer nível de objeto). RFC 8259 permite a sintaxe mas não diz qual
    # valor vence; parsers diferentes decidem diferente (json.loads: último
    # vence). Um token com {"alg":"none","alg":"HS256"} pode ser lido como
    # "none" por um verificador e "HS256" por outro — a mesma ambiguidade de
    # classe que já rendeu confusão de algoritmo. `decode()` nunca falha por
    # isso; só registra, para o auditor ver o que um verificador tolerante
    # poderia discordar.
    duplicate_keys: tuple[str, ...] = ()

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

    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def sorted(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity.rank, f.check_id))
