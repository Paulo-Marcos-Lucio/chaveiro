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
    # "compact" (RFC 7515 §3.1, os 3 segmentos pontuados — a forma comum) ou
    # "json" (§7.2, Flattened ou General): o token veio de um objeto JSON em
    # vez da string compacta. Checks que assumem a forma compacta (ex.: que
    # recompõem `raw` a partir de 3 partes) precisam saber distinguir.
    serialization: str = "compact"
    # Chaves fora do esquema canônico da serialização JSON (RFC 7515 §7.2):
    # qualquer coisa que não seja payload/protected/header/signature
    # (Flattened) ou payload/signatures (General) mais protected/header/
    # signature de dentro da entrada de assinatura usada. Vazio na forma
    # compacta. Um campo extra pode ser metadado inócuo (ex.: "kid" fora do
    # lugar) ou pode ser o verificador real lendo algo que este decodificador
    # ignorou — por isso fica visível, não descartado em silêncio.
    extra_fields: dict[str, Any] = field(default_factory=dict)

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
