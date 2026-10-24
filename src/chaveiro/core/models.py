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


class FindingType(str, Enum):
    """Em qual DIMENSÃO do token a checagem vive — espelha o prefixo já usado nos
    ids do catálogo (``alg-*``, ``claim-*``, ``header-*``, ``payload-*``), agora
    como campo explícito em vez de convenção implícita no nome. Serve para quem
    consome o JSON agrupar achados sem fazer parsing de string no `id`.
    """

    ALGORITHM = "algorithm"  # alg-none, alg-missing, alg-unknown, alg-hmac-advisory
    CLAIM = "claim"  # exp/iat/aud/iss/nbf: presença, formato, tempo de vida
    HEADER = "header"  # jku/x5u/jwk/x5c/kid/crit/zip/cty
    PAYLOAD = "payload"  # conteúdo do corpo do token (aninhamento, dado sensível)


class Confidence(str, Enum):
    """Confiança de que o achado é um problema REAL neste token — não confiança de
    parsing (a extração de header/claims é sempre determinística; o Chaveiro nunca
    "acha que talvez" exista um campo). O que varia é se a checagem captura um fato
    universalmente arriscado ou um sinal que depende do contexto de implantação:

    - HIGH: o fato detectado é inequívoco e o risco vale para qualquer verificador
      (``alg: none``, cabeçalho ``jku``/``jwk`` presente, claim temporal fora do
      formato NumericDate do RFC 7519).
    - MEDIUM: o fato é determinístico, mas o risco real depende de como o token é
      usado (``aud``/``iss`` ausentes não importam num sistema de um serviço só;
      ``x5c`` só é problema se o verificador não validar a cadeia).
    - LOW: a checagem é consultiva por natureza — pede confirmação adicional antes
      de virar ação (``alg-hmac-advisory`` pede rodar `chaveiro crack`;
      `payload-nested-jwt` é heurística de "parece conter" outro token; `header-crit`
      é puramente informativo).
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


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
    #: Dimensão do token (:class:`FindingType`) e confiança de que é um problema
    #: real (:class:`Confidence`) — herdados de ``checks.catalog.CheckMeta``, que
    #: exige os dois na construção (ver
    #: `tests/test_detectors.py::test_toda_checagem_declara_type_e_confidence`).
    #: Sem default: propagar um achado sem os dois quebra na construção.
    finding_type: FindingType
    confidence: Confidence
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
