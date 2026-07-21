"""Catálogo declarativo das checagens — fonte única de metadados.

Cada checagem tem id, título, severidade padrão, OWASP/CWE e recomendação. As
funções em ``checks/*`` decidem *quando* emitir; os metadados vêm daqui.
"""

from __future__ import annotations

from dataclasses import dataclass

from chaveiro.core.models import Finding, Severity


@dataclass(frozen=True)
class CheckMeta:
    id: str
    title: str
    severity: Severity
    recommendation: str
    owasp: str | None = None
    cwe: str | None = None


CATALOG: dict[str, CheckMeta] = {
    m.id: m
    for m in [
        CheckMeta(
            "alg-none",
            "Token não assinado (alg: none)",
            Severity.CRITICAL,
            "Rejeite explicitamente 'none'. Use uma allowlist fixa de algoritmos na verificação.",
            "A07:2021 Identification and Authentication Failures",
            "CWE-347",
        ),
        CheckMeta(
            "alg-missing",
            "Cabeçalho sem 'alg'",
            Severity.HIGH,
            "Sem 'alg' a verificação fica ambígua. Fixe o algoritmo esperado no servidor.",
            "A07:2021 Identification and Authentication Failures",
            "CWE-347",
        ),
        CheckMeta(
            "alg-unknown",
            "Algoritmo incomum/não reconhecido",
            Severity.MEDIUM,
            "Aceite apenas os algoritmos que você realmente usa (allowlist).",
            "A07:2021 Identification and Authentication Failures",
            "CWE-347",
        ),
        CheckMeta(
            "alg-hmac-advisory",
            "HMAC (HS*) — verifique segredo e confusão de algoritmo",
            Severity.LOW,
            "Rode `chaveiro crack` para testar segredo fraco. Se o servidor também aceita RS*/ES*, "
            "há risco de confusão de algoritmo (RS→HS) — separe as chaves e fixe o algoritmo.",
            "A02:2021 Cryptographic Failures",
            "CWE-326",
        ),
        CheckMeta(
            "claim-no-exp",
            "Sem expiração (claim 'exp' ausente)",
            Severity.HIGH,
            "Emita tokens de vida curta com 'exp'. Sem isso, um token vazado é válido para sempre.",
            "A07:2021 Identification and Authentication Failures",
            "CWE-613",
        ),
        CheckMeta(
            "claim-expired",
            "Token expirado",
            Severity.INFO,
            "Informativo: o 'exp' já passou. Um verificador correto rejeitaria este token.",
            None,
            None,
        ),
        CheckMeta(
            "claim-long-lifetime",
            "Vida útil longa",
            Severity.MEDIUM,
            "Reduza a validade (minutos/horas). Use refresh tokens em vez de access tokens longevos.",
            "A07:2021 Identification and Authentication Failures",
            "CWE-613",
        ),
        CheckMeta(
            "claim-no-iat",
            "Sem 'iat' (issued-at)",
            Severity.LOW,
            "Inclua 'iat' para permitir políticas de idade e auditoria.",
            "A07:2021 Identification and Authentication Failures",
            None,
        ),
        CheckMeta(
            "claim-no-aud",
            "Sem 'aud' (audience)",
            Severity.LOW,
            "Valide 'aud' no servidor para impedir reúso do token em outro serviço.",
            "A07:2021 Identification and Authentication Failures",
            "CWE-345",
        ),
        CheckMeta(
            "claim-no-iss",
            "Sem 'iss' (issuer)",
            Severity.LOW,
            "Inclua e valide 'iss' para amarrar o token ao emissor esperado.",
            "A07:2021 Identification and Authentication Failures",
            "CWE-345",
        ),
        CheckMeta(
            "claim-nbf-future",
            "'nbf' no futuro",
            Severity.INFO,
            "Informativo: o token ainda não é válido (not-before no futuro).",
            None,
            None,
        ),
        CheckMeta(
            "header-jku",
            "Cabeçalho 'jku' (URL de conjunto de chaves)",
            Severity.HIGH,
            "Nunca busque a chave de uma URL vinda do token — vetor de SSRF e injeção de chave. "
            "Use uma allowlist local de chaves confiáveis.",
            "A10:2021 Server-Side Request Forgery",
            "CWE-918",
        ),
        CheckMeta(
            "header-x5u",
            "Cabeçalho 'x5u' (URL de certificado)",
            Severity.HIGH,
            "Idem 'jku': não carregue material de chave de URL controlável pelo emissor do token.",
            "A10:2021 Server-Side Request Forgery",
            "CWE-918",
        ),
        CheckMeta(
            "header-jwk",
            "Cabeçalho 'jwk' (chave embutida)",
            Severity.HIGH,
            "Chave pública embutida no token: um atacante fornece a própria chave. Ignore 'jwk' e "
            "use apenas chaves configuradas no servidor.",
            "A07:2021 Identification and Authentication Failures",
            "CWE-347",
        ),
        CheckMeta(
            "header-x5c",
            "Cabeçalho 'x5c' (cadeia de certificados embutida)",
            Severity.MEDIUM,
            "Só confie em 'x5c' se validar a cadeia contra uma âncora confiável sua.",
            "A07:2021 Identification and Authentication Failures",
            "CWE-347",
        ),
        CheckMeta(
            "header-kid-injection",
            "'kid' com caracteres perigosos",
            Severity.HIGH,
            "Trate 'kid' como identificador opaco. Nunca o use em caminho de arquivo ou SQL — "
            "é vetor de path traversal / injeção.",
            "A03:2021 Injection",
            "CWE-91",
        ),
        CheckMeta(
            "header-crit",
            "Cabeçalho 'crit' presente",
            Severity.INFO,
            "Informativo: extensões críticas declaradas; confirme que o verificador as entende.",
            None,
            None,
        ),
        CheckMeta(
            "payload-sensitive",
            "Dado sensível no payload",
            Severity.MEDIUM,
            "O payload de um JWT é apenas base64 — não é cifrado. Não coloque segredos nem dados "
            "pessoais (LGPD) nele; use JWE se precisar de confidencialidade.",
            "A02:2021 Cryptographic Failures",
            "CWE-522",
        ),
    ]
}


def make_finding(
    check_id: str,
    detail: str,
    *,
    evidence: str | None = None,
    severity: Severity | None = None,
) -> Finding:
    meta = CATALOG[check_id]
    return Finding(
        check_id=meta.id,
        title=meta.title,
        severity=severity or meta.severity,
        detail=detail,
        recommendation=meta.recommendation,
        cwe=meta.cwe,
        owasp=meta.owasp,
        evidence=evidence,
    )
