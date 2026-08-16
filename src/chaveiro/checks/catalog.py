"""Catálogo declarativo das checagens — fonte única de metadados.

Cada checagem tem id, título, severidade padrão, OWASP/CWE e recomendação. As
funções em ``checks/*`` decidem *quando* emitir; os metadados vêm daqui.
"""

from __future__ import annotations

from dataclasses import dataclass

from chaveiro.core.models import Finding, Severity

# Edição do OWASP Top 10 usada nos rótulos deste catálogo. Fica explícita no
# JSON e no cabeçalho das tabelas porque o mesmo código muda de significado
# entre edições ('A03' é Injection em 2021 e Software Supply Chain em 2025).
OWASP_EDITION = "2025"


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
            "A07:2025 Authentication Failures",
            "CWE-347",
        ),
        CheckMeta(
            "alg-missing",
            "Cabeçalho sem 'alg'",
            Severity.HIGH,
            "Sem 'alg' a verificação fica ambígua. Fixe o algoritmo esperado no servidor.",
            "A07:2025 Authentication Failures",
            "CWE-347",
        ),
        CheckMeta(
            "alg-unknown",
            "Algoritmo incomum/não reconhecido",
            Severity.MEDIUM,
            "Aceite apenas os algoritmos que você realmente usa (allowlist).",
            "A07:2025 Authentication Failures",
            "CWE-347",
        ),
        CheckMeta(
            "alg-hmac-advisory",
            "HMAC (HS*) — verifique segredo e confusão de algoritmo",
            Severity.LOW,
            "Rode `chaveiro crack` para testar segredo fraco. Se o servidor também aceita RS*/ES*, "
            "há risco de confusão de algoritmo (RS→HS) — separe as chaves e fixe o algoritmo.",
            "A04:2025 Cryptographic Failures",
            "CWE-326",
        ),
        CheckMeta(
            "claim-no-exp",
            "Sem expiração (claim 'exp' ausente)",
            Severity.HIGH,
            "Emita tokens de vida curta com 'exp'. Sem isso, um token vazado é válido para sempre.",
            "A07:2025 Authentication Failures",
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
            "A07:2025 Authentication Failures",
            "CWE-613",
        ),
        CheckMeta(
            "claim-no-iat",
            "Sem 'iat' (issued-at)",
            Severity.LOW,
            "Inclua 'iat' para permitir políticas de idade e auditoria.",
            "A07:2025 Authentication Failures",
            None,
        ),
        CheckMeta(
            "claim-no-aud",
            "Sem 'aud' (audience)",
            Severity.LOW,
            "Valide 'aud' no servidor para impedir reúso do token em outro serviço.",
            "A07:2025 Authentication Failures",
            "CWE-345",
        ),
        CheckMeta(
            "claim-no-iss",
            "Sem 'iss' (issuer)",
            Severity.LOW,
            "Inclua e valide 'iss' para amarrar o token ao emissor esperado.",
            "A07:2025 Authentication Failures",
            "CWE-345",
        ),
        CheckMeta(
            "claim-malformed-time",
            "Claim temporal presente mas não numérica",
            Severity.MEDIUM,
            "RFC 7519 §2 define exp/nbf/iat como NumericDate (número de segundos). Uma claim "
            "temporal em string ou objeto faz muito verificador pular a checagem em silêncio "
            "(fail-open) — o token deixa de expirar. Emita NumericDate e rejeite o que não for.",
            "A07:2025 Authentication Failures",
            "CWE-613",
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
            "A01:2025 Broken Access Control",
            "CWE-918",
        ),
        CheckMeta(
            "header-x5u",
            "Cabeçalho 'x5u' (URL de certificado)",
            Severity.HIGH,
            "Idem 'jku': não carregue material de chave de URL controlável pelo emissor do token.",
            "A01:2025 Broken Access Control",
            "CWE-918",
        ),
        CheckMeta(
            "header-jwk",
            "Cabeçalho 'jwk' (chave embutida)",
            Severity.HIGH,
            "Chave pública embutida no token: um atacante fornece a própria chave. Ignore 'jwk' e "
            "use apenas chaves configuradas no servidor.",
            "A07:2025 Authentication Failures",
            "CWE-347",
        ),
        CheckMeta(
            "header-x5c",
            "Cabeçalho 'x5c' (cadeia de certificados embutida)",
            Severity.MEDIUM,
            "Só confie em 'x5c' se validar a cadeia contra uma âncora confiável sua.",
            "A07:2025 Authentication Failures",
            "CWE-347",
        ),
        CheckMeta(
            "header-kid-injection",
            "'kid' com caracteres perigosos",
            Severity.HIGH,
            "Trate 'kid' como identificador opaco. Nunca o use em caminho de arquivo ou SQL — "
            "é vetor de path traversal / injeção.",
            "A05:2025 Injection",
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
            "header-zip-jws",
            "'zip' (compressão) num JWS de 3 segmentos",
            Severity.HIGH,
            "O parâmetro 'zip' só é válido em JWE (RFC 7516); num JWS (token de 3 segmentos) viola o "
            "RFC 7515. Bibliotecas que descomprimem o payload ANTES de verificar a assinatura ficam "
            "expostas a DoS por descompressão sem conhecer chave nenhuma (o caso do Apache James). "
            "Rejeite tokens com 'zip' fora de JWE e limite o tamanho do payload descomprimido.",
            "A06:2025 Insecure Design",
            "CWE-409",
        ),
        CheckMeta(
            "header-cty-nested",
            "JWT aninhado declarado ('cty: JWT')",
            Severity.MEDIUM,
            "JWT aninhado (RFC 7519 §5.2): o payload da casca deveria ser outro JWT. Verifique a "
            "assinatura das DUAS camadas, com allowlist de algoritmos em cada uma; nunca confie no "
            "token interno sem validá-lo (assinatura, alg, exp, aud/iss).",
            "A07:2025 Authentication Failures",
            "CWE-347",
        ),
        CheckMeta(
            "payload-nested-jwt",
            "Payload aparenta conter outro JWT",
            Severity.LOW,
            "Uma claim carrega o que parece ser outro JWT. Se um token embute outro, valide o token "
            "interno com o mesmo rigor da casca antes de confiar nele — não o repasse como confiável.",
            "A07:2025 Authentication Failures",
            "CWE-347",
        ),
        CheckMeta(
            "payload-sensitive",
            "Dado sensível no payload",
            Severity.MEDIUM,
            "O payload de um JWT é apenas base64 — não é cifrado. Não coloque segredos nem dados "
            "pessoais (LGPD) nele; use JWE se precisar de confidencialidade.",
            "A04:2025 Cryptographic Failures",
            "CWE-522",
        ),
        # --- JWE (RFC 7516) — cabeçalho protegido, sem decifrar nada ---------
        CheckMeta(
            "jwe-alg-rsa15",
            "Gerenciamento de chave 'RSA1_5' (sem OAEP)",
            Severity.HIGH,
            "Migre para 'RSA-OAEP' ou 'RSA-OAEP-256'. RSAES-PKCS1-v1_5 é o mecanismo do ataque de "
            "oráculo de padding de Bleichenbacher — a RFC 8725 (JOSE BCP) recomenda evitá-lo.",
            "A04:2025 Cryptographic Failures",
            "CWE-780",
        ),
        CheckMeta(
            "jwe-alg-unknown",
            "Algoritmo de gerenciamento de chave (alg) não reconhecido",
            Severity.MEDIUM,
            "Aceite apenas os algoritmos de gerenciamento de chave que seu sistema realmente usa "
            "(allowlist) — um valor fora do esperado deixa a verificação ambígua.",
            "A04:2025 Cryptographic Failures",
            "CWE-327",
        ),
        CheckMeta(
            "jwe-enc-unknown",
            "Algoritmo de conteúdo (enc) não reconhecido",
            Severity.MEDIUM,
            "Aceite apenas os algoritmos de cifra de conteúdo que seu sistema realmente usa "
            "(allowlist, ex. A256GCM) — um valor fora do esperado deixa a verificação ambígua.",
            "A04:2025 Cryptographic Failures",
            "CWE-327",
        ),
        CheckMeta(
            "jwe-p2c-abusive",
            "Contagem de iterações PBES2 ('p2c') abusiva",
            Severity.HIGH,
            "Rejeite tokens com 'p2c' acima de um teto fixo antes de tentar derivar a chave. "
            "'p2c' é escolhido por quem EMITE o token e pago por quem VERIFICA a cada tentativa, "
            "antes de qualquer autenticação — o mecanismo exato do ataque de 'Billion Hash'.",
            "A06:2025 Insecure Design",
            "CWE-400",
        ),
        CheckMeta(
            "jwe-zip-dos",
            "'zip: DEF' comprime o plaintext antes de cifrar",
            Severity.MEDIUM,
            "Limite o tamanho do conteúdo descomprimido no verificador. 'zip' comprime antes de "
            "cifrar; ao decifrar, quem verifica descomprime sem saber de antemão o tamanho final — "
            "brecha de exaustão de memória/CPU (zip bomb) sem precisar de chave nenhuma.",
            "A06:2025 Insecure Design",
            "CWE-409",
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
