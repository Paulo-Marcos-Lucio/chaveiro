"""Checagem passiva de prova DPoP (RFC 9449) — ``validate_dpop``.

Uma prova DPoP é, na forma, um JWS compacto — mas o que ela precisa carregar é
diferente de um access/id token: cabeçalho com ``typ: dpop+jwt``, ``alg``
assimétrico e a chave PÚBLICA do par em ``jwk``; payload com ``jti``/``htm``/
``htu``/``iat``. As checagens de ``checks/detectors.py`` (pensadas para JWT
comum) não cobrem essa semântica, daí um módulo dedicado.

Além da prova isolada, ``validate_dpop_binding`` audita o par prova+access
token: ``ath`` (RFC 9449 §4.2 — hash do access token) e ``cnf.jkt`` (RFC 9449
§6.1 + RFC 7800 — thumbprint RFC 7638 da chave pública da prova, carimbado no
próprio access token). Essas duas claims são o que amarra a prova a UM access
token específico; sem elas, uma prova capturada serve para qualquer token.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from chaveiro.checks.catalog import CheckMeta
from chaveiro.core.jwt import JWTError, b64url_encode, decode
from chaveiro.core.models import DecodedToken, Finding, Severity

# Catálogo próprio — não entra em ``checks.catalog.CATALOG`` de propósito: aquele
# catálogo é consumido só por ``run_all`` (JWT comum) e o meta-teste
# ``test_toda_checagem_do_catalogo_tem_caso_positivo`` exige que CADA id ali
# apareça num caso que passa por ``run_all``. Uma prova DPoP nunca passa por
# ``run_all`` — é outro tipo de token, auditado por ``validate_dpop`` — então
# compartilhar o dict misturaria dois universos de cobertura.
DPOP_CATALOG: dict[str, CheckMeta] = {
    m.id: m
    for m in [
        CheckMeta(
            "dpop-typ-wrong",
            "Prova DPoP com 'typ' diferente de 'dpop+jwt'",
            Severity.HIGH,
            "RFC 9449 §4.2 exige 'typ: dpop+jwt' no cabeçalho. Sem isso, nada distingue a prova "
            "DPoP de um JWT comum — um access token pode ser replayado como se fosse prova.",
            "A07:2025 Authentication Failures",
            "CWE-347",
        ),
        CheckMeta(
            "dpop-alg-symmetric",
            "Prova DPoP assinada com algoritmo simétrico ou 'none'",
            Severity.CRITICAL,
            "A prova DPoP tem de usar um algoritmo assimétrico: o cabeçalho carrega a chave "
            "PÚBLICA em 'jwk' para o servidor verificar a posse da privada. HMAC/'none' anulam a "
            "prova de posse — qualquer um que leia a chave 'pública' forja a assinatura.",
            "A07:2025 Authentication Failures",
            "CWE-347",
        ),
        CheckMeta(
            "dpop-jwk-missing",
            "Prova DPoP sem cabeçalho 'jwk'",
            Severity.HIGH,
            "RFC 9449 §4.2 exige a chave pública do par em 'jwk'. Sem ela, o servidor não tem "
            "como verificar a assinatura nem amarrar a prova à chave do cliente.",
            "A07:2025 Authentication Failures",
            "CWE-347",
        ),
        CheckMeta(
            "dpop-jwk-private",
            "Cabeçalho 'jwk' da prova DPoP expõe componente de chave privada",
            Severity.CRITICAL,
            "'jwk' deve conter só a chave PÚBLICA. A presença de 'd' (EC/OKP/RSA) ou dos "
            "parâmetros CRT de RSA ('p'/'q'/'dp'/'dq'/'qi') vaza a chave privada no próprio "
            "cabeçalho — qualquer verificador que leia o token aprende o segredo.",
            "A07:2025 Authentication Failures",
            "CWE-522",
        ),
        CheckMeta(
            "dpop-no-jti",
            "Prova DPoP sem claim 'jti'",
            Severity.HIGH,
            "'jti' identifica a prova para o servidor detectar reuso (replay). Sem ela, a mesma "
            "prova pode ser reapresentada sem que nada a torne reconhecível.",
            "A07:2025 Authentication Failures",
            "CWE-294",
        ),
        CheckMeta(
            "dpop-no-htm",
            "Prova DPoP sem claim 'htm'",
            Severity.HIGH,
            "'htm' amarra a prova ao método HTTP da requisição. Sem ela, a mesma prova serve "
            "para qualquer verbo — ex.: uma prova de GET reaproveitada num DELETE.",
            "A07:2025 Authentication Failures",
            "CWE-290",
        ),
        CheckMeta(
            "dpop-no-htu",
            "Prova DPoP sem claim 'htu'",
            Severity.HIGH,
            "'htu' amarra a prova à URI da requisição. Sem ela, a mesma prova serve para "
            "qualquer endpoint que aceite o mesmo access token.",
            "A07:2025 Authentication Failures",
            "CWE-290",
        ),
        CheckMeta(
            "dpop-no-iat",
            "Prova DPoP sem claim 'iat'",
            Severity.HIGH,
            "'iat' é o que permite ao servidor rejeitar prova velha fora de uma janela de "
            "frescor. Sem ela, uma prova capturada vale para sempre.",
            "A07:2025 Authentication Failures",
            "CWE-613",
        ),
        CheckMeta(
            "dpop-htu-query",
            "'htu' da prova DPoP inclui query string ou fragmento",
            Severity.MEDIUM,
            "RFC 9449 §4.2 define 'htu' sem query nem fragmento. Incluí-los cria ambiguidade "
            "entre o que o auditor lê e o que cada verificador compara — normalize 'htu' para "
            "esquema+autoridade+caminho antes de comparar.",
            "A07:2025 Authentication Failures",
            "CWE-20",
        ),
        CheckMeta(
            "dpop-iat-window",
            "'iat' da prova DPoP fora da janela de frescor aceitável",
            Severity.MEDIUM,
            "Uma prova com 'iat' muito no passado ou no futuro não deveria ser aceita — valide "
            "'iat' contra uma janela curta e configurável para limitar o réplay.",
            "A07:2025 Authentication Failures",
            "CWE-294",
        ),
        # --- Binding prova↔access token — checks/dpop.py::validate_dpop_binding --- #
        CheckMeta(
            "dpop-ath-missing",
            "Prova DPoP sem 'ath' ao ser usada com um access token",
            Severity.HIGH,
            "'ath' amarra a prova a UM access token (RFC 9449 §4.2). Sem ela, a mesma prova "
            "serve para apresentar qualquer access token que o cliente possua.",
            "A07:2025 Authentication Failures",
            "CWE-290",
        ),
        CheckMeta(
            "dpop-ath-mismatch",
            "'ath' da prova DPoP não corresponde ao access token apresentado",
            Severity.CRITICAL,
            "'ath' deve ser o SHA-256 (base64url) do access token efetivamente usado. Um valor "
            "divergente é prova de reuso: esta prova foi gerada para outro access token.",
            "A07:2025 Authentication Failures",
            "CWE-290",
        ),
        CheckMeta(
            "dpop-access-token-opaque",
            "Access token não decodifica como JWT — binding 'cnf.jkt' não verificável",
            Severity.INFO,
            "Informativo: token de referência (opaco) é válido por desenho (RFC 9449 não exige "
            "JWT), mas a verificação de 'cnf.jkt' por este auditor exige um access token JWT.",
            None,
            None,
        ),
        CheckMeta(
            "dpop-cnf-missing",
            "Access token (JWT) sem claim 'cnf' — binding por chave não verificável",
            Severity.INFO,
            "Informativo: sem 'cnf' não há como confirmar aqui que o access token está amarrado "
            "à chave da prova. Pode ser intencional (binding resolvido no introspection).",
            None,
            None,
        ),
        CheckMeta(
            "dpop-jkt-missing",
            "Access token com 'cnf' mas sem 'jkt'",
            Severity.MEDIUM,
            "'cnf' sem 'jkt' (RFC 7800/RFC 9449 §6.1) não amarra o access token a nenhuma chave "
            "— a confirmação de posse fica incompleta.",
            "A07:2025 Authentication Failures",
            "CWE-290",
        ),
        CheckMeta(
            "dpop-jkt-unsupported-kty",
            "Thumbprint RFC 7638 não calculável para o 'kty' do 'jwk' da prova",
            Severity.LOW,
            "Informativo/limitação: este auditor calcula o thumbprint para RSA/EC/OKP/oct "
            "(RFC 7638 + extensão de fato para OKP/oct). Confirme o binding manualmente.",
            None,
            None,
        ),
        CheckMeta(
            "dpop-jkt-mismatch",
            "'cnf.jkt' do access token não corresponde à chave da prova DPoP",
            Severity.CRITICAL,
            "O thumbprint RFC 7638 do 'jwk' da prova diverge do 'cnf.jkt' do access token: este "
            "access token não está amarrado à chave que assinou esta prova.",
            "A07:2025 Authentication Failures",
            "CWE-290",
        ),
    ]
}


def _make_finding(check_id: str, detail: str, *, evidence: str | None = None) -> Finding:
    meta = DPOP_CATALOG[check_id]
    return Finding(
        check_id=meta.id,
        title=meta.title,
        severity=meta.severity,
        detail=detail,
        recommendation=meta.recommendation,
        cwe=meta.cwe,
        owasp=meta.owasp,
        evidence=evidence,
    )


_DPOP_TYP = "dpop+jwt"
_SYMMETRIC_OR_NONE_ALGS = {"HS256", "HS384", "HS512", "none"}
# RFC 7518 §6.3.2 (RSA) e §6.2.2 (EC)/RFC 8037 (OKP): qualquer uma destas chaves
# só existe na forma PRIVADA do JWK. 'd' cobre EC/OKP/RSA; as demais são os
# parâmetros CRT opcionais de RSA.
_PRIVATE_JWK_KEYS = {"d", "p", "q", "dp", "dq", "qi"}
_REQUIRED_CLAIMS: tuple[tuple[str, str], ...] = (
    ("jti", "dpop-no-jti"),
    ("htm", "dpop-no-htm"),
    ("htu", "dpop-no-htu"),
    ("iat", "dpop-no-iat"),
)
# RFC 9449 não fixa um número: recomenda uma janela curta e deixa a critério do
# servidor. 60s é um piso comum de referência (clock skew + latência de rede).
DEFAULT_IAT_WINDOW_S = 60


def _alg_normalizado(alg: Any) -> str | None:
    if not isinstance(alg, str):
        return None
    return alg.strip()


def _checar_typ(header: dict[str, Any]) -> list[Finding]:
    typ = header.get("typ")
    if typ == _DPOP_TYP:
        return []
    return [
        _make_finding(
            "dpop-typ-wrong",
            f"Cabeçalho 'typ' é {typ!r}, esperado {_DPOP_TYP!r}.",
            evidence=f"typ={typ!r}",
        )
    ]


def _checar_alg(header: dict[str, Any]) -> list[Finding]:
    alg = _alg_normalizado(header.get("alg"))
    if alg is not None and alg not in _SYMMETRIC_OR_NONE_ALGS:
        return []
    return [
        _make_finding(
            "dpop-alg-symmetric",
            f"'alg' é {header.get('alg')!r} — DPoP exige algoritmo assimétrico.",
            evidence=f"alg={header.get('alg')!r}",
        )
    ]


def _checar_jwk(header: dict[str, Any]) -> list[Finding]:
    jwk = header.get("jwk")
    if not isinstance(jwk, dict):
        return [_make_finding("dpop-jwk-missing", "Cabeçalho 'jwk' ausente ou não é objeto.")]
    vazados = sorted(_PRIVATE_JWK_KEYS & jwk.keys())
    if not vazados:
        return []
    return [
        _make_finding(
            "dpop-jwk-private",
            f"'jwk' carrega componente(s) de chave privada: {', '.join(vazados)}.",
            evidence=f"jwk contém {vazados}",
        )
    ]


def _checar_claims_obrigatorias(payload: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for claim, check_id in _REQUIRED_CLAIMS:
        if claim not in payload:
            findings.append(_make_finding(check_id, f"Claim '{claim}' ausente no payload."))
    return findings


def _checar_htu(payload: dict[str, Any]) -> list[Finding]:
    htu = payload.get("htu")
    if not isinstance(htu, str) or not ("?" in htu or "#" in htu):
        return []
    return [
        _make_finding(
            "dpop-htu-query",
            f"'htu' inclui query string ou fragmento: {htu!r}.",
            evidence=f"htu={htu!r}",
        )
    ]


def _checar_iat_janela(payload: dict[str, Any], now: int, window_s: int) -> list[Finding]:
    iat = payload.get("iat")
    if not isinstance(iat, (int, float)) or isinstance(iat, bool):
        return []
    delta = now - iat
    if -window_s <= delta <= window_s:
        return []
    direcao = "no futuro" if delta < 0 else "no passado"
    return [
        _make_finding(
            "dpop-iat-window",
            f"'iat' está {abs(delta):.0f}s {direcao}, fora da janela de {window_s}s.",
            evidence=f"iat={iat!r}, now={now}, janela={window_s}s",
        )
    ]


def validate_dpop(
    token: DecodedToken, now: int, iat_window_s: int = DEFAULT_IAT_WINDOW_S
) -> list[Finding]:
    """Audita uma prova DPoP (RFC 9449) já decodificada — sem verificar assinatura.

    ``now`` e ``iat_window_s`` seguem a mesma unidade (segundos desde a época).
    """
    findings: list[Finding] = []
    findings += _checar_typ(token.header)
    findings += _checar_alg(token.header)
    findings += _checar_jwk(token.header)
    findings += _checar_claims_obrigatorias(token.payload)
    findings += _checar_htu(token.payload)
    findings += _checar_iat_janela(token.payload, now, iat_window_s)
    return findings


# --------------------------------------------------------------------------- #
# Binding prova↔access token: 'ath' (RFC 9449 §4.2) e 'cnf.jkt' (RFC 9449
# §6.1 + RFC 7800, thumbprint RFC 7638).
# --------------------------------------------------------------------------- #

# RFC 7638 §3.2: só os membros "obrigatórios" do JWK entram no thumbprint, em
# ordem lexicográfica. OKP (RFC 8037) e 'oct' (simétrico) não têm thumbprint
# formalizado em RFC — a extensão (crv+kty+x; k+kty) segue a mesma receita e é
# prática comum (ex.: bibliotecas JOSE maduras), mas não é um RFC à parte.
_THUMBPRINT_MEMBERS: dict[str, tuple[str, ...]] = {
    "RSA": ("e", "kty", "n"),
    "EC": ("crv", "kty", "x", "y"),
    "OKP": ("crv", "kty", "x"),
    "oct": ("k", "kty"),
}


def jwk_thumbprint(jwk: dict[str, Any]) -> str | None:
    """Thumbprint RFC 7638 de um JWK — ``None`` se o 'kty' não é suportado ou os
    membros obrigatórios não são todos strings (JWK malformado)."""
    kty = jwk.get("kty")
    members = _THUMBPRINT_MEMBERS.get(kty) if isinstance(kty, str) else None
    if members is None or not all(isinstance(jwk.get(m), str) for m in members):
        return None
    canonical = json.dumps({m: jwk[m] for m in members}, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    return b64url_encode(digest)


def compute_ath(access_token: str) -> str:
    """'ath' (RFC 9449 §4.2): SHA-256 base64url do access token, como STRING crua —
    funciona tanto para access token JWT quanto opaco."""
    digest = hashlib.sha256(access_token.encode("utf-8")).digest()
    return b64url_encode(digest)


def _checar_ath(payload: dict[str, Any], access_token: str) -> list[Finding]:
    ath = payload.get("ath")
    if ath is None:
        return [_make_finding("dpop-ath-missing", "Claim 'ath' ausente no payload da prova.")]
    esperado = compute_ath(access_token)
    if ath == esperado:
        return []
    return [
        _make_finding(
            "dpop-ath-mismatch",
            f"'ath'={ath!r} não corresponde ao SHA-256 do access token apresentado.",
            evidence=f"ath={ath!r}, esperado={esperado!r}",
        )
    ]


def _checar_jkt(jwk: Any, access_token: str) -> list[Finding]:
    try:
        at_decoded = decode(access_token)
    except JWTError:
        return [
            _make_finding(
                "dpop-access-token-opaque",
                "Access token não decodifica como JWT — 'cnf.jkt' não verificável.",
            )
        ]
    cnf = at_decoded.payload.get("cnf")
    if not isinstance(cnf, dict):
        return [
            _make_finding("dpop-cnf-missing", "Access token (JWT) não tem claim 'cnf' no payload.")
        ]
    jkt = cnf.get("jkt")
    if jkt is None:
        return [_make_finding("dpop-jkt-missing", "'cnf' do access token não tem 'jkt'.")]
    kty = jwk.get("kty") if isinstance(jwk, dict) else None
    thumbprint = jwk_thumbprint(jwk) if isinstance(jwk, dict) else None
    if thumbprint is None:
        return [
            _make_finding(
                "dpop-jkt-unsupported-kty",
                f"Não calculei o thumbprint do 'jwk' da prova (kty={kty!r}) para comparar "
                "com 'cnf.jkt'.",
            )
        ]
    if jkt == thumbprint:
        return []
    return [
        _make_finding(
            "dpop-jkt-mismatch",
            f"'cnf.jkt'={jkt!r} do access token não bate com o thumbprint {thumbprint!r} "
            "do 'jwk' da prova.",
            evidence=f"jkt={jkt!r}, thumbprint={thumbprint!r}",
        )
    ]


def validate_dpop_binding(token: DecodedToken, access_token: str) -> list[Finding]:
    """Audita o binding de uma prova DPoP a UM access token: 'ath' (RFC 9449 §4.2)
    e 'cnf.jkt' (RFC 9449 §6.1), quando o access token é um JWT."""
    findings: list[Finding] = []
    findings += _checar_ath(token.payload, access_token)
    findings += _checar_jkt(token.header.get("jwk"), access_token)
    return findings
