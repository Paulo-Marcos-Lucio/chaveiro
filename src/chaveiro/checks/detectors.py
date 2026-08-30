"""As checagens em si — passivas, sobre um token já decodificado."""

from __future__ import annotations

import json
import math
import re
import unicodedata
import urllib.parse
from collections.abc import Iterator
from typing import Any

from chaveiro.checks.catalog import make_finding
from chaveiro.core.jwt import JWTError, b64url_decode, decode, looks_like_jws
from chaveiro.core.models import DecodedToken, Finding

_KNOWN_ALGS = {
    "HS256", "HS384", "HS512",
    "RS256", "RS384", "RS512",
    "ES256", "ES384", "ES512", "ES256K",
    "PS256", "PS384", "PS512",
    "EdDSA",
}  # fmt: skip
# Caracteres de largura zero / BOM: NAO sao whitespace para str.strip(), entao
# 'none\u200b' escapava do alg-none. Homoglifo (cirilico 'o') NAO entra aqui de
# proposito: e uma string diferente que um verificador tambem rejeita (nao e bypass).
_ZERO_WIDTH = ("\u200b", "\u200c", "\u200d", "\ufeff", "\u2060", "\u00a0")
_HMAC_ALGS = {"HS256", "HS384", "HS512"}
_LONG_LIFETIME_S = 24 * 3600
# Acima disso um inteiro não cabe em float (`/` estoura ~1.8e308) e o valor já
# não é um NumericDate plausível. ~31 mil anos em segundos — nenhum token real
# chega perto; serve só de para-raios do OverflowError.
_FLOAT_SAFE_SECONDS = 10**12
_SECONDS_PER_YEAR = 365 * 24 * 3600

# Traversal / controle: uma barra SOZINHA nao e traversal (thumbprint base64 do Cognito,
# kid hierarquico, kid como URL do emissor usam '/' legitimamente). So '..' e chars de
# controle sao traversal. Injecao: metacaracteres de shell/SQL/LDAP que um kid legitimo
# nao carrega. FP (kid-b64/url/logico) e FN (A1 percent-encoded, A2 LDAP, A3 SQLi, A4 &&)
# eram os dois lados da mesma classe: blocklist ingenua por caractere.
_KID_TRAVERSAL = ("..", "\x00", "\n", "\r", "\t")
# Metacaracteres de shell/SQL/LDAP/EL. '&' (nao so '&&'), '$', '{' e '}' entram: um kid
# legitimo do corpus nao os carrega, mas '&' encadeia comando, e '${...}' e EL/JNDI (Log4Shell).
_KID_INJECTION = (
    "'", '"', ";", "`", "$(", "<", ">", "(", ")", "*", "&&", "||", "|", "\\", "&", "$", "{", "}"
)  # fmt: skip
_KID_SQL_RE = re.compile(r"(?i)\b(?:or|and)\b\s+[\w']+\s*=\s*[\w']+|\bunion\b|--|/\*|;\s*drop\b")
# Expression Language / JNDI: ${jndi:ldap://...}, ${...}. So os '$' '{' '}' ja marcam, mas o
# padrao explicito documenta a classe e sobrevive a forma percent/NFKC normalizada.
_KID_EL_RE = re.compile(r"\$\{[^}]*\}")
# Caminho ABSOLUTO (nao hierarquico relativo): /etc/passwd, C:\..., \\share. Um kid logico
# ('keys/prod/1') ou URL ('https://...') nao comeca por '/'+segmento nem por drive/UNC.
_KID_ABS_PATH_RE = re.compile(r"(?i)^(?:/[^/]|[a-z]:[\\/]|\\\\)")


def _unquote_ate_ponto_fixo(texto: str, teto: int = 3) -> str:
    """percent-decode em LACO ate estabilizar (double/triple-encoding: %252e -> %2e -> .).
    Teto pequeno porque um kid legitimo nunca muda sob unquote, entao 3 passes bastam."""
    for _ in range(teto):
        decodificado = urllib.parse.unquote(texto)
        if decodificado == texto:
            break
        texto = decodificado
    return texto


def _kid_candidatos(kid: str) -> set[str]:
    """Todas as formas que um verificador pode ENXERGAR do kid: cru, percent-decodificado ate
    ponto-fixo e normalizado NFKC (fullwidth U+FF0E/U+FF0F colapsam para '../'). A blocklist de
    caractere isolada e um single-decode deixavam passar double-encoding, EL e homoglifo largo."""
    formas: set[str] = set()
    for base in (kid, _unquote_ate_ponto_fixo(kid)):
        formas.add(base)
        formas.add(unicodedata.normalize("NFKC", base))  # NFKC de str nunca levanta
    return formas


def _kid_perigoso(kid: str) -> bool:
    """O 'kid' carrega traversal/injecao/caminho absoluto? Avalia TODAS as formas normalizadas
    (percent ate ponto-fixo + NFKC), nao so a crua e um unico unquote."""
    for c in _kid_candidatos(kid):
        if any(t in c for t in _KID_TRAVERSAL):
            return True
        if any(t in c for t in _KID_INJECTION):
            return True
        if _KID_EL_RE.search(c) or _KID_ABS_PATH_RE.search(c) or _KID_SQL_RE.search(c):
            return True
    return False


_TIME_CLAIMS = ("exp", "iat", "nbf")
# Igualdade exata: termos que só são sinal quando são a chave inteira ('token'
# como substring casaria com 'token_type: Bearer', que é ruído de OAuth).
_SENSITIVE_KEYS = {
    "password", "passwd", "pwd", "senha",
    "secret", "client_secret", "api_key", "apikey",
    "token", "access_token", "refresh_token", "private_key",
}  # fmt: skip
# Radicais LONGOS e inequívocos: seguros como substring na chave achatada
# (minúscula, sem separadores) — nenhuma palavra inocente os contém. Pega
# 'user_password', 'x-api-key', 'privateKey'.
_SENSITIVE_PARTS_FLAT = ("password", "passwd", "apikey", "privatekey")
# Radicais CURTOS/ambíguos: só valem como TOKEN inteiro (fronteira de palavra),
# senão a substring achatada casa 'secretaria'/'secretary'/'greatsecret'
# ('secret'), 'resenha'/'desenha'/'senharia' ('senha') e 'pwded' ('pwd').
# Continuam pegando as formas compostas REAIS ('client_secret', 'dbSecret',
# 'senha_usuario', 'pwdHash'), porque elas têm fronteira (separador ou camelCase).
_SENSITIVE_PARTS_TOKEN = ("secret", "senha", "pwd")
_NOT_ALNUM = re.compile(r"[^a-z0-9]")
# Fronteiras de palavra dentro de uma chave: separadores e transições de caixa
# (camelCase) / letra<->dígito. Tokeniza 'dbSecret'->{db,secret},
# 'senha_usuario'->{senha,usuario}, 'APIKey'->{api,key} — sem quebrar
# 'secretaria', que continua um token único (e por isso não casa 'secret').
_KEY_SEP = re.compile(r"[^A-Za-z0-9]+")
_KEY_BOUNDARY = re.compile(
    r"(?<=[a-z0-9])(?=[A-Z])"  # minúscula/dígito -> Maiúscula (camelCase)
    r"|(?<=[A-Z])(?=[A-Z][a-z])"  # fim de acrônimo: 'APIKey' -> 'API' 'Key'
    r"|(?<=[A-Za-z])(?=[0-9])"  # letra -> dígito
    r"|(?<=[0-9])(?=[A-Za-z])"  # dígito -> letra
)
_NOT_DIGIT = re.compile(r"\D")
# CPF nas duas formas de campo: pontuada e 11 dígitos crus. Os dígitos
# verificadores são conferidos depois — sem isso, todo número de 11 dígitos
# (telefone, id) viraria achado de LGPD.
_CPF = re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b|\b\d{11}\b")
# RFC 7515 §4.1.10 / RFC 7519 §5.2: comparação case-insensitive e o prefixo
# "application/" pode ser omitido — "JWT" marca um token aninhado.
_CTY_NESTED = {"jwt", "application/jwt"}


# Teto de profundidade do aninhamento auditado. Nenhum JWT aninhado legitimo passa de poucas
# camadas; o teto + a protecao de ciclo evitam laco infinito numa casca que se auto-referencia.
_MAX_NESTED_DEPTH = 4


def _run_camada(token: DecodedToken, now: int) -> list[Finding]:
    """Bateria COMPLETA de checagens de UMA camada (sem descer no aninhamento — a descida e
    do laco em run_all). Extraida para rodar identica em cada nivel de um JWT aninhado."""
    findings: list[Finding] = []
    findings += check_alg(token)
    findings += check_header(token)
    findings += check_signature(token)
    findings += check_header_duplicates(token)
    findings += check_nesting(token)
    findings += check_claims(token, now)
    findings += check_payload(token)
    return findings


def run_all(token: DecodedToken, now: int) -> list[Finding]:
    findings = _run_camada(token, now)
    # JWT aninhado: as vulnerabilidades moram nas camadas INTERNAS (casca HS256 envolvendo um
    # miolo alg:none a N niveis, com jku/kid/segredo dentro). Auditar so a casca — ou so 1 nivel
    # com check_alg — cega o vetor. Descemos por `token.nested` rodando a bateria COMPLETA em
    # cada camada, com TETO de profundidade e protecao contra ciclo (FN J1 e alem).
    vistos = {token.raw}
    interno_raw = token.nested
    profundidade = 1
    while interno_raw is not None and profundidade <= _MAX_NESTED_DEPTH:
        if interno_raw in vistos:
            break  # ciclo: casca que aponta para uma camada ja vista — para
        vistos.add(interno_raw)
        try:
            interno = decode(interno_raw)
        except JWTError:
            break
        findings += _run_camada(interno, now)
        interno_raw = interno.nested
        profundidade += 1
    return findings


def _alg_normalizado(alg: Any) -> str | None:
    """Forma do 'alg' para COMPARACAO: sem espaco nas pontas e sem caracteres de largura zero
    no meio — a mesma leniencia que muitas libs aplicam. None quando 'alg' nao e string; o valor
    CRU permanece na evidencia. Fonte UNICA: check_alg e check_signature usam esta mesma funcao,
    para 'none'+largura-zero ser reconhecido como none nas DUAS (senao vinha alg-none E um
    signature-empty espurio com mensagem enganosa)."""
    if not isinstance(alg, str):
        return None
    normalized = alg.strip()
    for zw in _ZERO_WIDTH:
        normalized = normalized.replace(zw, "")
    return normalized.strip()


def check_signature(token: DecodedToken) -> list[Finding]:
    """Assinatura vazia num algoritmo de ASSINATURA = efetivamente nao assinado (FN D1/D2)."""
    alg = token.header.get("alg")
    normalized = _alg_normalizado(alg)
    if normalized is not None and normalized.lower() == "none":
        return []  # 'none' (inclusive com largura-zero) ja e coberto por alg-none
    if token.signature == b"":
        return [
            make_finding(
                "signature-empty",
                "A assinatura (3o segmento) esta vazia, mas 'alg' declara um algoritmo de "
                "assinatura. Um verificador leniente pode aceitar o token como assinado.",
                evidence=f"alg={alg!r}, assinatura=<vazia>",
            )
        ]
    return []


def _header_primeira_ocorrencia(raw_token: str) -> tuple[dict[str, Any], set[str]]:
    """Reparse do cabecalho preservando a PRIMEIRA ocorrencia de cada chave e coletando as
    repetidas. json.loads fica com a ULTIMA; parsers first-wins ficam com a primeira — a
    diferenca e o ataque (FN F1/F2)."""
    repetidas: set[str] = set()

    def _first_wins(pares: list[tuple[str, Any]]) -> dict[str, Any]:
        d: dict[str, Any] = {}
        for k, v in pares:
            if k in d:
                repetidas.add(k)
            else:
                d[k] = v
        return d

    seg = raw_token.split(".", 1)[0]
    dados = json.loads(b64url_decode(seg), object_pairs_hook=_first_wins)
    return (dados if isinstance(dados, dict) else {}), repetidas


def check_header_duplicates(token: DecodedToken) -> list[Finding]:
    """Chave de cabecalho repetida: parser-differential. Avalia tambem a interpretacao
    first-wins (que json.loads descartou) para alg/kid — a mais perigosa das duas vence."""
    out: list[Finding] = []
    try:
        primeiro, repetidas = _header_primeira_ocorrencia(token.raw)
    except (JWTError, ValueError):
        return out
    if not repetidas:
        return out
    out.append(
        make_finding(
            "header-duplicate-key",
            f"O cabecalho repete a(s) chave(s) {sorted(repetidas)!r}. Parsers divergem sobre "
            "qual valor vale (primeiro x ultimo) — um atacante explora a diferenca.",
            evidence=f"repetidas={sorted(repetidas)!r}",
        )
    )
    alg_primeiro = primeiro.get("alg")
    if isinstance(alg_primeiro, str) and alg_primeiro.strip().lower() == "none":
        out.append(
            make_finding(
                "alg-none",
                "Sob interpretacao first-wins do cabecalho duplicado, 'alg' e 'none' — token "
                "nao assinado para uma parte dos verificadores.",
                evidence=f"alg(primeiro)={alg_primeiro!r}",
            )
        )
    kid_primeiro = primeiro.get("kid")
    if isinstance(kid_primeiro, str) and _kid_perigoso(kid_primeiro):
        out.append(
            make_finding(
                "header-kid-injection",
                "Sob interpretacao first-wins do cabecalho duplicado, o 'kid' contem traversal/injecao.",
                evidence=f"kid(primeiro)={kid_primeiro!r}",
            )
        )
    return out


def check_alg(token: DecodedToken) -> list[Finding]:
    out: list[Finding] = []
    alg = token.header.get("alg")
    if not isinstance(alg, str) or alg.strip() == "":
        out.append(make_finding("alg-missing", "O cabeçalho não declara 'alg'."))
        return out
    # Espaço/tabulação/largura-zero em volta do valor não muda a intenção: 'none ',
    # '\tNoNe', 'none​' e 'HS256 ' são o mesmo algoritmo para um verificador
    # leniente (muitas libs fazem strip). Comparamos pela forma normalizada — mantendo
    # o valor cru na evidência — senão 'alg: none ' escaparia do CRÍTICO para o MÉDIO de
    # alg-unknown. Mesma normalização de check_signature (fonte única _alg_normalizado).
    normalized = _alg_normalizado(alg) or ""
    if normalized.lower() == "none":
        out.append(
            make_finding(
                "alg-none",
                "O token declara 'alg: none' — não há assinatura. Qualquer um pode forjar claims "
                "se o verificador aceitar tokens não assinados.",
                evidence=f"alg={alg!r}",
            )
        )
        return out
    if normalized not in _KNOWN_ALGS:
        out.append(
            make_finding("alg-unknown", f"Algoritmo não reconhecido: {alg!r}.", evidence=alg)
        )
    elif normalized in _HMAC_ALGS:
        out.append(
            make_finding(
                "alg-hmac-advisory",
                f"Token assinado com {alg} (segredo compartilhado).",
                evidence=alg,
            )
        )
    return out


def check_header(token: DecodedToken) -> list[Finding]:
    out: list[Finding] = []
    header = token.header
    for field_name, check_id in (("jku", "header-jku"), ("x5u", "header-x5u")):
        if field_name in header:
            out.append(
                make_finding(
                    check_id,
                    f"'{field_name}' aponta para material de chave externo.",
                    evidence=str(header[field_name])[:200],
                )
            )
    if "jwk" in header:
        out.append(make_finding("header-jwk", "Chave pública embutida no próprio token ('jwk')."))
    if "x5c" in header:
        out.append(make_finding("header-x5c", "Cadeia de certificados embutida ('x5c')."))
    if "crit" in header:
        out.append(make_finding("header-crit", f"Extensões críticas: {header['crit']!r}."))
    if "zip" in header:
        # O token que chega aqui é sempre um JWS compacto de 3 segmentos (o parser rejeita
        # o resto). 'zip' só é válido em JWE (RFC 7516); num JWS é violação de RFC e o vetor
        # de DoS por descompressão pré-verificação (Apache James descomprimia antes de checar
        # a assinatura). Detectável offline, sem tocar a rede, só lendo o header.
        out.append(
            make_finding(
                "header-zip-jws",
                "O cabeçalho declara 'zip' (compressão) num token de 3 segmentos (JWS). "
                "'zip' só é válido em JWE; aqui viola o RFC 7515 e abre DoS por descompressão "
                "se o verificador descomprime antes de checar a assinatura.",
                evidence=f"zip={header['zip']!r}",
            )
        )
    kid = header.get("kid")
    if isinstance(kid, str) and _kid_perigoso(kid):
        out.append(
            make_finding(
                "header-kid-injection",
                "O 'kid' contém caracteres típicos de path traversal ou injeção.",
                evidence=f"kid={kid!r}",
            )
        )
    return out


def check_nesting(token: DecodedToken) -> list[Finding]:
    """Sinaliza o vetor de JWT confusion por aninhamento (cty / token embutido).

    Passiva: observa que o cabeçalho declara um JWT aninhado ('cty: JWT'), que o
    payload da casca **é** outro JWS compacto (aninhamento real, RFC 7519 §5.2)
    e/ou que alguma claim carrega o que aparenta ser outro JWT. Não valida
    assinatura nem faz rede — só aponta a superfície de confusão.
    """
    out: list[Finding] = []
    cty = token.header.get("cty")
    if isinstance(cty, str) and cty.strip().lower() in _CTY_NESTED:
        out.append(
            make_finding(
                "header-cty-nested",
                "O cabeçalho declara 'cty' de JWT aninhado — o payload deveria ser outro JWT. "
                "Um verificador que valida só a casca e confia no miolo sem checá-lo é enganável.",
                evidence=f"cty={cty!r}",
            )
        )
    if token.nested is not None:
        out.append(
            make_finding(
                "payload-nested-jwt",
                "O payload desta casca É outro JWS compacto (JWT aninhado, RFC 7519 §5.2): as "
                "claims estão no token interno. Audite o token interno separadamente — a casca "
                "sozinha não diz nada sobre expiração, emissor ou destinatário.",
                evidence=f"payload = JWS compacto de {len(token.nested)} caracteres",
            )
        )
    for key, value in token.payload.items():
        if isinstance(value, str) and looks_like_jws(value):
            out.append(
                make_finding(
                    "payload-nested-jwt",
                    f"A claim {key!r} contém o que aparenta ser outro JWT (token aninhado).",
                    evidence=f"{key}=<jwt>",
                )
            )
    return out


def check_claims(token: DecodedToken, now: int) -> list[Finding]:
    out: list[Finding] = []
    payload = token.payload
    if token.nested is not None:
        # Casca de JWT aninhado: as claims vivem no token interno. Cobrar
        # 'exp'/'aud'/'iss' da casca produziria quatro achados falsos.
        return out
    exp = _as_epoch(payload.get("exp"))
    iat = _as_epoch(payload.get("iat"))
    nbf = _as_epoch(payload.get("nbf"))

    for name in _TIME_CLAIMS:
        if name in payload and _as_epoch(payload[name]) is None:
            out.append(
                make_finding(
                    "claim-malformed-time",
                    f"A claim {name!r} existe mas não é um NumericDate (RFC 7519 §2). Muitos "
                    f"verificadores tratam claim temporal inválida como AUSENTE e seguem em "
                    f"frente — o token deixa de expirar.",
                    evidence=f"{name}={str(payload[name])[:60]!r}",
                )
            )

    if "exp" not in payload:
        out.append(make_finding("claim-no-exp", "O token não tem 'exp' — nunca expira."))
    elif exp is not None and exp < now:
        out.append(make_finding("claim-expired", f"'exp' já passou (exp={exp}, agora={now})."))

    # Sem 'iat' a vida útil é aproximada por 'agora': um token de 10 anos sem
    # 'iat' é MAIS perigoso, e era justo aí que a checagem se desligava.
    # Refresh token (Keycloak: typ=Refresh) tem vida longa POR DESIGN — nao e achado.
    # Mas 'typ' e um campo SELF-ASSERTED, nao autenticado: um access token de 30d com
    # scope:admin nao vira refresh so por declarar typ=Refresh. So suprimimos quando NAO
    # ha sinais de access token (scope/scp/azp). Havendo sinal de acesso, NAO suprime.
    typ = str(token.header.get("typ", "")).strip().lower()
    tem_sinais_de_acesso = any(k in payload for k in ("scope", "scp", "azp"))
    typ_diz_refresh = (
        typ in ("refresh", "refresh+jwt") or str(payload.get("typ", "")).lower() == "refresh"
    )
    e_refresh = typ_diz_refresh and not tem_sinais_de_acesso
    if exp is not None and not e_refresh:
        base = "exp - iat" if iat is not None else "exp - agora, sem 'iat'"
        lifetime = exp - iat if iat is not None else exp - now
        if lifetime > _LONG_LIFETIME_S:
            out.append(
                make_finding(
                    "claim-long-lifetime", f"Validade de {_humanize_seconds(lifetime)} ({base})."
                )
            )

    if "iat" not in payload:
        out.append(make_finding("claim-no-iat", "Sem 'iat'."))
    if "aud" not in payload:
        out.append(make_finding("claim-no-aud", "Sem 'aud'."))
    if "iss" not in payload:
        out.append(make_finding("claim-no-iss", "Sem 'iss'."))
    if nbf is not None and nbf > now:
        out.append(make_finding("claim-nbf-future", f"'nbf' no futuro (nbf={nbf}, agora={now})."))
    # iat no futuro (alem de uma folga de relogio) = token pre-datado (FN C1).
    if iat is not None and iat > now + 300:
        out.append(make_finding("claim-iat-future", f"'iat' no futuro (iat={iat}, agora={now})."))
    return out


def check_payload(token: DecodedToken) -> list[Finding]:
    """Procura segredo e dado pessoal em **qualquer profundidade** do payload.

    `{"user": {"cpf": ...}}` é a forma mais comum de payload JWT no Brasil, então
    varrer só o primeiro nível seria falso negativo na forma que mais aparece.

    Duas lentes complementares:
      (1) SINAL DO VALOR — uma credencial reconhecivel (AKIA/sk-/ghp_/xox/AIza, PEM, URL com
          userinfo ou webhook Slack/Discord, presigned AWS) vale por si, em QUALQUER chave —
          ate sob chave de metadata como 'api_key_url';
      (2) CONTEXTO DA CHAVE — sob uma chave sensivel NAO-metadata, strings (que nao sejam
          placeholder) e numeros sob chave-nucleo sao segredo, descendo em listas/dicts.
    A exclusao de metadata/placeholder/URL-simples permanece — a re-inclusao e por sinal, nao
    por afrouxar o gate (que era a regressao: segredo-URL, numerico, lista e chave-metadata).
    """
    out: list[Finding] = []
    for path, key, value, sob in _walk_com_contexto(token.payload):
        e_segredo = (isinstance(value, str) and _valor_tem_assinatura_de_credencial(value)) or (
            sob and _folha_parece_segredo(key, value)
        )
        if e_segredo:
            out.append(
                make_finding(
                    "payload-sensitive",
                    f"A claim {path!r} parece carregar um segredo em texto claro.",
                    evidence=f"{path}=…",
                )
            )
        elif isinstance(value, str) and has_cpf(value):
            out.append(
                make_finding(
                    "payload-sensitive",
                    f"A claim {path!r} contém um CPF (dado pessoal — LGPD) no payload.",
                    evidence=f"{path}=<cpf>",
                )
            )
    return out


# Sufixos/prefixos de METADADO sobre auth: a claim descreve o segredo, nao O e. `pwd_exp`
# (expiracao), `password_changed_at` (timestamp), `has_password` (flag), `password_policy`
# (objeto), `pwdLastSet` (AD), `pwd_url` (URL) sao metadados, nao credencial em claro (FP).
_META_SUFIXOS = (
    "_exp", "_at", "_url", "_uri", "_link", "_policy", "_changed", "lastset", "last_set",
    "_count", "_expires", "_updated", "_ts", "_time", "_date", "_version", "_id", "_len",
)  # fmt: skip
_META_PREFIXOS = ("has_", "is_", "can_", "num_", "n_")
# Chaves de credencial NUCLEO: aqui um valor NUMERICO tambem e segredo (PIN/senha numerica).
# Restrito (nao o _is_sensitive_key amplo) p/ 'password_expires_days: 90' seguir metadado (TN).
_NUMERIC_SECRET_KEYS = {
    "password", "passwd", "pwd", "senha", "secret", "client_secret",
    "api_key", "apikey", "token", "access_token", "refresh_token", "pin", "otp",
}  # fmt: skip
# Assinatura FORTE de credencial no VALOR — vale por si, em QUALQUER chave (ate sob chave de
# metadata como 'api_key_url'): re-inclui os FN que a exclusao de URL/metadata reintroduziu.
_CRED_VALUE_RES = (
    re.compile(r"(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA)[0-9A-Z]{12,}"),  # chaves de acesso AWS
    re.compile(r"\bAIza[0-9A-Za-z_\-]{20,}"),                       # Google API key
    re.compile(r"\bgithub_pat_[0-9A-Za-z_]{20,}|\bgh[opusr]_[0-9A-Za-z]{20,}"),  # GitHub PAT/token
    re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}"),                  # Slack token
    re.compile(r"\bsk-[0-9A-Za-z_\-]{16,}"),                        # OpenAI-style secret key
    re.compile(r"\bsk_(?:live|test)_[0-9A-Za-z]{16,}"),            # Stripe secret key
    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),  # chave privada PEM
)  # fmt: skip
_WEBHOOK_HOSTS = ("hooks.slack.com", "discord.com/api/webhooks", "discordapp.com/api/webhooks")
# userinfo na URL (basic-auth embutido scheme://user:senha@host) e presigned AWS (X-Amz-Signature).
_USERINFO_RE = re.compile(r"://[^/\s:@]+:[^/\s:@]+@")
_AMZ_SIG_RE = re.compile(r"(?i)[?&]x-amz-signature=")
# Placeholder/template: NAO e o segredo. ${VAR}, <seu-segredo>, %VAR%, $VAR, mascaras (xxxx/****)
# e palavras-molde. So exclui a string INTEIRA (ancorada) p/ nao cegar um segredo que apenas
# CONTENHA a palavra (ex.: a chave AWS canonica 'AKIA...EXAMPLE' segue pega pela lente de valor).
_PLACEHOLDER_RE = re.compile(
    r"^\s*(?:"
    r"\$?\{[^}]*\}|<[^>]*>|%[A-Za-z0-9_]+%|\$[A-Za-z_]\w*"
    r"|x{3,}|\*{3,}|\.{3,}|-{3,}"
    r"|changeme|change_me|redacted|placeholder|your[-_ ]?\w+|example|dummy|sample|test|none|null|n/?a"
    r")\s*$",
    re.IGNORECASE,
)


def _chave_e_metadata(key: str) -> bool:
    """A chave DESCREVE auth (flag/timestamp/URL/policy) em vez de carregar o segredo?"""
    low = key.lower().replace("-", "_")
    return any(low.endswith(suf) for suf in _META_SUFIXOS) or any(
        low.startswith(pre) for pre in _META_PREFIXOS
    )


def _valor_tem_assinatura_de_credencial(value: str) -> bool:
    """O VALOR carrega, por si so, uma credencial reconhecivel — independente da chave."""
    if any(rx.search(value) for rx in _CRED_VALUE_RES):
        return True
    return "://" in value and bool(
        _USERINFO_RE.search(value)
        or any(h in value for h in _WEBHOOK_HOSTS)
        or _AMZ_SIG_RE.search(value)
    )


def _folha_parece_segredo(key: str, value: Any) -> bool:
    """Sob uma chave sensivel NAO-metadata: a folha carrega um segredo em claro?

    String -> sim, salvo URL simples (sem credencial; a lente de valor cuida das secret-URLs) e
    placeholder. Numero -> so quando a PROPRIA chave e credencial-nucleo (senao e count/policy,
    ex.: 'password_expires_days: 90'). Bool/objeto -> nao.
    """
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return key.lower().replace("-", "_") in _NUMERIC_SECRET_KEYS
    if isinstance(value, str):
        if value == "" or value.startswith(("http://", "https://")):
            return False
        return not _PLACEHOLDER_RE.match(value)
    return False


def _walk_com_contexto(payload: dict[str, Any]) -> Iterator[tuple[str, str, Any, bool]]:
    """Percorre o payload inteiro (dicts e listas aninhados) **sem recursão**.

    Devolve ``(caminho, chave, valor, sob_sensivel)``. ``sob_sensivel`` marca que o valor esta
    sob uma chave sensivel NAO-metadata — herdado para dentro de listas/dicts, para pegar segredo
    numa lista (``api_keys: ["AKIA..."]``) ou num objeto (``secret: {"value": "..."}``). Itens de
    lista vem com chave vazia (so posicao). A profundidade ja e limitada no decode
    (``MAX_JSON_DEPTH``), mas a pilha explicita torna isso independente disso.
    """
    stack: list[tuple[str, Any, bool]] = [("", payload, False)]
    while stack:
        prefix, node, sob = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                k = str(key)
                sob_filho = sob or (_is_sensitive_key(k) and not _chave_e_metadata(k))
                yield path, k, value, sob_filho
                if isinstance(value, (dict, list)):
                    stack.append((path, value, sob_filho))
        elif isinstance(node, list):
            for position, value in enumerate(node):
                path = f"{prefix}[{position}]"
                if isinstance(value, (dict, list)):
                    stack.append((path, value, sob))
                else:
                    yield path, "", value, sob


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    if lowered in _SENSITIVE_KEYS:
        return True
    # Radical longo: substring na forma achatada (sem risco de colisão).
    normalized = _NOT_ALNUM.sub("", lowered)
    if any(part in normalized for part in _SENSITIVE_PARTS_FLAT):
        return True
    # Radical curto/ambíguo: só conta se for uma palavra inteira da chave.
    tokens = _tokenize_key(key)
    return any(part in tokens for part in _SENSITIVE_PARTS_TOKEN)


def _tokenize_key(key: str) -> set[str]:
    """Quebra a chave em palavras por separadores + fronteiras camelCase/dígito.

    Assim 'secret' casa 'client_secret'/'dbSecret' (têm fronteira) mas NÃO
    'secretaria' (palavra única) — o radical curto vira sinal só na fronteira,
    em vez de um filtro binário que cega tudo.
    """
    spaced = _KEY_BOUNDARY.sub(" ", _KEY_SEP.sub(" ", key))
    return {tok.lower() for tok in spaced.split()}


def has_cpf(value: str) -> bool:
    """True se a string contém um CPF com dígitos verificadores válidos (mód-11).

    Público porque a redação de PII do laudo (``report.redaction``) usa o mesmo
    critério de CPF do detector — uma fonte única evita divergência entre "o que
    é sinalizado" e "o que é redigido".
    """
    return any(_cpf_digits_ok(_NOT_DIGIT.sub("", m.group())) for m in _CPF.finditer(value))


def _cpf_digits_ok(digits: str) -> bool:
    """Confere os dois dígitos verificadores do CPF (módulo 11)."""
    if len(digits) != 11 or digits == digits[0] * 11:
        return False
    for size in (9, 10):
        total = sum(int(d) * (size + 1 - i) for i, d in enumerate(digits[:size]))
        if (total * 10) % 11 % 10 != int(digits[size]):
            return False
    return True


def _humanize_seconds(seconds: int) -> str:
    """Duração legível que **nunca** estoura float com um inteiro gigante.

    Um ``exp`` absurdo (ex.: ``10**400``) fazia ``seconds / 3600`` levantar
    ``OverflowError`` ("integer division result too large for a float") e derrubar
    a auditoria inteira — traceback no ``inspect`` e, no ``batch``, o token era
    engolido como "malformado" (o achado de validade-longa-demais sumia e o gate
    passava verde: fail-open). Para valores plausíveis mantemos horas com uma
    casa; para o gigantesco caímos em anos por divisão **inteira**, preservando o
    achado. ``str`` do resultado é segura: o decode já rejeita inteiro além do
    limite de dígitos, então o que chega aqui converte para texto sem levantar.
    """
    if -_FLOAT_SAFE_SECONDS < seconds < _FLOAT_SAFE_SECONDS:
        return f"~{round(seconds / 3600, 1)}h"
    return f"~{seconds // _SECONDS_PER_YEAR} anos"


def _as_epoch(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None  # Infinity/NaN (json.loads aceita esses literais)
    if isinstance(value, (int, float)):
        return int(value)
    return None
