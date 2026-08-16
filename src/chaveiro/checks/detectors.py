"""As checagens em si — passivas, sobre um token já decodificado."""

from __future__ import annotations

import math
import re
from collections.abc import Iterator
from typing import Any

from chaveiro.checks.catalog import make_finding
from chaveiro.core.jwt import looks_like_jws
from chaveiro.core.models import DecodedToken, Finding

_KNOWN_ALGS = {
    "HS256", "HS384", "HS512",
    "RS256", "RS384", "RS512",
    "ES256", "ES384", "ES512",
    "PS256", "PS384", "PS512",
    "EdDSA",
}  # fmt: skip
_HMAC_ALGS = {"HS256", "HS384", "HS512"}
_LONG_LIFETIME_S = 24 * 3600
# Acima disso um inteiro não cabe em float (`/` estoura ~1.8e308) e o valor já
# não é um NumericDate plausível. ~31 mil anos em segundos — nenhum token real
# chega perto; serve só de para-raios do OverflowError.
_FLOAT_SAFE_SECONDS = 10**12
_SECONDS_PER_YEAR = 365 * 24 * 3600

_KID_DANGEROUS = ("..", "/", "\\", "'", '"', ";", "`", "$(", "|", "<", ">", "\x00", "\n")
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

# --- JWE (RFC 7516) — vocabulário do cabeçalho protegido, distinto do JWS ---
# 'alg' aqui é gerenciamento de CHAVE, não assinatura; misturar com _KNOWN_ALGS
# (vocabulário de JWS) daria falso-positivo em todo RSA-OAEP/ECDH-ES legítimo.
_JWE_ALG_ALLOWLIST = {
    "RSA-OAEP", "RSA-OAEP-256",
    "A128KW", "A192KW", "A256KW",
    "A128GCMKW", "A192GCMKW", "A256GCMKW",
    "dir",
    "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW",
    "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW",
}  # fmt: skip
_JWE_ENC_ALLOWLIST = {
    "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
    "A128GCM", "A192GCM", "A256GCM",
}  # fmt: skip
_JWE_ALG_RSA1_5 = "RSA1_5"
_JWE_PBES2_ALGS = {"PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW"}
# Teto de 'p2c' (iterações do PBES2, RFC 7518 §4.8.1.2). O valor é escolhido por
# quem EMITE o token e pago por quem VERIFICA em toda tentativa de decifrar,
# antes de qualquer autenticação — o oposto de hash de senha em repouso, que
# roda uma vez no cadastro. Uso legítimo fixa um número da ordem de milhares;
# nada com latência de verificação síncrona justifica mais que isso. Acima do
# teto é o mecanismo exato do ataque de "Billion Hash": o emissor infla 'p2c' e
# o verificador queima CPU tentando decifrar tokens hostis.
_JWE_P2C_MAX = 100_000


def run_all(token: DecodedToken, now: int) -> list[Finding]:
    if token.kind == "jwe":
        # As checagens abaixo são vocabulário de JWS (alg de assinatura, claims
        # em claro) — não fazem sentido sobre um cabeçalho de JWE.
        return check_jwe_header(token)
    findings: list[Finding] = []
    findings += check_alg(token)
    findings += check_header(token)
    findings += check_nesting(token)
    findings += check_claims(token, now)
    findings += check_payload(token)
    return findings


def check_jwe_header(token: DecodedToken) -> list[Finding]:
    """Checagens passivas sobre o cabeçalho protegido de um JWE — sem decifrar nada.

    Cobre os três vetores auditáveis sem a chave: algoritmo de gerenciamento de
    chave (`alg`) e de conteúdo (`enc`) fora da allowlist, iterações de PBES2
    (`p2c`) abusivas e `zip: DEF` (descompressão sem controle de tamanho).
    """
    out: list[Finding] = []
    header = token.header
    alg = header.get("alg")
    enc = header.get("enc")

    if isinstance(alg, str):
        if alg == _JWE_ALG_RSA1_5:
            out.append(
                make_finding(
                    "jwe-alg-rsa15",
                    "Gerenciamento de chave 'RSA1_5' (RSAES-PKCS1-v1_5, sem OAEP).",
                    evidence=f"alg={alg!r}",
                )
            )
        elif alg not in _JWE_ALG_ALLOWLIST:
            out.append(
                make_finding(
                    "jwe-alg-unknown",
                    f"Algoritmo de gerenciamento de chave não reconhecido: {alg!r}.",
                    evidence=alg,
                )
            )
        if alg in _JWE_PBES2_ALGS:
            p2c = header.get("p2c")
            if isinstance(p2c, int) and not isinstance(p2c, bool) and p2c > _JWE_P2C_MAX:
                out.append(
                    make_finding(
                        "jwe-p2c-abusive",
                        f"'p2c' = {p2c} iterações, acima do teto de {_JWE_P2C_MAX}.",
                        evidence=f"alg={alg} p2c={p2c}",
                    )
                )

    if isinstance(enc, str) and enc not in _JWE_ENC_ALLOWLIST:
        out.append(
            make_finding(
                "jwe-enc-unknown",
                f"Algoritmo de conteúdo (enc) não reconhecido: {enc!r}.",
                evidence=enc,
            )
        )

    if header.get("zip") == "DEF":
        out.append(
            make_finding(
                "jwe-zip-dos",
                "O cabeçalho declara 'zip: DEF' — o plaintext é comprimido antes de cifrar; ao "
                "decifrar, quem verifica descomprime o conteúdo sem saber de antemão o tamanho "
                "final, o que abre exaustão de memória/CPU (zip bomb) sem precisar de chave "
                "nenhuma.",
                evidence="zip=DEF",
            )
        )
    return out


def check_alg(token: DecodedToken) -> list[Finding]:
    out: list[Finding] = []
    alg = token.header.get("alg")
    if not isinstance(alg, str) or alg.strip() == "":
        out.append(make_finding("alg-missing", "O cabeçalho não declara 'alg'."))
        return out
    # Espaço/tabulação em volta do valor não muda a intenção: 'none ', '\tNoNe'
    # e 'HS256 ' são o mesmo algoritmo para um verificador leniente (muitas libs
    # fazem strip). Comparamos pela forma normalizada — mantendo o valor cru na
    # evidência — senão 'alg: none ' escaparia do CRÍTICO para o MÉDIO de
    # alg-unknown. O strip acompanha a leniência de caixa que já existia no none.
    normalized = alg.strip()
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
        # `run_all` só chama `check_header` para `kind == "jws"` — um token de 5
        # segmentos (JWE) cai em `check_jwe_header`, onde 'zip' é válido (RFC
        # 7516) e vira o achado `jwe-zip-dos`, não este. Aqui, 'zip' num JWS é
        # violação do RFC 7515 e o vetor de DoS por descompressão
        # pré-verificação (Apache James descomprimia antes de checar a
        # assinatura). Detectável offline, sem tocar a rede, só lendo o header.
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
    if isinstance(kid, str) and any(token_ in kid for token_ in _KID_DANGEROUS):
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
    if exp is not None:
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
    return out


def check_payload(token: DecodedToken) -> list[Finding]:
    """Procura segredo e dado pessoal em **qualquer profundidade** do payload.

    `{"user": {"cpf": ...}}` é a forma mais comum de payload JWT no Brasil, então
    varrer só o primeiro nível seria falso negativo na forma que mais aparece.
    """
    out: list[Finding] = []
    for path, key, value in _walk(token.payload):
        if _is_sensitive_key(key) and value not in (None, "", [], {}):
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


def _walk(payload: dict[str, Any]) -> Iterator[tuple[str, str, Any]]:
    """Percorre o payload inteiro — dicts e listas aninhados — **sem recursão**.

    Devolve ``(caminho, chave, valor)``; itens de lista vêm com chave vazia (não
    têm nome, só posição). A profundidade já é limitada no decode
    (``MAX_JSON_DEPTH``), mas a pilha explícita torna isso independente disso.
    """
    stack: list[tuple[str, Any]] = [("", payload)]
    while stack:
        prefix, node = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                yield path, str(key), value
                if isinstance(value, (dict, list)):
                    stack.append((path, value))
        elif isinstance(node, list):
            for position, value in enumerate(node):
                path = f"{prefix}[{position}]"
                if isinstance(value, (dict, list)):
                    stack.append((path, value))
                else:
                    yield path, "", value


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
