"""Decodificação, assinatura e verificação de JWS/JWT.

Este módulo é deliberadamente de baixo nível: ele decodifica **sem** verificar
(para auditoria) e oferece primitivas de assinatura/verificação que as
ferramentas de ataque e o módulo de referência usam.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from chaveiro.core.models import DecodedToken

_HMAC_HASH: dict[str, Any] = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}
_RSA_HASH: dict[str, hashes.HashAlgorithm] = {
    "RS256": hashes.SHA256(),
    "RS384": hashes.SHA384(),
    "RS512": hashes.SHA512(),
}
_EC_HASH: dict[str, hashes.HashAlgorithm] = {
    "ES256": hashes.SHA256(),
    "ES384": hashes.SHA384(),
    "ES512": hashes.SHA512(),
}
# RSASSA-PSS (RFC 7518 §3.5): MGF1 e salt do mesmo tamanho da saída do hash.
_PSS_HASH: dict[str, hashes.HashAlgorithm] = {
    "PS256": hashes.SHA256(),
    "PS384": hashes.SHA384(),
    "PS512": hashes.SHA512(),
}
# EdDSA (RFC 8037): 'alg' único; a curva vem do tipo da chave (Ed25519/Ed448).
_EDDSA = "EdDSA"

# RFC 7515 §2: base64url, alfabeto -_ e **sem** padding.
_B64URL = re.compile(r"[A-Za-z0-9_-]*")
# Teto de aninhamento de header/payload. Nenhum JWT legítimo passa de poucos
# níveis; medido nesta máquina: json.dumps(indent=2) estoura em 996 níveis e
# json.loads em 2.998 — o teto protege decodificação, render e serialização.
MAX_JSON_DEPTH = 64


class JWTError(ValueError):
    """Token malformado ou operação inválida."""


# --------------------------------------------------------------------------- #
# base64url
# --------------------------------------------------------------------------- #


def b64url_decode(segment: str) -> bytes:
    """Decodifica um segmento em base64url **estrito** (RFC 7515 §2).

    A validação do alfabeto é deliberada: ``base64.urlsafe_b64decode`` descarta
    em silêncio qualquer byte fora do alfabeto (espaço, ``!``, quebra de linha) e
    ainda aceita base64 padrão (``+/``). Um auditor tolerante decodifica um token
    que nenhum verificador aceita — e passa a laudar um token que não existe.
    """
    if not _B64URL.fullmatch(segment):
        raise JWTError(
            f"segmento não é base64url estrito (RFC 7515 §2: alfabeto A-Za-z0-9-_ "
            f"e sem padding '='): {segment[:12]}…"
        )
    padding_needed = (-len(segment)) % 4
    try:
        return base64.urlsafe_b64decode(segment + "=" * padding_needed)
    except (ValueError, TypeError) as exc:
        raise JWTError(f"segmento base64url inválido: {segment[:12]}…") from exc


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# --------------------------------------------------------------------------- #
# decode
# --------------------------------------------------------------------------- #


def decode(token: str) -> DecodedToken:
    """Decodifica um JWS ou JWE compacto em suas partes, **sem verificar/decifrar**.

    Um JWS (RFC 7515) tem 3 segmentos; um JWE (RFC 7516) tem 5. Cobre as duas
    formas do JWS previstas no RFC 7519: o JWT comum (payload = objeto JSON) e
    o **JWT aninhado** (§5.2), cujo payload é outro JWS compacto. No aninhado,
    ``payload`` fica vazio — a casca não tem claims próprias — e ``nested``
    guarda o token interno, que precisa ser auditado à parte.
    """
    token = token.strip()
    parts = token.split(".")
    if len(parts) == 5:
        return _decode_jwe(token, parts)
    if len(parts) != 3:
        raise JWTError(
            f"esperados 3 segmentos (JWS) ou 5 (JWE) separados por ponto, encontrei {len(parts)}"
        )
    header_b64, payload_b64, sig_b64 = parts
    header = _decode_json(header_b64, "header")
    payload, nested = _decode_payload(payload_b64)
    signature = b64url_decode(sig_b64)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    return DecodedToken(
        raw=token,
        header=header,
        payload=payload,
        signature=signature,
        signing_input=signing_input,
        nested=nested,
        kind="jws",
    )


def _decode_jwe(token: str, parts: list[str]) -> DecodedToken:
    """Decodifica um JWE compacto (RFC 7516 §3.3) — só o cabeçalho é legível.

    Sem a chave de descriptografia, chave-encriptada/IV/ciphertext/tag continuam
    opacos por definição — a auditoria passiva é só sobre o cabeçalho protegido
    (primeiro segmento), única parte em JSON. Os outros quatro segmentos só têm
    o alfabeto base64url conferido (um deles, a chave encriptada, é vazio de
    propósito em modos como 'alg: dir' — RFC 7516 §5.1 passo 4).
    """
    header_b64, *opaco = parts
    header = _decode_json(header_b64, "cabeçalho protegido")
    for segmento in opaco:
        b64url_decode(segmento)
    return DecodedToken(
        raw=token,
        header=header,
        payload={},
        signature=b"",
        signing_input=b"",
        nested=None,
        kind="jwe",
    )


def parse_json_limited(raw: bytes, what: str) -> Any:
    """``json.loads`` com teto **explícito** de aninhamento.

    ``json.loads`` é recursivo: um documento profundo o bastante derruba o
    processo com ``RecursionError``, e ``json.dumps`` (usado pelos relatórios)
    estoura antes ainda. Por isso a profundidade é medida **antes** do parse,
    varrendo os bytes uma vez, sem recursão — assim decodificação, render e
    serialização ficam protegidos de uma vez só. Tudo o que é entrada hostil
    vira ``JWTError``, que o chamador já sabe tratar.
    """
    depth = _nesting_depth(raw)
    if depth > MAX_JSON_DEPTH:
        raise JWTError(f"{what} aninhado demais: {depth} níveis (teto {MAX_JSON_DEPTH})")
    try:
        return json.loads(raw)
    except (ValueError, RecursionError) as exc:
        # `json.loads` levanta `ValueError` para JSON malformado (JSONDecodeError),
        # bytes não-UTF-8 (UnicodeDecodeError também é ValueError) **e** — o caso
        # que escapava — para um inteiro literal além de `sys.get_int_max_str_digits()`
        # (~4300 dígitos): esse é um `ValueError` **cru**, não um JSONDecodeError, e
        # antes vazava por cima do `except`, virando traceback no `inspect` e um erro
        # opaco que engolia o token no `batch`. `RecursionError` cobre o parser
        # recursivo em JSON patológico. Tudo agora falha ALTO como `JWTError`, que o
        # chamador já sabe tratar (inspect: exit 2; batch: linha isolada como erro).
        raise JWTError(
            f"{what} não é JSON processável (UTF-8 válido, sem inteiro grande demais)"
        ) from exc


def _nesting_depth(raw: bytes) -> int:
    """Profundidade máxima de ``{``/``[`` do texto, medida **sem recursão**.

    Ignora o conteúdo de strings, onde chave e colchete são texto e não
    estrutura. Varre bytes: todos os delimitadores JSON são ASCII e UTF-8 é
    auto-sincronizante, então byte a byte é seguro.
    """
    depth = deepest = 0
    in_string = escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:  # \
                escaped = True
            elif byte == 0x22:  # "
                in_string = False
        elif byte == 0x22:
            in_string = True
        elif byte in (0x7B, 0x5B):  # { [
            depth += 1
            deepest = max(deepest, depth)
        elif byte in (0x7D, 0x5D):  # } ]
            depth -= 1
    return deepest


def looks_like_jws(value: str) -> bool:
    """True se ``value`` tem a cara de um JWS compacto: 3 segmentos e um cabeçalho
    base64url que decodifica para um objeto JSON com 'alg'. Heurística
    conservadora (exige o cabeçalho decodificável) para evitar falso-positivo em
    strings pontuadas."""
    parts = value.split(".")
    if len(parts) != 3:
        return False
    try:
        header = parse_json_limited(b64url_decode(parts[0]), "header")
    except JWTError:
        return False
    return isinstance(header, dict) and "alg" in header


def _decode_json(segment: str, what: str) -> dict[str, Any]:
    data = parse_json_limited(b64url_decode(segment), what)
    if not isinstance(data, dict):
        raise JWTError(f"{what} deve ser um objeto JSON")
    return data


def _decode_payload(segment: str) -> tuple[dict[str, Any], str | None]:
    """Payload de um JWT comum (objeto JSON) ou de um JWT aninhado (RFC 7519 §5.2)."""
    raw = b64url_decode(segment)
    try:
        data = parse_json_limited(raw, "payload")
    except JWTError:
        nested = _as_nested_jws(raw)
        if nested is None:
            raise
        return {}, nested
    if not isinstance(data, dict):
        raise JWTError("payload deve ser um objeto JSON (ou um JWS compacto, se aninhado)")
    return data, None


def _as_nested_jws(raw: bytes) -> str | None:
    try:
        text = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        return None
    return text if looks_like_jws(text) else None


# --------------------------------------------------------------------------- #
# assinatura / verificação
# --------------------------------------------------------------------------- #


def sign_hmac(signing_input: bytes, secret: bytes, alg: str = "HS256") -> bytes:
    func = _HMAC_HASH.get(alg)
    if func is None:
        raise JWTError(f"algoritmo HMAC não suportado: {alg}")
    return hmac.new(secret, signing_input, func).digest()


def verify_hmac(token: DecodedToken, secret: bytes) -> bool:
    if token.alg not in _HMAC_HASH:
        return False
    expected = sign_hmac(token.signing_input, secret, token.alg)
    return hmac.compare_digest(expected, token.signature)


def encode_hmac(header: dict[str, Any], payload: dict[str, Any], secret: bytes) -> str:
    alg = header.get("alg", "HS256")
    if alg not in _HMAC_HASH:
        raise JWTError(f"encode_hmac requer algoritmo HS*, recebi {alg}")
    header_b64 = b64url_encode(_compact_json(header))
    payload_b64 = b64url_encode(_compact_json(payload))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = sign_hmac(signing_input, secret, alg)
    return f"{header_b64}.{payload_b64}.{b64url_encode(signature)}"


def verify_asymmetric(token: DecodedToken, public_key_pem: bytes) -> bool:
    """Verifica assinatura RS*/PS*/ES*/EdDSA com uma chave pública PEM.

    Cobre as famílias assimétricas do JOSE (RFC 7518) mais EdDSA (RFC 8037):

    - ``RS*`` — RSASSA-PKCS1-v1_5;
    - ``PS*`` — RSASSA-PSS com MGF1 e salt do tamanho do hash;
    - ``ES*`` — ECDSA (assinatura crua R||S convertida para DER);
    - ``EdDSA`` — Ed25519/Ed448 (assina o ``signing_input`` sem pré-hash).

    Retorna ``False`` (nunca levanta) para assinatura inválida ou para
    par alg/chave incompatível — o chamador decide a política.
    """
    key = load_pem_public_key(public_key_pem)
    try:
        if token.alg in _RSA_HASH and isinstance(key, rsa.RSAPublicKey):
            key.verify(
                token.signature,
                token.signing_input,
                padding.PKCS1v15(),
                _RSA_HASH[token.alg],
            )
            return True
        if token.alg in _PSS_HASH and isinstance(key, rsa.RSAPublicKey):
            hash_alg = _PSS_HASH[token.alg]
            key.verify(
                token.signature,
                token.signing_input,
                padding.PSS(
                    mgf=padding.MGF1(hash_alg),
                    salt_length=padding.PSS.DIGEST_LENGTH,
                ),
                hash_alg,
            )
            return True
        if token.alg in _EC_HASH and isinstance(key, ec.EllipticCurvePublicKey):
            # JWS usa assinatura ECDSA crua (R||S); cryptography exige DER.
            n = (key.curve.key_size + 7) // 8
            if len(token.signature) != 2 * n:
                return False
            r = int.from_bytes(token.signature[:n], "big")
            s = int.from_bytes(token.signature[n:], "big")
            key.verify(
                encode_dss_signature(r, s),
                token.signing_input,
                ec.ECDSA(_EC_HASH[token.alg]),
            )
            return True
        if token.alg == _EDDSA and isinstance(
            key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)
        ):
            # EdDSA assina a mensagem diretamente (sem pré-hash separado).
            key.verify(token.signature, token.signing_input)
            return True
    except InvalidSignature:
        return False
    return False


def load_public_key(public_key_pem: bytes) -> PublicKeyTypes:
    return load_pem_public_key(public_key_pem)


def _compact_json(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=False).encode("utf-8")
