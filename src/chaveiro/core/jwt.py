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


class JWTError(ValueError):
    """Token malformado ou operação inválida."""


# --------------------------------------------------------------------------- #
# base64url
# --------------------------------------------------------------------------- #


def b64url_decode(segment: str) -> bytes:
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
    """Decodifica um JWS compacto em suas partes, **sem verificar assinatura**."""
    token = token.strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise JWTError(f"esperados 3 segmentos separados por ponto, encontrei {len(parts)}")
    header_b64, payload_b64, sig_b64 = parts
    header = _decode_json(header_b64, "header")
    payload = _decode_json(payload_b64, "payload")
    signature = b64url_decode(sig_b64)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    return DecodedToken(
        raw=token,
        header=header,
        payload=payload,
        signature=signature,
        signing_input=signing_input,
    )


def _decode_json(segment: str, what: str) -> dict[str, Any]:
    try:
        data = json.loads(b64url_decode(segment))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise JWTError(f"{what} não é JSON UTF-8 válido") from exc
    if not isinstance(data, dict):
        raise JWTError(f"{what} deve ser um objeto JSON")
    return data


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
