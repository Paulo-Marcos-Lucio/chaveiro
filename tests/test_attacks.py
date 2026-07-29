from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from chaveiro.attacks.confusion import forge_rs_to_hs
from chaveiro.attacks.crack import crack, crack_with_defaults
from chaveiro.core.jwt import b64url_encode, decode, verify_asymmetric, verify_hmac
from tests.conftest import hs_token, raw_token, sign_rs256
from tests.test_review_fixes import _sign_es256


def test_crack_finds_weak_default_secret() -> None:
    token = decode(hs_token({"sub": "a"}, secret="secret"))
    assert crack_with_defaults(token) == "secret"


def test_crack_finds_from_wordlist() -> None:
    token = decode(hs_token({"sub": "a"}, secret="correct-horse"))
    assert crack(token, ["nope", "correct-horse", "other"]) == "correct-horse"


def test_crack_fails_on_strong_secret() -> None:
    token = decode(hs_token({"sub": "a"}, secret="Zx9$Kp2!mQ7wLvB3cD5fG6hJ8nR0tY4u"))
    assert crack_with_defaults(token) is None


def test_crack_ignores_non_hmac() -> None:
    # um token RS256 não é atacável por dicionário HMAC
    token = decode(raw_token({"alg": "RS256"}, {"sub": "a"}))
    assert crack_with_defaults(token) is None


def test_crack_guard_corta_antes_de_iterar() -> None:
    """O guard de alg tem que cortar ANTES de testar candidato.

    Sem o guard, `verify_hmac` devolver False para alg não-HMAC mascara o defeito
    (o teste passa pelo efeito colateral). Aqui provamos que o guard corta: se
    `crack` consumir um só candidato de um token RS256, o iterador levanta.
    """

    def _explode() -> object:
        raise AssertionError("o guard deveria ter cortado antes de iterar candidatos")
        yield  # pragma: no cover

    token = decode(raw_token({"alg": "RS256"}, {"sub": "a"}))
    assert crack(token, _explode()) is None


def test_verify_asymmetric_es256_wrong_size_returns_false() -> None:
    """ES*: assinatura de tamanho != 2n devolve False (nunca levanta, nunca True).

    NOTA de honestidade: este teste NÃO fixa o guard `len(sig) != 2*n` — medi que
    removê-lo não muda o retorno (uma assinatura de tamanho errado falha a
    verificação de qualquer forma, InvalidSignature -> False, em todos os
    tamanhos que testei). O guard é defensivo/de clareza, não pinável por
    comportamento. Este teste trava só o contrato observável: entrada torta ->
    False, sem traceback."""
    key = ec.generate_private_key(ec.SECP256R1())
    pub = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    token = _sign_es256({"sub": "z"}, key)
    header_b64, payload_b64, _ = token.split(".")
    wrong_size = b"\x00" * 10  # 10 bytes, não 64
    tampered = f"{header_b64}.{payload_b64}.{b64url_encode(wrong_size)}"
    assert not verify_asymmetric(decode(tampered), pub)


def test_rs_to_hs_confusion_poc(rsa_keys: tuple[bytes, bytes]) -> None:
    private_pem, public_pem = rsa_keys
    original = decode(sign_rs256({"sub": "user", "role": "user"}, private_pem))

    forged = forge_rs_to_hs(original, public_pem, edits={"role": "admin"})
    forged_decoded = decode(forged)

    # o token forjado agora é HS256, com a claim adulterada...
    assert forged_decoded.alg == "HS256"
    assert forged_decoded.payload["role"] == "admin"
    # ...e é "válido" para quem verificar HMAC usando a chave pública como segredo.
    assert verify_hmac(forged_decoded, public_pem)
