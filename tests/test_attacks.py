from __future__ import annotations

from chaveiro.attacks.confusion import forge_rs_to_hs
from chaveiro.attacks.crack import crack, crack_with_defaults
from chaveiro.core.jwt import decode, verify_hmac
from tests.conftest import hs_token, sign_rs256


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
    from tests.conftest import raw_token

    token = decode(raw_token({"alg": "RS256"}, {"sub": "a"}))
    assert crack_with_defaults(token) is None


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
