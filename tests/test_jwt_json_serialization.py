"""Testes da serialização JSON de JWS (RFC 7515 §7.2) — Flattened e General.

Item CH-10b: a maioria dos tokens reais chega na forma compacta (3
segmentos), mas alguns emissores (ex.: certas pilhas SAML/WS-Fed, ou
qualquer JWS produzido por uma lib que serializa "cru") usam a forma JSON.
`decode_json_serialization` aceita essa entrada em vez de recusar, marca
`serialization="json"` e expõe qualquer campo fora do esquema canônico em
`extra_fields` — o auditor vê o que não é padrão em vez de ele desaparecer
num parse silencioso.
"""

from __future__ import annotations

import json

import pytest
from hypothesis import given
from hypothesis import strategies as st

from chaveiro.core.jwt import JWTError, decode_any, decode_json_serialization, verify_hmac
from tests.conftest import hs_token


def _flattened(token: str, **extra_top: object) -> str:
    protected_b64, payload_b64, sig_b64 = token.split(".")
    obj: dict[str, object] = {
        "payload": payload_b64,
        "protected": protected_b64,
        "signature": sig_b64,
        **extra_top,
    }
    return json.dumps(obj)


def _general(token: str, extra_sig: dict[str, object] | None = None, **extra_top: object) -> str:
    protected_b64, payload_b64, sig_b64 = token.split(".")
    sig_entry: dict[str, object] = {"protected": protected_b64, "signature": sig_b64}
    sig_entry.update(extra_sig or {})
    obj: dict[str, object] = {"payload": payload_b64, "signatures": [sig_entry], **extra_top}
    return json.dumps(obj)


def test_flattened_is_accepted_and_marked_json() -> None:
    # Critério de aceite (CH-10b), na forma Flattened: aceito, serialization="json".
    token = hs_token({"sub": "alice"}, secret="k")
    decoded = decode_json_serialization(_flattened(token))
    assert decoded.serialization == "json"
    assert decoded.payload["sub"] == "alice"
    assert decoded.extra_fields == {}


def test_general_is_accepted_and_marked_json() -> None:
    # Mesmo critério, na forma General (lista `signatures`).
    token = hs_token({"sub": "bob"}, secret="k")
    decoded = decode_json_serialization(_general(token))
    assert decoded.serialization == "json"
    assert decoded.payload["sub"] == "bob"
    assert decoded.extra_fields == {}


def test_flattened_signature_still_verifies() -> None:
    # O signing_input (protected + "." + payload) é igual ao da forma compacta
    # — a verificação de assinatura não pode distinguir as duas formas.
    token = hs_token({"sub": "alice"}, secret="topsecret")
    decoded = decode_json_serialization(_flattened(token))
    assert verify_hmac(decoded, b"topsecret")


def test_flattened_extra_top_level_field_goes_to_extra_fields() -> None:
    token = hs_token({"sub": "alice"}, secret="k")
    decoded = decode_json_serialization(_flattened(token, kid_fora_do_lugar="x"))
    assert decoded.extra_fields == {"kid_fora_do_lugar": "x"}


def test_general_extra_field_in_signature_entry_goes_to_extra_fields() -> None:
    token = hs_token({"sub": "bob"}, secret="k")
    decoded = decode_json_serialization(_general(token, extra_sig={"x5t": "abc"}))
    assert decoded.extra_fields == {"x5t": "abc"}


def test_general_uses_first_signature_and_documents_the_choice() -> None:
    # Dois signatários independentes: General expõe só o primeiro — limitação
    # documentada (DecodedToken modela um signatário, não N).
    first = hs_token({"sub": "first"}, secret="k1")
    second = hs_token({"sub": "second"}, secret="k2")
    protected1, payload1, sig1 = first.split(".")
    _protected2, _payload2, sig2 = second.split(".")
    obj = {
        "payload": payload1,
        "signatures": [
            {"protected": protected1, "signature": sig1},
            {"protected": protected1, "signature": sig2},
        ],
    }
    decoded = decode_json_serialization(json.dumps(obj))
    assert decoded.payload["sub"] == "first"
    assert verify_hmac(decoded, b"k1")


def test_general_empty_signatures_raises() -> None:
    with pytest.raises(JWTError):
        decode_json_serialization(json.dumps({"payload": "x", "signatures": []}))


def test_missing_protected_raises() -> None:
    with pytest.raises(JWTError):
        decode_json_serialization(json.dumps({"payload": "x", "signature": "y"}))


def test_not_an_object_raises() -> None:
    with pytest.raises(JWTError):
        decode_json_serialization(json.dumps([1, 2, 3]))


def test_unprotected_header_merges_but_protected_wins_conflict() -> None:
    token = hs_token({"sub": "alice"}, secret="k", kid="do-protected")
    protected_b64, payload_b64, sig_b64 = token.split(".")
    obj = {
        "payload": payload_b64,
        "protected": protected_b64,
        "header": {"kid": "do-nao-protegido", "x-extra": "visivel"},
        "signature": sig_b64,
    }
    decoded = decode_json_serialization(json.dumps(obj))
    assert decoded.header["kid"] == "do-protected"  # protected vence
    assert decoded.header["x-extra"] == "visivel"  # não-protegido some só se colidir


def test_decode_any_prefers_compact() -> None:
    token = hs_token({"sub": "alice"}, secret="k")
    assert decode_any(token).serialization == "compact"


def test_decode_any_falls_back_to_json_serialization() -> None:
    token = hs_token({"sub": "alice"}, secret="k")
    decoded = decode_any(_flattened(token))
    assert decoded.serialization == "json"
    assert decoded.payload["sub"] == "alice"


def test_decode_any_raises_when_neither_form_works() -> None:
    with pytest.raises(JWTError):
        decode_any("isto nao e nem compacto nem json")


@given(
    extra=st.dictionaries(
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=1, max_size=10),
        st.one_of(st.text(max_size=10), st.integers(), st.booleans()),
        max_size=5,
    )
)
def test_flattened_extra_fields_invariant(extra: dict[str, object]) -> None:
    """INVARIANTE: toda chave fora do esquema canônico Flattened aparece em
    extra_fields, com o mesmo valor — e nenhuma chave canônica aparece lá,
    não importa quantos campos extras (ou nenhum) o emissor tenha colado."""
    token = hs_token({"sub": "alice"}, secret="k")
    # chave canônica não pode ser "extra" de propósito — Hypothesis poderia
    # gerar "payload"/"protected"/"header"/"signature" por acaso.
    extra = {
        k: v for k, v in extra.items() if k not in {"payload", "protected", "header", "signature"}
    }
    decoded = decode_json_serialization(_flattened(token, **extra))
    assert decoded.extra_fields == extra
