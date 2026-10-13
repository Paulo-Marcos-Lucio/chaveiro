"""Corpus de SHAPE real de emissores (item C02 do backlog) sustenta o que promete.

`bench/emissores.py` existe para que o auditor veja o jargão real de cada
provedor (`realm_access` do Keycloak, `tid` do Entra, `token_use` do
Cognito...) e não o confunda com achado. Este teste é a parte executável da
promessa: ≥30 tokens, ≥5 emissores, cada token decodificável e com a claim
que identifica a FORMA daquele emissor — e nenhum nome/e-mail/usuário sem o
marcador `exemplo`, para que "nenhum dado de pessoa real" não dependa de
revisão visual.
"""

from __future__ import annotations

import importlib.util
import os
import sys

from chaveiro.core.jwt import decode

_BENCH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bench")
if _BENCH not in sys.path:
    sys.path.insert(0, _BENCH)


def _load_emissores() -> object:
    spec = importlib.util.spec_from_file_location("emissores", os.path.join(_BENCH, "emissores.py"))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["emissores"] = module
    spec.loader.exec_module(module)
    return module


# Claim (ou valor de 'iss') que só aparece no formato daquele emissor —
# o "sotaque" que a auditoria tem de reconhecer como normal, não como achado.
_MARCA_DO_EMISSOR: dict[str, object] = {
    "keycloak": "realm_access",
    "auth0": "azp_ou_sub_namespaced",  # tratado à parte: sub tem '|'
    "entra": "tid",
    "cognito": "token_use",
    "google": "at_hash",
    "open_finance_br": "acr_openbanking",  # tratado à parte: acr começa com urn:brasil:
}

# Campos que, se existirem, carregam identidade de pessoa — têm de trazer o
# marcador 'exemplo' (case-insensitive) em algum lugar do valor. Campos como
# 'given_name' (só o primeiro nome, ex.: "Thiago") ficam de fora de propósito:
# um nome próprio comum isolado não identifica pessoa real nenhuma — é o
# sobrenome/e-mail/usuário completo que o corpus marca como fictício.
_CAMPOS_DE_IDENTIDADE = (
    "name",
    "family_name",
    "email",
    "preferred_username",
    "cognito:username",
    "username",
    "nickname",
    "upn",
)


def test_corpus_tem_pelo_menos_30_tokens_de_pelo_menos_5_emissores() -> None:
    emissores = _load_emissores()
    total = sum(len(fn()) for fn in emissores.EMISSORES.values())  # type: ignore[attr-defined]
    assert len(emissores.EMISSORES) >= 5  # type: ignore[attr-defined]
    assert total >= 30


def test_todo_token_decodifica_como_jwt_bem_formado() -> None:
    emissores = _load_emissores()
    for nome, fn in emissores.EMISSORES.items():  # type: ignore[attr-defined]
        for i, token in enumerate(fn()):
            assert token.count(".") == 2, f"{nome}[{i}] não tem 3 segmentos"
            decoded = decode(token)
            assert decoded.header, f"{nome}[{i}] com header vazio"
            assert decoded.payload, f"{nome}[{i}] com payload vazio"


def test_cada_emissor_tem_a_claim_que_e_a_sua_forma() -> None:
    """INVARIANTE: todo token de um emissor traz a claim/valor que SÓ aparece
    no formato real daquele emissor — a diferença entre "parece um JWT
    genérico" e "tem a forma do Keycloak/Entra/Cognito/Google/Open Finance"."""
    emissores = _load_emissores()

    for token in emissores.tokens_keycloak():  # type: ignore[attr-defined]
        payload = decode(token).payload
        assert "realm_access" in payload and "resource_access" in payload

    for token in emissores.tokens_auth0():  # type: ignore[attr-defined]
        payload = decode(token).payload
        assert "|" in payload["sub"] or payload.get("gty") == "client-credentials"

    for token in emissores.tokens_entra():  # type: ignore[attr-defined]
        payload = decode(token).payload
        assert "tid" in payload and "oid" in payload

    for token in emissores.tokens_cognito():  # type: ignore[attr-defined]
        payload = decode(token).payload
        assert payload.get("token_use") in ("id", "access")

    for token in emissores.tokens_google():  # type: ignore[attr-defined]
        payload = decode(token).payload
        assert payload["iss"] in ("https://accounts.google.com", "accounts.google.com")
        assert isinstance(payload["sub"], str) and payload["sub"].isdigit()

    for token in emissores.tokens_open_finance_br():  # type: ignore[attr-defined]
        payload = decode(token).payload
        assert str(payload.get("acr", "")).startswith("urn:brasil:openbanking:")


def test_nenhum_dado_de_identidade_sem_o_marcador_sintetico() -> None:
    """Todo campo de identidade (nome, e-mail, usuário...) carrega 'exemplo' —
    o marcador que, nesta base, afirma "isto foi fabricado" (mesmo princípio
    do `CPF_DE_TUTORIAL` do Guardião: dado estruturalmente válido, mas que o
    próprio corpus declara fictício)."""
    emissores = _load_emissores()
    achados_sem_marcador: list[str] = []
    for nome, fn in emissores.EMISSORES.items():  # type: ignore[attr-defined]
        for i, token in enumerate(fn()):
            payload = decode(token).payload
            for campo in _CAMPOS_DE_IDENTIDADE:
                valor = payload.get(campo)
                if isinstance(valor, str) and "exemplo" not in valor.lower():
                    achados_sem_marcador.append(f"{nome}[{i}].{campo}={valor!r}")
    assert achados_sem_marcador == []


def test_nenhum_cpf_ou_segredo_vaza_nos_tokens_de_emissor() -> None:
    """Estes são tokens de EMISSOR (identidade/autorização) — não devem
    carregar CPF nem segredo no payload; se carregassem, estariam testando o
    detector de PII/segredo, não o reconhecimento de forma de emissor."""
    from chaveiro.audit import audit_token

    emissores = _load_emissores()
    for nome, fn in emissores.EMISSORES.items():  # type: ignore[attr-defined]
        for i, token in enumerate(fn()):
            achados = {f.check_id for f in audit_token(token, emissores.AGORA).findings}  # type: ignore[attr-defined]
            assert "payload-sensitive" not in achados, f"{nome}[{i}] vazou CPF/segredo"
