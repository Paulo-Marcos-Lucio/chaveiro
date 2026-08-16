from __future__ import annotations

import pytest

from chaveiro.checks.catalog import CATALOG
from chaveiro.checks.detectors import _JWE_P2C_MAX, _is_sensitive_key, run_all
from chaveiro.core.jwt import decode
from chaveiro.core.models import Severity
from tests.conftest import hs_token, jwe_token, raw_token

NOW = 1_800_000_000
_INNER_JWT = hs_token({"sub": "admin"}, secret="k")


def _ids(token: str, now: int = NOW) -> set[str]:
    return {f.check_id for f in run_all(decode(token), now)}


# --------------------------------------------------------------------------- #
# Cobertura por ID: para CADA checagem do catálogo, um caso que a dispara.
# Fecha a família de "detector invertido/apagado sem quebrar teste": matar
# qualquer ramo de check_* apaga o id da lista e o `parametrize` fica vermelho.
# --------------------------------------------------------------------------- #

_CASOS_POSITIVOS: list[tuple[str, dict, dict]] = [
    ("alg-none", {"alg": "none"}, {"sub": "a"}),
    ("alg-missing", {"typ": "JWT"}, {"sub": "a"}),
    ("alg-unknown", {"alg": "ZZ999"}, {"sub": "a"}),
    ("alg-hmac-advisory", {"alg": "HS256"}, {"sub": "a"}),
    ("header-jku", {"alg": "HS256", "jku": "http://evil/keys"}, {"sub": "a"}),
    ("header-x5u", {"alg": "HS256", "x5u": "http://evil/cert"}, {"sub": "a"}),
    ("header-jwk", {"alg": "HS256", "jwk": {"kty": "oct"}}, {"sub": "a"}),
    ("header-x5c", {"alg": "HS256", "x5c": ["MIIB..."]}, {"sub": "a"}),
    ("header-crit", {"alg": "HS256", "crit": ["exp"]}, {"sub": "a"}),
    ("header-zip-jws", {"alg": "HS256", "zip": "DEF"}, {"sub": "a"}),
    ("header-kid-injection", {"alg": "HS256", "kid": "../../etc/passwd"}, {"sub": "a"}),
    ("header-cty-nested", {"alg": "HS256", "cty": "JWT"}, {"sub": "a"}),
    ("claim-no-exp", {"alg": "HS256"}, {"iat": NOW, "aud": "x", "iss": "y"}),
    ("claim-expired", {"alg": "HS256"}, {"exp": NOW - 10, "iat": NOW - 70}),
    ("claim-long-lifetime", {"alg": "HS256"}, {"iat": NOW, "exp": NOW + 90 * 24 * 3600}),
    ("claim-no-iat", {"alg": "HS256"}, {"exp": NOW + 60, "aud": "x", "iss": "y"}),
    ("claim-no-aud", {"alg": "HS256"}, {"exp": NOW + 60, "iat": NOW, "iss": "y"}),
    ("claim-no-iss", {"alg": "HS256"}, {"exp": NOW + 60, "iat": NOW, "aud": "x"}),
    ("claim-malformed-time", {"alg": "HS256"}, {"exp": "1", "iat": NOW}),
    ("claim-nbf-future", {"alg": "HS256"}, {"nbf": NOW + 3600, "exp": NOW + 7200}),
    ("payload-nested-jwt", {"alg": "HS256"}, {"assertion": _INNER_JWT}),
    ("payload-sensitive", {"alg": "HS256"}, {"password": "hunter2"}),
]

# JWE (RFC 7516): 5 segmentos, não 3 — `payload=None` é o sinal para montar via
# `jwe_token(header)` em vez de `raw_token(header, payload)` (ver `_token_for`).
_CASOS_POSITIVOS_JWE: list[tuple[str, dict, None]] = [
    ("jwe-alg-rsa15", {"alg": "RSA1_5", "enc": "A128CBC-HS256"}, None),
    ("jwe-alg-unknown", {"alg": "ZZ-nao-existe", "enc": "A256GCM"}, None),
    ("jwe-enc-unknown", {"alg": "dir", "enc": "ZZ-nao-existe"}, None),
    (
        "jwe-p2c-abusive",
        {
            "alg": "PBES2-HS256+A128KW",
            "enc": "A128CBC-HS256",
            "p2c": _JWE_P2C_MAX + 1,
            "p2s": "c2FsdA",
        },
        None,
    ),
    ("jwe-zip-dos", {"alg": "dir", "enc": "A256GCM", "zip": "DEF"}, None),
]


def _token_for(header: dict, payload: dict | None) -> str:
    return jwe_token(header) if payload is None else raw_token(header, payload)


@pytest.mark.parametrize(
    "check_id, header, payload",
    [*_CASOS_POSITIVOS, *_CASOS_POSITIVOS_JWE],
    ids=[c[0] for c in [*_CASOS_POSITIVOS, *_CASOS_POSITIVOS_JWE]],
)
def test_cada_checagem_dispara(check_id: str, header: dict, payload: dict | None) -> None:
    assert check_id in _ids(_token_for(header, payload))


def test_toda_checagem_do_catalogo_tem_caso_positivo() -> None:
    """Meta-teste: nenhum ID do catálogo pode nascer sem um caso que o exercite.

    Transforma disciplina humana em invariante — uma checagem nova entra
    vermelha até ganhar sua tupla em `_CASOS_POSITIVOS`.
    """
    testados = {cid for cid, _, _ in [*_CASOS_POSITIVOS, *_CASOS_POSITIVOS_JWE]}
    assert set(CATALOG) - testados == set()


# --------------------------------------------------------------------------- #
# Casos NEGATIVOS: o par que mata a inversão silenciosa de um detector.
# Ex.: `nbf > now` invertido para `nbf < now` sobrevive a qualquer teste que só
# olhe o caso positivo — o negativo é o que fica vermelho.
# --------------------------------------------------------------------------- #

_CASOS_NEGATIVOS: list[tuple[str, dict, dict]] = [
    # nbf no passado é o token saudável normal — não pode disparar nbf-future.
    ("claim-nbf-future", {"alg": "HS256"}, {"nbf": NOW - 3600, "exp": NOW + 60}),
    # exp no futuro não é "expirado".
    ("claim-expired", {"alg": "HS256"}, {"exp": NOW + 3600, "iat": NOW}),
    # exp presente e numérico não é "sem exp".
    ("claim-no-exp", {"alg": "HS256"}, {"exp": NOW + 60}),
    # exp/iat numéricos não são claim temporal malformada.
    ("claim-malformed-time", {"alg": "HS256"}, {"exp": NOW + 60, "iat": NOW}),
    # alg conhecido não é alg desconhecido.
    ("alg-unknown", {"alg": "RS256"}, {"sub": "a"}),
    # kid opaco e rotacionado não é injeção.
    ("header-kid-injection", {"alg": "HS256", "kid": "chave-2024-rotacionada"}, {"sub": "a"}),
    # vida curta não é vida longa.
    ("claim-long-lifetime", {"alg": "HS256"}, {"iat": NOW, "exp": NOW + 300}),
    # token sem 'zip' não dispara o achado de compressão em JWS.
    ("header-zip-jws", {"alg": "HS256"}, {"sub": "a"}),
]


@pytest.mark.parametrize(
    "check_id, header, payload", _CASOS_NEGATIVOS, ids=[f"nao-{c[0]}" for c in _CASOS_NEGATIVOS]
)
def test_caso_negativo_nao_dispara(check_id: str, header: dict, payload: dict) -> None:
    assert check_id not in _ids(raw_token(header, payload))


# --------------------------------------------------------------------------- #
# kid: os vetores de injeção (aspas/backtick/pipe/SQL), não só o path traversal.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "kid",
    [
        "../../etc/passwd",
        "chave1'; DROP TABLE users--",
        'x"y',
        "chave1`id`",
        "chave|nc evil 1234",
        "a;b",
        "$(whoami)",
        "a<b",
        "linha1\nlinha2",
    ],
)
def test_kid_caracteres_perigosos_disparam(kid: str) -> None:
    ids = _ids(raw_token({"alg": "HS256", "kid": kid}, {"sub": "a"}))
    assert "header-kid-injection" in ids


def test_alg_none_case_insensitive() -> None:
    # Várias libs aceitam 'None'/'NONE' como não-assinado — o guard usa .lower().
    for variante in ("None", "NONE", "nOnE"):
        findings = run_all(decode(raw_token({"alg": variante}, {"sub": "a"})), NOW)
        assert any(
            f.check_id == "alg-none" and f.severity is Severity.CRITICAL for f in findings
        ), variante


def test_alg_none_is_critical() -> None:
    token = raw_token({"alg": "none", "typ": "JWT"}, {"sub": "admin"})
    findings = run_all(decode(token), NOW)
    assert any(f.check_id == "alg-none" and f.severity is Severity.CRITICAL for f in findings)


@pytest.mark.parametrize("alg", ["none ", " none", "NoNe\t", "\tNoNe", "  none  ", "None "])
def test_alg_none_with_surrounding_whitespace_is_critical(alg: str) -> None:
    # Um verificador leniente faz strip e aceita o token não-assinado; 'none '
    # com espaço/tab NÃO pode cair para alg-unknown (MEDIUM). Deve ser CRÍTICO.
    findings = run_all(decode(raw_token({"alg": alg}, {"sub": "a"})), NOW)
    assert any(f.check_id == "alg-none" and f.severity is Severity.CRITICAL for f in findings), alg
    # e nunca a rebaixa como algoritmo "desconhecido"
    assert "alg-unknown" not in {f.check_id for f in findings}


def test_alg_known_with_trailing_whitespace_not_unknown() -> None:
    # Coerência do strip: 'HS256 ' é HS256 para quem faz strip — vira advisory,
    # não alg-unknown.
    ids = {f.check_id for f in run_all(decode(raw_token({"alg": "HS256 "}, {"sub": "a"})), NOW)}
    assert "alg-hmac-advisory" in ids
    assert "alg-unknown" not in ids


def test_missing_exp() -> None:
    token = hs_token({"sub": "a", "iat": NOW, "aud": "x", "iss": "y"})
    assert "claim-no-exp" in _ids(token)


def test_expired_token() -> None:
    token = hs_token({"exp": NOW - 10, "iat": NOW - 70, "aud": "x", "iss": "y"})
    assert "claim-expired" in _ids(token)


def test_long_lifetime() -> None:
    token = hs_token({"iat": NOW, "exp": NOW + 90 * 24 * 3600, "aud": "x", "iss": "y"})
    assert "claim-long-lifetime" in _ids(token)


def test_long_lifetime_sem_iat_ainda_dispara() -> None:
    # Token de 10 anos SEM iat é MAIS perigoso — e era justo aí que a checagem se
    # desligava (exigia iat). A vida útil passa a ser aproximada por 'agora'.
    token = raw_token({"alg": "HS256"}, {"exp": NOW + 10 * 365 * 24 * 3600, "aud": "x", "iss": "y"})
    assert "claim-long-lifetime" in _ids(token)


def test_header_jku_and_kid_injection() -> None:
    token = raw_token(
        {"alg": "HS256", "jku": "http://evil/keys", "kid": "../../etc/passwd"},
        {"exp": NOW + 60, "iat": NOW, "aud": "x", "iss": "y"},
    )
    ids = _ids(token)
    assert "header-jku" in ids
    assert "header-kid-injection" in ids


def test_sensitive_payload() -> None:
    token = hs_token({"exp": NOW + 60, "iat": NOW, "aud": "x", "iss": "y", "password": "hunter2"})
    assert "payload-sensitive" in _ids(token)


def test_cpf_in_payload() -> None:
    token = hs_token({"exp": NOW + 60, "iat": NOW, "aud": "x", "iss": "y", "doc": "123.456.789-09"})
    assert "payload-sensitive" in _ids(token)


# --------------------------------------------------------------------------- #
# _is_sensitive_key: radical curto ancorado à fronteira de palavra.
# A substring achatada casava 'resenha'/'secretaria' (FP). Radical curto agora
# só conta como token inteiro; radical longo segue como substring; formas
# compostas reais (com separador/camelCase) continuam pegando.
# --------------------------------------------------------------------------- #

# Palavras inocentes que CONTÊM um radical curto como substring — não podem casar.
_CHAVES_NAO_SENSIVEIS = [
    "resenha", "desenha", "senharia", "secretaria", "secretary", "greatsecret",
    "pwded", "prensa", "pesquisa", "username", "email", "token_type",
]  # fmt: skip

# Chaves REAIS de segredo — não podem ser perdidas (precisão sem sacrificar recall).
_CHAVES_SENSIVEIS = [
    "password", "passwd", "senha", "secret", "pwd",
    "senha_usuario", "user_password", "client_secret", "dbSecret", "secret_key",
    "api_key", "apikey", "x-api-key", "private_key", "privateKey",
    "pwdHash", "userPwd", "clientSecret", "USER_SENHA",
]  # fmt: skip


@pytest.mark.parametrize("key", _CHAVES_NAO_SENSIVEIS)
def test_chave_inocente_com_substring_nao_e_sensivel(key: str) -> None:
    assert _is_sensitive_key(key) is False


@pytest.mark.parametrize("key", _CHAVES_SENSIVEIS)
def test_chave_real_de_segredo_continua_sensivel(key: str) -> None:
    assert _is_sensitive_key(key) is True


def test_payload_resenha_nao_dispara_mas_senha_dispara() -> None:
    # Integração ponta-a-ponta: 'resenha' no payload não vira achado; 'senha' sim.
    limpo = hs_token({"exp": NOW + 60, "iat": NOW, "aud": "x", "iss": "y", "resenha": "texto"})
    assert "payload-sensitive" not in _ids(limpo)
    real = hs_token({"exp": NOW + 60, "iat": NOW, "aud": "x", "iss": "y", "senha_usuario": "x"})
    assert "payload-sensitive" in _ids(real)


def test_hmac_advisory() -> None:
    token = hs_token({"exp": NOW + 60, "iat": NOW, "aud": "x", "iss": "y"})
    assert "alg-hmac-advisory" in _ids(token)


def test_cty_jwt_flags_nested() -> None:
    token = hs_token({"exp": NOW + 60, "iat": NOW, "aud": "x", "iss": "y"}, cty="JWT")
    assert "header-cty-nested" in _ids(token)


def test_cty_application_jwt_variation_flags_nested() -> None:
    # RFC 7515 §4.1.10: "application/" pode ser omitido e a comparação é case-insensitive.
    token = hs_token({"exp": NOW + 60, "iat": NOW, "aud": "x", "iss": "y"}, cty="application/jwt")
    assert "header-cty-nested" in _ids(token)


def test_nested_jwt_in_claim_flags() -> None:
    inner = hs_token({"exp": NOW + 60, "iat": NOW, "aud": "x", "iss": "y", "role": "admin"})
    outer = hs_token({"exp": NOW + 60, "iat": NOW, "aud": "x", "iss": "y", "assertion": inner})
    assert "payload-nested-jwt" in _ids(outer)


def test_normal_token_has_no_nesting_findings() -> None:
    # Negativo: sem 'cty' e sem claim parecida com JWT — nenhum sinal de aninhamento.
    token = hs_token({"exp": NOW + 60, "iat": NOW, "aud": "x", "iss": "y", "sub": "a.b.c"})
    ids = _ids(token)
    assert "header-cty-nested" not in ids
    assert "payload-nested-jwt" not in ids


def test_well_formed_rs_token_is_clean() -> None:
    token = raw_token(
        {"alg": "RS256", "typ": "JWT"},
        {"sub": "z", "exp": NOW + 60, "iat": NOW, "aud": "api", "iss": "auth"},
    )
    assert run_all(decode(token), NOW) == []
