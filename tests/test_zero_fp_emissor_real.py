"""Teste property-based (Hypothesis) da INVARIANTE "emissor real não gera FP grave".

`bench/` mede falso-positivo com um corpus fixo de 6 negativos (§C02). Um
corpus fixo prova que os exemplos plantados passam limpos — não prova que a
FORMA (ordem de claims, presença de `nbf`, presença de `roles`) é irrelevante
para a auditoria. Este teste é o complemento: gera centenas de tokens de
emissor real (RS*/PS*/ES*/EdDSA — os mesmos que `bench/` usa como negativo,
porque um HS* bem-formado ainda dispara o aviso `alg-hmac-advisory`, LOW) com
claims completas, permutando a ORDEM das claims no payload e variando `nbf`
(ausente / agora / no passado) e `roles` (ausente / vazia / com papéis), e
afirma que nenhuma combinação produz achado de severidade >= MEDIUM.

Se um detector algum dia passar a depender de posição de claim, ou tratar
`nbf`/`roles` bem-formados como suspeitos, o Hypothesis encontra o
contraexemplo e o encolhe (shrink) para o caso mínimo — não é preciso que
alguém tenha pensado nesse vetor específico de antemão.
"""

from __future__ import annotations

import json

from hypothesis import given, settings
from hypothesis import strategies as st

from chaveiro.audit import audit_token
from chaveiro.core.jwt import b64url_encode
from chaveiro.core.models import Severity

# 'agora' fixo: torna exp/iat/nbf reprodutíveis entre execuções (mesmo padrão de bench/gerar.py).
AGORA = 1_800_000_000

# Emissores REAIS (assimétricos) — universo idêntico ao de bench/gerar.py:negativos().
# HS* fica de fora de propósito: um HS* bem-formado ainda dispara 'alg-hmac-advisory'
# (LOW), então não é um emissor "limpo" para esta invariante (LOW não conta — o teste
# só barra >= MEDIUM).
_EMISSORES_REAIS = (
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "EdDSA",
)


def _token_raw(header: dict[str, object], payload: dict[str, object]) -> str:
    """JWS compacto arbitrário — a auditoria é passiva e nunca verifica assinatura."""
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return f"{h}.{p}.{b64url_encode(b'sig')}"


@st.composite
def claims_de_emissor_real(draw: st.DrawFn) -> tuple[dict[str, object], dict[str, object]]:
    """Um (header, payload) de token "bem comportado", com claims em ordem embaralhada."""
    alg = draw(st.sampled_from(_EMISSORES_REAIS))
    lifetime = draw(st.integers(min_value=60, max_value=24 * 3600))  # <= _LONG_LIFETIME_S
    nbf_modo = draw(st.sampled_from(["ausente", "agora", "passado"]))
    roles = draw(
        st.one_of(
            st.none(),  # claim ausente
            st.just([]),  # presente e vazia
            st.lists(
                st.sampled_from(["user", "admin", "editor", "viewer", "auditor"]),
                min_size=1,
                max_size=4,
                unique=True,
            ),
        )
    )

    payload: dict[str, object] = {
        "sub": "user-1",
        "exp": AGORA + lifetime,
        "iat": AGORA,
        "aud": "api",
        "iss": "https://auth",
    }
    if nbf_modo == "agora":
        payload["nbf"] = AGORA
    elif nbf_modo == "passado":
        payload["nbf"] = AGORA - draw(st.integers(min_value=1, max_value=lifetime))
    if roles is not None:
        payload["roles"] = roles
        payload["scope"] = "read"

    # ORDEM: nenhuma checagem deve depender de em que posição uma claim aparece —
    # a mesma claim, em qualquer posição do payload, tem que produzir o mesmo veredito.
    chaves_embaralhadas = draw(st.permutations(list(payload.keys())))
    payload_embaralhado = {k: payload[k] for k in chaves_embaralhadas}

    header = {"alg": alg, "typ": "JWT"}
    return header, payload_embaralhado


@settings(max_examples=300)
@given(claims_de_emissor_real())
def test_zero_fp_em_emissor_real(par: tuple[dict[str, object], dict[str, object]]) -> None:
    """INVARIANTE: emissor real + claims completas, em qualquer ordem/nbf/roles, => zero >=MEDIUM."""
    header, payload = par
    token = _token_raw(header, payload)
    resultado = audit_token(token, AGORA)
    graves = [f for f in resultado.findings if f.severity.rank >= Severity.MEDIUM.rank]
    assert not graves, (
        f"emissor real {header['alg']!r} gerou achado >=MEDIUM: "
        f"{[(f.check_id, f.severity.value) for f in graves]} — payload={payload!r}"
    )
