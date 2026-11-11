"""Testes property-based (Hypothesis) da INVARIANTE de privacidade da redação LGPD.

O Chaveiro grava laudos com claims de JWT — que frequentemente carregam PII do titular
(sub, email, CPF). Vazar PII num laudo é falha de LGPD, o "bug sério achado tarde" clássico.
Os testes por exemplo cobrem os e-mails/CPFs que alguém digitou; estes geram milhares e
afirmam as propriedades que não podem falhar:

    1. e-mail como valor, sob qualquer chave não-estrutural, é sempre redigido;
    2. CPF válido (mód-11), idem;
    3. chaves estruturais (exp/iat/aud/...) nunca são redigidas — não destruir o laudo.
"""

from __future__ import annotations

import json

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from chaveiro.checks.detectors import has_cpf, run_all
from chaveiro.core.jwt import b64url_encode, decode
from chaveiro.report.redaction import REDIGIDO, redact_claims

NOW = 1_800_000_000

_CHAVES_INOCENTES = st.sampled_from(["nota", "obs", "custom", "documento", "campo_x", "dados"])
_ESTRUTURAIS = st.sampled_from(["alg", "exp", "iat", "nbf", "iss", "aud", "typ", "kid", "jti"])


@st.composite
def cpfs_validos(draw: st.DrawFn) -> str:
    """Gera um CPF com dígitos verificadores válidos, formatado ddd.ddd.ddd-dd."""
    base = draw(st.lists(st.integers(0, 9), min_size=9, max_size=9))

    def _dv(digs: list[int]) -> int:
        peso = len(digs) + 1
        s = sum(d * (peso - i) for i, d in enumerate(digs))
        r = s % 11
        return 0 if r < 2 else 11 - r

    d1 = _dv(base)
    d2 = _dv([*base, d1])
    nums = [*base, d1, d2]
    cpf = "".join(map(str, nums))
    return f"{cpf[:3]}.{cpf[3:6]}.{cpf[6:9]}-{cpf[9:]}"


@settings(max_examples=200)
@given(chave=_CHAVES_INOCENTES, email=st.emails())
def test_email_por_valor_sempre_redigido(chave: str, email: str) -> None:
    """INVARIANTE 1: e-mail como valor, sob qualquer chave, some do laudo."""
    saida = redact_claims({chave: f"contato: {email}"})
    assert saida[chave] == REDIGIDO, f"e-mail vazou sob {chave!r}: {saida[chave]!r}"


@settings(max_examples=200)
@given(chave=_CHAVES_INOCENTES, cpf=cpfs_validos())
def test_cpf_valido_por_valor_sempre_redigido(chave: str, cpf: str) -> None:
    """INVARIANTE 2: CPF válido como valor, sob qualquer chave, é redigido."""
    assume(has_cpf(cpf))  # ignora os poucos padrões que o validador mód-11 rejeita
    saida = redact_claims({chave: f"doc {cpf} do titular"})
    assert saida[chave] == REDIGIDO, f"CPF vazou sob {chave!r}: {saida[chave]!r}"
    assert cpf not in str(saida), "CPF cru sobreviveu no laudo"


@settings(max_examples=150)
@given(chave=_ESTRUTURAIS, valor=st.integers(0, 2_000_000_000))
def test_chave_estrutural_nunca_e_redigida(chave: str, valor: int) -> None:
    """INVARIANTE 3: metadados do token (exp/iat/aud/...) não podem ser destruídos pela redação."""
    saida = redact_claims({chave: valor})
    assert saida[chave] == valor, f"chave estrutural {chave!r} foi redigida indevidamente"


# --------------------------------------------------------------------------- #
# INVARIANTE 4 (AUD0908-fn-rfc7797-b64false-nao-modelado): um cabeçalho com
# 'b64:false' (RFC 7797, payload não codificado) nunca pode ser descartado como
# token malformado só porque o payload não é base64url-de-JSON — e precisa
# sempre gerar o achado DEDICADO de confusão b64/crit, não o header-crit
# genérico (que não comunica o risco real de RFC 7797 §6). Vale para qualquer
# conteúdo de payload cru e qualquer valor de 'crit', inclusive o caso mais
# perigoso: 'crit' sem 'b64'.
# --------------------------------------------------------------------------- #

_CRIT_VARIANTES = st.one_of(
    st.none(),
    st.just(["b64"]),
    st.just(["exp", "b64"]),
    st.just(["exp"]),  # falta 'b64' no crit — o caso mais perigoso do RFC 7797 §6
)


@settings(max_examples=150)
@given(payload_cru=st.text(max_size=40).filter(lambda s: "." not in s), crit=_CRIT_VARIANTES)
def test_b64_false_e_sempre_auditado_com_achado_dedicado(
    payload_cru: str, crit: list[str] | None
) -> None:
    header: dict[str, object] = {"alg": "HS256", "b64": False}
    if crit is not None:
        header["crit"] = crit
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    sig_b64 = b64url_encode(b"sig")
    token = f"{header_b64}.{payload_cru}.{sig_b64}"

    decoded = decode(token)  # nao pode levantar JWTError, qualquer que seja o payload cru
    ids = {f.check_id for f in run_all(decoded, NOW)}

    assert "header-b64-false" in ids, f"b64:false nao gerou achado dedicado (crit={crit!r})"
    assert "header-crit" not in ids, "header-crit generico nao devia sobreviver ao b64:false"
