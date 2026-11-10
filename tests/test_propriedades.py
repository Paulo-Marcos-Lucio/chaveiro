"""Testes property-based (Hypothesis) da INVARIANTE de privacidade da redação LGPD.

O Chaveiro grava laudos com claims de JWT — que frequentemente carregam PII do titular
(sub, email, CPF). Vazar PII num laudo é falha de LGPD, o "bug sério achado tarde" clássico.
Os testes por exemplo cobrem os e-mails/CPFs que alguém digitou; estes geram milhares e
afirmam as propriedades que não podem falhar:

    1. e-mail como valor, sob qualquer chave não-estrutural, é sempre redigido;
    2. CPF válido (mód-11), idem;
    3. chaves estruturais (exp/iat/aud/...) nunca são redigidas — não destruir o laudo;
    4. JWE: 'p2c' acima do teto PBES2 sempre gera achado; abaixo, nunca (AUD0908).
"""

from __future__ import annotations

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from chaveiro.checks.detectors import _PBES2_P2C_TETO, check_jwe_header, has_cpf
from chaveiro.core.jwt import decode
from chaveiro.report.redaction import REDIGIDO, redact_claims
from tests.conftest import jwe_token

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


@settings(max_examples=150)
@given(p2c=st.integers(min_value=_PBES2_P2C_TETO + 1, max_value=_PBES2_P2C_TETO * 100))
def test_jwe_p2c_acima_do_teto_sempre_gera_achado(p2c: int) -> None:
    """INVARIANTE 4 (AUD0908): qualquer 'p2c' acima do teto PBES2 — o atacante controla
    esse valor no header em claro — tem que virar achado, nunca silêncio."""
    header = {"alg": "PBES2-HS256+A128KW", "enc": "A128CBC-HS256", "p2c": p2c}
    findings = check_jwe_header(decode(jwe_token(header)))
    assert any(f.check_id == "jwe-pbes2-p2c-alto" for f in findings)


@settings(max_examples=150)
@given(p2c=st.integers(min_value=1, max_value=_PBES2_P2C_TETO))
def test_jwe_p2c_dentro_do_teto_nunca_gera_achado(p2c: int) -> None:
    """Contraparte: nenhum p2c dentro do teto (faixa que um emissor real usaria) é acusado."""
    header = {"alg": "PBES2-HS256+A128KW", "enc": "A128CBC-HS256", "p2c": p2c}
    findings = check_jwe_header(decode(jwe_token(header)))
    assert not any(f.check_id == "jwe-pbes2-p2c-alto" for f in findings)
