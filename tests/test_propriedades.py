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

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from chaveiro.checks.detectors import has_cpf, run_all
from chaveiro.core.jwt import decode
from chaveiro.report.redaction import REDIGIDO, redact_claims
from tests.conftest import hs_token

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
# Testes property-based da INVARIANTE do perfil access-token (CHV-03,
# RFC 9068). O defeito original: a checagem de claims era genérica e cobrava
# 'aud' de qualquer token, inclusive de um access token legítimo que
# simplesmente não a inclui — falso positivo. A correção não pode travar só
# o exemplo que apareceu no relatório; precisa travar a CLASSE: nenhuma
# combinação de claims extras faz 'aud' voltar a ser cobrada no perfil
# access-token, e 'sub'/'client_id' (o substituto do RFC 9068) nunca são
# perdoados quando realmente faltam.
# --------------------------------------------------------------------------- #

NOW_PERFIL = 1_800_000_000
_CLAIM_EXTRAS = st.dictionaries(
    st.sampled_from(["scope", "jti", "nota", "custom_claim", "amr"]),
    st.one_of(st.text(max_size=20), st.integers(0, 10_000)),
    max_size=4,
)


@settings(max_examples=200)
@given(extra=_CLAIM_EXTRAS)
def test_access_token_legitimo_sem_aud_nunca_e_achado(extra: dict) -> None:
    """INVARIANTE 4: no perfil access-token ('typ: at+jwt'), 'iss'/'exp'/'iat'/
    'sub'/'client_id' presentes e 'aud' ausente NUNCA produz achado — não
    importa que outras claims o token carregue."""
    payload = {
        "iss": "https://as.example",
        "sub": "user-1",
        "client_id": "client-1",
        "exp": NOW_PERFIL + 300,
        "iat": NOW_PERFIL,
        **{k: v for k, v in extra.items() if k != "aud"},
    }
    token = hs_token(payload, typ="at+jwt")
    findings = {f.check_id for f in run_all(decode(token), NOW_PERFIL)}
    assert "claim-no-aud" not in findings, "perfil access-token voltou a cobrar 'aud'"
    assert "claim-no-sub" not in findings
    assert "claim-no-client-id" not in findings


@settings(max_examples=200)
@given(extra=_CLAIM_EXTRAS)
def test_generico_sem_aud_continua_achado(extra: dict) -> None:
    """INVARIANTE 4 (outro lado): o MESMO conjunto de claims, sem 'typ: at+jwt',
    continua cobrando 'aud' — a supressão é decisão do perfil access-token, não
    uma regressão geral da checagem de claims."""
    payload = {
        "iss": "https://as.example",
        "sub": "user-1",
        "client_id": "client-1",
        "exp": NOW_PERFIL + 300,
        "iat": NOW_PERFIL,
        **{k: v for k, v in extra.items() if k != "aud"},
    }
    token = hs_token(payload)  # typ padrão 'JWT' — perfil genérico
    findings = {f.check_id for f in run_all(decode(token), NOW_PERFIL)}
    assert "claim-no-aud" in findings, "perfil genérico parou de cobrar 'aud'"


@settings(max_examples=200)
@given(tem_sub=st.booleans(), tem_client_id=st.booleans(), extra=_CLAIM_EXTRAS)
def test_access_token_cobra_sub_e_client_id_quando_ausentes(
    tem_sub: bool, tem_client_id: bool, extra: dict
) -> None:
    """INVARIANTE 4 (o substituto): no perfil access-token, 'sub' e 'client_id'
    ausentes SEMPRE viram achado, para qualquer combinação de presença dos
    dois e qualquer claim extra — são o preço de não cobrar mais 'aud'."""
    payload = {
        "iss": "https://as.example",
        "exp": NOW_PERFIL + 300,
        "iat": NOW_PERFIL,
        **{k: v for k, v in extra.items() if k not in ("sub", "client_id", "aud")},
    }
    if tem_sub:
        payload["sub"] = "user-1"
    if tem_client_id:
        payload["client_id"] = "client-1"
    token = hs_token(payload, typ="at+jwt")
    findings = {f.check_id for f in run_all(decode(token), NOW_PERFIL)}
    assert ("claim-no-sub" in findings) == (not tem_sub)
    assert ("claim-no-client-id" in findings) == (not tem_client_id)
    assert "claim-no-aud" not in findings
