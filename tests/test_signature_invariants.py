"""CH-09b — invariantes de FORMA da assinatura: ES256/384/512/256K com r=0 ou s=0 é sempre
CRITICAL (`signature-ecdsa-invalid-point`); uma assinatura ECDSA/HMAC genuína nunca dispara os
achados de forma; HS256/384/512 têm comprimento fixo (`signature-hmac-length-mismatch`).

Por que isto é uma classe, não um exemplo: r=0 (ou s=0) numa assinatura ECDSA é a "assinatura
psíquica" (CVE-2022-21449) — quando um verificador não rejeita esse caso degenerado, QUALQUER
mensagem verifica sob a chave, sem conhecer o segredo. O critério de aceite cita "ES256 r=0"
como exemplo; os testes de propriedade abaixo cobrem TODO valor de r/s (zero ou não) em TODO
algoritmo ECDSA suportado (ES256/ES384/ES512/ES256K), não só o caso citado.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from chaveiro.checks.detectors import run_all
from chaveiro.core.jwt import decode, encode_hmac
from tests.conftest import raw_token, sign_es256

NOW = 1_800_000_000

# Tamanho (bytes) do componente r/s por algoritmo — espelha _ECDSA_COMPONENT_LEN de
# detectors.py; duplicado aqui de propósito (o teste não pode importar o alvo privado e
# concordar com ele por construção, senão uma inversão no mapa de produção passaria batida).
_TAMANHO_COMPONENTE = {"ES256": 32, "ES256K": 32, "ES384": 48, "ES512": 66}
_TAMANHO_HMAC = {"HS256": 32, "HS384": 48, "HS512": 64}


def _ids(token: str) -> set[str]:
    return {f.check_id for f in run_all(decode(token), NOW)}


def _bytes_nao_zero(dados: bytes, tamanho: int) -> bytes:
    """`dados` ajustado para exatamente `tamanho` bytes, garantidamente NÃO all-zero (o padding
    à esquerda de um `dados` todo-zero ainda seria zero; força o último byte a 1 nesse caso)."""
    ajustado = dados[:tamanho].rjust(tamanho, b"\x00")
    if ajustado.count(0) == tamanho:
        ajustado = ajustado[:-1] + b"\x01"
    return ajustado


# --------------------------------------------------------------------------- #
# INVARIANTE 1 — r=0 OU s=0 em QUALQUER algoritmo ECDSA suportado é SEMPRE
# signature-ecdsa-invalid-point; r,s não-zero NUNCA dispara. Isto é a classe do
# exemplo "ES256 r=0" do critério de aceite.
# --------------------------------------------------------------------------- #
@settings(max_examples=300)
@given(
    alg=st.sampled_from(sorted(_TAMANHO_COMPONENTE)),
    r_zero=st.booleans(),
    s_zero=st.booleans(),
    r_bytes=st.binary(min_size=1, max_size=66),
    s_bytes=st.binary(min_size=1, max_size=66),
)
def test_es256_r_zero_e_qualquer_curva_com_r_ou_s_zero_e_sempre_critical(
    alg: str, r_zero: bool, s_zero: bool, r_bytes: bytes, s_bytes: bytes
) -> None:
    n = _TAMANHO_COMPONENTE[alg]
    r = b"\x00" * n if r_zero else _bytes_nao_zero(r_bytes, n)
    s = b"\x00" * n if s_zero else _bytes_nao_zero(s_bytes, n)
    token = raw_token({"alg": alg}, {"sub": "a"}, signature=r + s)
    disparou = "signature-ecdsa-invalid-point" in _ids(token)
    assert disparou is (r_zero or s_zero), (
        f"{alg}: r_zero={r_zero} s_zero={s_zero} deveria disparar={r_zero or s_zero}, "
        f"disparou={disparou}"
    )


# --------------------------------------------------------------------------- #
# INVARIANTE 2 — uma assinatura ECDSA GENUÍNA (chave real, cryptography.hazmat) nunca dispara
# o achado de forma, para qualquer payload. Reforça a invariante 1 com o caso que mais importa:
# o tráfego legítimo não pode ser o falso positivo.
# --------------------------------------------------------------------------- #
@settings(max_examples=50)
@given(sub=st.text(min_size=1, max_size=20), exp_offset=st.integers(min_value=1, max_value=10**6))
def test_assinatura_valida_nunca_dispara(sub: str, exp_offset: int) -> None:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    token = sign_es256({"sub": sub, "exp": NOW + exp_offset, "iat": NOW}, pem)
    ids = _ids(token)
    assert "signature-ecdsa-invalid-point" not in ids
    assert "signature-empty" not in ids
    assert "signature-hmac-length-mismatch" not in ids


# --------------------------------------------------------------------------- #
# INVARIANTE 3 — HS256/384/512: comprimento diferente do fixo do algoritmo SEMPRE dispara
# signature-hmac-length-mismatch; o comprimento correto NUNCA dispara — para QUALQUER
# comprimento errado, não só um exemplo hardcoded.
# --------------------------------------------------------------------------- #
@settings(max_examples=200)
@given(
    alg=st.sampled_from(sorted(_TAMANHO_HMAC)),
    tamanho=st.integers(min_value=1, max_value=100),
)
def test_hs256_len_fixo_qualquer_tamanho_errado_dispara_e_o_certo_nao(
    alg: str, tamanho: int
) -> None:
    esperado = _TAMANHO_HMAC[alg]
    token = raw_token({"alg": alg}, {"sub": "a"}, signature=b"\x01" * tamanho)
    disparou = "signature-hmac-length-mismatch" in _ids(token)
    assert disparou is (tamanho != esperado), (
        f"{alg}: tamanho={tamanho} esperado={esperado} deveria disparar={tamanho != esperado}, "
        f"disparou={disparou}"
    )


# --------------------------------------------------------------------------- #
# INVARIANTE 4 — um HMAC GENUÍNO (`encode_hmac`, usado pelo resto da suíte) nunca dispara o
# mismatch de comprimento, para qualquer segredo/payload — o tráfego legítimo não é o FP.
# --------------------------------------------------------------------------- #
@settings(max_examples=100)
@given(
    alg=st.sampled_from(sorted(_TAMANHO_HMAC)),
    secret=st.text(min_size=1, max_size=40),
    sub=st.text(min_size=1, max_size=20),
)
def test_hmac_genuino_nunca_dispara_mismatch(alg: str, secret: str, sub: str) -> None:
    token = encode_hmac({"alg": alg, "typ": "JWT"}, {"sub": sub}, secret.encode("utf-8"))
    assert "signature-hmac-length-mismatch" not in _ids(token)
