"""Checagens de JWE (RFC 7516) — cabeçalho protegido, sem decifrar nada.

Item CHV-02: sobre um JWE, o Chaveiro precisa emitir achado para 'p2c' abusivo
(Billion Hash), 'zip: DEF' (DoS de descompressão) e 'alg'/'enc' fora da
allowlist — cada um com CWE, OWASP e recomendação.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from chaveiro.checks.detectors import _JWE_P2C_MAX, check_jwe_header, run_all
from chaveiro.core.jwt import JWTError, decode
from tests.conftest import jwe_token

_PBES2 = "PBES2-HS256+A128KW"


def _ids(header: dict) -> set[str]:
    token = decode(jwe_token(header))
    return {f.check_id for f in check_jwe_header(token)}


# --------------------------------------------------------------------------- #
# decode() reconhece o JWE de 5 segmentos
# --------------------------------------------------------------------------- #


def test_decode_reconhece_jwe_de_5_segmentos() -> None:
    token = decode(jwe_token({"alg": "RSA-OAEP-256", "enc": "A256GCM"}))
    assert token.kind == "jwe"
    assert token.header == {"alg": "RSA-OAEP-256", "enc": "A256GCM"}
    assert token.payload == {}  # cifrado — não é "sem claims", é "ilegível sem a chave"
    assert token.alg == "RSA-OAEP-256"  # aqui é gerenciamento de chave, não assinatura


def test_decode_rejeita_contagem_de_segmentos_que_nao_e_3_nem_5() -> None:
    with pytest.raises(JWTError):
        decode("a.b.c.d")


def test_run_all_roteia_jwe_para_check_jwe_header_e_nao_para_checagens_de_jws() -> None:
    # alg='dir' é gerenciamento de chave válido; se run_all rodasse check_alg
    # (vocabulário de JWS) por engano, 'dir' cairia em alg-unknown — falso positivo.
    token = decode(jwe_token({"alg": "dir", "enc": "A256GCM"}))
    findings = run_all(token, now=0)
    assert findings == []
    ids = {f.check_id for f in findings}
    assert "alg-unknown" not in ids
    assert "claim-no-exp" not in ids  # payload vazio não é "token eterno"


# --------------------------------------------------------------------------- #
# alg / enc fora da allowlist
# --------------------------------------------------------------------------- #


def test_alg_rsa1_5_e_achado_de_alta_severidade() -> None:
    assert _ids({"alg": "RSA1_5", "enc": "A128CBC-HS256"}) == {"jwe-alg-rsa15"}


def test_alg_fora_da_allowlist_gera_achado() -> None:
    assert "jwe-alg-unknown" in _ids({"alg": "XYZ-nao-existe", "enc": "A256GCM"})


def test_enc_fora_da_allowlist_gera_achado() -> None:
    assert "jwe-enc-unknown" in _ids({"alg": "dir", "enc": "XYZ-nao-existe"})


def test_alg_e_enc_conhecidos_nao_geram_achado_de_allowlist() -> None:
    ids = _ids({"alg": "ECDH-ES+A128KW", "enc": "A128GCM"})
    assert "jwe-alg-unknown" not in ids
    assert "jwe-enc-unknown" not in ids


# --------------------------------------------------------------------------- #
# zip: DEF
# --------------------------------------------------------------------------- #


def test_zip_def_gera_achado_de_descompressao() -> None:
    assert "jwe-zip-dos" in _ids({"alg": "dir", "enc": "A256GCM", "zip": "DEF"})


def test_sem_zip_nao_gera_achado() -> None:
    assert "jwe-zip-dos" not in _ids({"alg": "dir", "enc": "A256GCM"})


# --------------------------------------------------------------------------- #
# p2c (PBES2) — inclui a propriedade que tranca a CLASSE do defeito, não só o
# exemplo: qualquer p2c acima do teto emite o achado, qualquer p2c dentro do
# intervalo plausível não emite.
# --------------------------------------------------------------------------- #


def test_p2c_acima_do_teto_gera_achado() -> None:
    ids = _ids({"alg": _PBES2, "enc": "A128CBC-HS256", "p2c": _JWE_P2C_MAX + 1, "p2s": "c2FsdA"})
    assert "jwe-p2c-abusive" in ids


def test_p2c_no_teto_nao_gera_achado() -> None:
    ids = _ids({"alg": _PBES2, "enc": "A128CBC-HS256", "p2c": _JWE_P2C_MAX, "p2s": "c2FsdA"})
    assert "jwe-p2c-abusive" not in ids


def test_p2c_alto_em_alg_nao_pbes2_e_ignorado() -> None:
    # 'p2c' só tem sentido sob um alg PBES2-*; noutro alg é campo estranho, não abuso.
    ids = _ids({"alg": "dir", "enc": "A256GCM", "p2c": _JWE_P2C_MAX * 100})
    assert "jwe-p2c-abusive" not in ids


@settings(max_examples=200)
@given(p2c=st.integers(min_value=0, max_value=_JWE_P2C_MAX))
def test_invariante_p2c_dentro_do_teto_nunca_dispara(p2c: int) -> None:
    assert "jwe-p2c-abusive" not in _ids({"alg": _PBES2, "enc": "A128CBC-HS256", "p2c": p2c})


@settings(max_examples=200)
@given(p2c=st.integers(min_value=_JWE_P2C_MAX + 1, max_value=_JWE_P2C_MAX * 1000))
def test_invariante_p2c_acima_do_teto_sempre_dispara(p2c: int) -> None:
    assert "jwe-p2c-abusive" in _ids({"alg": _PBES2, "enc": "A128CBC-HS256", "p2c": p2c})


# --------------------------------------------------------------------------- #
# cada achado carrega CWE, OWASP e recomendação (exigido pelo critério de aceite)
# --------------------------------------------------------------------------- #


def test_todo_achado_de_jwe_tem_cwe_owasp_e_recomendacao() -> None:
    header = {
        "alg": "RSA1_5",
        "enc": "XYZ-nao-existe",
        "zip": "DEF",
    }
    token = decode(jwe_token(header))
    findings = check_jwe_header(token)
    assert {f.check_id for f in findings} == {"jwe-alg-rsa15", "jwe-enc-unknown", "jwe-zip-dos"}
    for finding in findings:
        assert finding.cwe, finding.check_id
        assert finding.owasp, finding.check_id
        assert finding.recommendation, finding.check_id


def test_token_conforme_nao_gera_achado_nenhum() -> None:
    header = {"alg": "ECDH-ES+A256KW", "enc": "A256GCM"}
    assert check_jwe_header(decode(jwe_token(header))) == []
