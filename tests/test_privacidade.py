"""Privacidade do laudo: redação de PII do titular e token fora do argv.

Defeitos que estes testes travam:
- P1-01: o relatório gravava 100% das claims (sub/email/cpf/nome) no JSON e no
  console — PII do TITULAR FINAL do cliente, sem necessidade (operador LGPD).
- P1-02: o JWT entrava por argv, vazando no histórico do shell e na lista de
  processos, sem o caminho seguro (stdin) ser padrão nem sinalizado.
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from chaveiro.cli import app
from tests.conftest import hs_token, raw_token

runner = CliRunner()
NOW = 1_800_000_000
CPF_VALIDO = "529.982.247-25"  # dígitos verificadores corretos (mód-11)


def _token_com_pii() -> str:
    return hs_token(
        {
            "sub": "user-42",
            "email": "joao.titular@example.com",
            "name": "João da Silva",
            "cpf": CPF_VALIDO,
            "role": "admin",
            "exp": NOW + 60,
            "iat": NOW,
            "aud": "api",
            "iss": "https://auth",
        },
        secret="k",
    )


def test_claims_de_identidade_sao_redigidas_por_padrao() -> None:
    result = runner.invoke(app, ["inspect", _token_com_pii(), "-f", "json", "--now", str(NOW)])
    doc = json.loads(result.stdout)
    claims = doc["token"]["claims"]
    # PII do titular: redigida
    assert claims["sub"] != "user-42"
    assert claims["email"] != "joao.titular@example.com"
    assert claims["name"] != "João da Silva"
    assert claims["cpf"] != CPF_VALIDO
    # e não vaza em NENHUM lugar do JSON serializado
    assert "joao.titular@example.com" not in result.stdout
    assert CPF_VALIDO not in result.stdout
    # claim não-identidade e claims estruturais permanecem visíveis
    assert claims["role"] == "admin"
    assert claims["iss"] == "https://auth"
    assert claims["exp"] == NOW + 60


def test_flag_claims_completas_mostra_tudo() -> None:
    result = runner.invoke(
        app, ["inspect", _token_com_pii(), "-f", "json", "--claims-completas", "--now", str(NOW)]
    )
    doc = json.loads(result.stdout)
    claims = doc["token"]["claims"]
    assert claims["email"] == "joao.titular@example.com"
    assert claims["cpf"] == CPF_VALIDO
    # opt-in explícito tem que AVISAR que a PII está em claro
    assert "claims-completas" in result.stderr or "PII" in result.stderr


def test_redacao_alcanca_pii_aninhada_em_dict_e_lista() -> None:
    # A forma mais comum de payload no Brasil é {"user": {"cpf": ...}}: redigir só
    # o primeiro nível deixaria a PII vazar. E um VALOR de e-mail/CPF é redigido
    # mesmo sob uma chave de nome inocente.
    from chaveiro.report.redaction import REDIGIDO, redact_claims

    limpo = redact_claims(
        {
            "user": {"cpf": CPF_VALIDO, "role": "admin"},
            "contatos": ["fulano@example.com", "só-texto"],
            "referencia": f"cadastro de {CPF_VALIDO}",
            "iss": "https://auth",
        }
    )
    assert limpo["user"]["cpf"] == REDIGIDO
    assert limpo["user"]["role"] == "admin"
    assert limpo["contatos"][0] == REDIGIDO
    assert limpo["contatos"][1] == "só-texto"
    assert limpo["referencia"] == REDIGIDO
    assert limpo["iss"] == "https://auth"


def test_inspect_le_token_de_stdin() -> None:
    token = raw_token({"alg": "none"}, {"sub": "x"})
    result = runner.invoke(app, ["inspect", "-", "-f", "json", "--now", str(NOW)], input=token)
    assert result.exit_code == 1
    doc = json.loads(result.stdout)
    assert any(f["id"] == "alg-none" for f in doc["findings"])
    # stdin é o caminho seguro: NÃO deve disparar o aviso de argv
    assert "histórico do shell" not in result.stderr


def test_avisa_quando_token_vem_por_argv() -> None:
    token = hs_token({"sub": "a"}, secret="k")
    result = runner.invoke(app, ["inspect", token, "--now", str(NOW)])
    # o aviso tem que explicar o risco e o caminho alternativo (stdin/'-')
    assert "histórico do shell" in result.stderr
    assert "stdin" in result.stderr or "'-'" in result.stderr


def test_crack_e_forge_tambem_leem_de_stdin() -> None:
    token = hs_token({"sub": "a"}, secret="secret")
    r_crack = runner.invoke(app, ["crack", "-"], input=token)
    assert r_crack.exit_code == 1  # segredo fraco encontrado, veio do stdin
    r_forge = runner.invoke(
        app, ["forge", "-", "--secret", "k", "--set", "role=admin"], input=token
    )
    assert r_forge.exit_code == 0
    assert r_forge.stdout.strip().count(".") == 2
