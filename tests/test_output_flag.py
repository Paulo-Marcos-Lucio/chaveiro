"""Invariante do `--output/-o` (item CH-01 da fila de cadência).

`inspect` e `batch` já sabiam gravar o laudo em arquivo em vez de imprimir no
stdout (commit 042ccae). O que faltava travar era o contrato exato que o
critério de aceite exige — não "grava alguma coisa", mas:

  1. com `-o`, nada vai para o stdout;
  2. o arquivo é BYTE-IDÊNTICO ao stdout do mesmo comando sem `-o`;
  3. o `artifact_sha256` recomputado sobre o documento gravado confere com o
     campo gravado.

O defeito real que este teste pegou: `_emit` escrevia o arquivo sem a quebra
de linha final que `typer.echo` sempre acrescenta no stdout — um `laudo.json`
gerado por `-o` divergia do `chaveiro ... > laudo.json` equivalente por
exatamente um byte (`\n`). Passava despercebido porque nenhum teste comparava
os dois canais; comparar só o JSON decodificado (como `test_cli.py` já fazia)
escondia a diferença de bytes.

A invariante é property-based porque o defeito não é de um token específico —
é da forma como qualquer laudo é serializado. Gerar payloads arbitrários evita
consertar só o exemplo que apareceu no relatório e travar a classe inteira.
"""

from __future__ import annotations

import json
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from typer.testing import CliRunner

from chaveiro.cli import app
from chaveiro.report.provenance import artifact_sha256
from tests.conftest import raw_token

runner = CliRunner()
NOW = 1_800_000_000

# Chaves e valores de claim simples — o que varia aqui é o CONTEÚDO do laudo,
# não a mecânica de JWT (já coberta em test_jwt.py/test_attacks.py).
_CHAVE = st.sampled_from(["sub", "role", "email", "nota", "aud", "custom", "x"])
_VALOR = st.one_of(
    st.text(min_size=0, max_size=12),
    st.integers(min_value=-1000, max_value=1000),
    st.booleans(),
    st.none(),
)
_CLAIMS = st.dictionaries(_CHAVE, _VALOR, min_size=0, max_size=5)


def _assert_byte_identico_e_hash_confere(sem_o: str, arquivo: Path) -> None:
    """As três pernas da invariante, num só lugar para não divergir entre inspect/batch."""
    esperado = sem_o.encode("utf-8")
    obtido = arquivo.read_bytes()
    assert obtido == esperado, (
        f"-o não é byte-idêntico ao stdout equivalente: "
        f"{len(obtido)} bytes gravados vs {len(esperado)} esperados"
    )
    doc = json.loads(obtido.decode("utf-8"))
    assert artifact_sha256(doc) == doc["artifact_sha256"], "artifact_sha256 recomputado não confere"


@settings(max_examples=40, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(claims=_CLAIMS)
def test_inspect_output_byte_identico_e_hash_confere(claims: dict, tmp_path: Path) -> None:
    token = raw_token({"alg": "none"}, claims)

    sem_o = runner.invoke(app, ["inspect", token, "-f", "json", "--now", str(NOW)])
    assert sem_o.exit_code in (0, 1)

    destino = tmp_path / "laudo.json"
    com_o = runner.invoke(
        app, ["inspect", token, "-f", "json", "-o", str(destino), "--now", str(NOW)]
    )
    assert com_o.exit_code == sem_o.exit_code
    assert com_o.stdout == "", "com -o, nada deveria ir para o stdout"

    _assert_byte_identico_e_hash_confere(sem_o.stdout, destino)
    destino.unlink()


@settings(max_examples=25, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(claims_lote=st.lists(_CLAIMS, min_size=1, max_size=4))
def test_batch_output_byte_identico_e_hash_confere(claims_lote: list[dict], tmp_path: Path) -> None:
    texto = "\n".join(raw_token({"alg": "none"}, c) for c in claims_lote)
    entrada = tmp_path / "tokens.txt"
    entrada.write_text(texto, encoding="utf-8")

    sem_o = runner.invoke(app, ["batch", str(entrada), "-f", "json", "--now", str(NOW)])
    assert sem_o.exit_code in (0, 1)

    destino = tmp_path / "laudo-lote.json"
    com_o = runner.invoke(
        app, ["batch", str(entrada), "-f", "json", "-o", str(destino), "--now", str(NOW)]
    )
    assert com_o.exit_code == sem_o.exit_code
    assert com_o.stdout == "", "com -o, nada deveria ir para o stdout"

    _assert_byte_identico_e_hash_confere(sem_o.stdout, destino)


# --------------------------------------------------------------------------- #
# Exemplos literais do critério de aceite: `-o` exige `--format json`.
# --------------------------------------------------------------------------- #


def test_inspect_output_exige_format_json(tmp_path: Path) -> None:
    token = raw_token({"alg": "none"}, {"sub": "admin"})
    result = runner.invoke(app, ["inspect", token, "-o", str(tmp_path / "x.json")])
    assert result.exit_code == 2


def test_batch_output_exige_format_json(tmp_path: Path) -> None:
    entrada = tmp_path / "tokens.txt"
    entrada.write_text(raw_token({"alg": "none"}, {"sub": "admin"}), encoding="utf-8")
    result = runner.invoke(app, ["batch", str(entrada), "-o", str(tmp_path / "x.json")])
    assert result.exit_code == 2
