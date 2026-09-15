"""Proveniência do envelope JSON (P1-03): o laudo tem que ser vinculável a um
código e a um conjunto de regras, e autoverificável.

Defeito: o relatório não trazia `commit`, `ruleset_hash` nem `artifact_sha256` —
um laudo solto, impossível de amarrar à versão que o produziu.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

from chaveiro.audit import audit_batch
from chaveiro.checks.detectors import run_all
from chaveiro.core.jwt import decode
from chaveiro.core.models import AuditResult
from chaveiro.report import provenance
from chaveiro.report.json_report import batch_to_json, to_json
from tests.conftest import raw_token

NOW = 1_800_000_000
_HEX64 = re.compile(r"[0-9a-f]{64}")
# Formato auto-descritivo do ruleset_hash na suíte: prefixo de algoritmo + hex.
_RULESET_HASH = re.compile(r"sha256:[0-9a-f]{64}")
# SHA de 40 hex, válido para o gate `^[0-9a-f]{40}$` do CHAVEIRO_COMMIT.
_SHA_VALIDO = "a1b2c3d4" * 5


def _result() -> AuditResult:
    token = decode(raw_token({"alg": "none"}, {"sub": "admin"}))
    return AuditResult(token=token, findings=run_all(token, NOW))


def test_envelope_traz_commit_ruleset_hash_e_artifact_sha256(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CHAVEIRO_COMMIT", _SHA_VALIDO)
    doc = json.loads(to_json(_result()))
    assert doc["commit"] == _SHA_VALIDO
    # commit_scope discrimina o sentido de `commit`: no Chaveiro é sempre a FERRAMENTA.
    assert doc["commit_scope"] == "tool"
    assert _RULESET_HASH.fullmatch(doc["ruleset_hash"])
    assert _HEX64.fullmatch(doc["artifact_sha256"])


def test_ruleset_hash_e_autodescritivo_e_versiona_o_schema() -> None:
    """INVARIANTE (receita única de verificação da suíte): o ruleset_hash é
    ``sha256:<64 hex>`` — prefixo de algoritmo explícito, não hex solto — e a versão
    do schema do catálogo entra no blob hasheado, então o hash vira se a ESTRUTURA do
    catálogo mudar, mesmo sem mudar uma regra. Revert→vermelho: devolver o hex puro
    (sem prefixo) ou tirar o schema_version do blob quebra a asserção."""
    from chaveiro.report.provenance import RULESET_SCHEMA, ruleset_hash

    valor = ruleset_hash()
    assert _RULESET_HASH.fullmatch(valor), valor
    assert RULESET_SCHEMA == "chaveiro-ruleset/1"


def test_commit_e_none_quando_nao_ha_fonte(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CHAVEIRO_COMMIT", raising=False)
    # _git_head recebe o diretório do pacote (base) — o stub precisa aceitar o argumento.
    monkeypatch.setattr("chaveiro.report.provenance._git_head", lambda base: None)
    doc = json.loads(to_json(_result()))
    assert doc["commit"] is None


def test_env_malformada_e_ignorada_nao_carimba_valor_falso(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # INVARIANTE: env que não é SHA de 40 hex ("HEAD", SHA truncado, "v2") não pode
    # virar carimbo — daria aparência falsa de rastreabilidade. É ignorada, caindo no git.
    monkeypatch.setattr("chaveiro.report.provenance._git_head", lambda base: None)
    for lixo in ("HEAD", "deadbeefcafe", "v2.0.0", _SHA_VALIDO + "0", "z" * 40, ""):
        monkeypatch.setenv("CHAVEIRO_COMMIT", lixo)
        assert provenance.commit() is None, lixo
    # ...mas um SHA válido em MAIÚSCULO é entrada legítima: normalizado, não descartado.
    monkeypatch.setenv("CHAVEIRO_COMMIT", _SHA_VALIDO.upper())
    assert provenance.commit() == _SHA_VALIDO


def test_artifact_sha256_e_autoverificavel(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CHAVEIRO_COMMIT", _SHA_VALIDO)
    from chaveiro.report.provenance import artifact_sha256

    doc = json.loads(to_json(_result()))
    # recomputar o hash sobre o documento SEM o próprio campo tem que bater
    assert artifact_sha256(doc) == doc["artifact_sha256"]


def test_ruleset_hash_e_estavel_entre_execucoes() -> None:
    from chaveiro.report.provenance import ruleset_hash

    assert ruleset_hash() == ruleset_hash()


def test_envelope_batch_tambem_traz_proveniencia(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CHAVEIRO_COMMIT", _SHA_VALIDO)
    outcomes = audit_batch(raw_token({"alg": "none"}, {"sub": "a"}) + "\n", NOW)
    doc = json.loads(batch_to_json(outcomes))
    assert doc["commit"] == _SHA_VALIDO
    assert doc["commit_scope"] == "tool"
    assert _RULESET_HASH.fullmatch(doc["ruleset_hash"])
    assert _HEX64.fullmatch(doc["artifact_sha256"])


def _git(base: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(base), *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip()


def _pacote_tem_git() -> bool:
    return provenance._git_head(Path(provenance.__file__).resolve().parent) is not None


@pytest.mark.skipif(not _pacote_tem_git(), reason="pacote não está sob um repositório git")
def test_commit_resolve_pelo_pacote_nao_pelo_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """INVARIANTE (commit-por-raiz, variante-pacote): o commit carimbado é o do git do
    DIRETÓRIO DO PACOTE, nunca o do CWD. Rodar de dentro de OUTRO repositório git não
    pode carimbar o HEAD daquele repositório.

    Revert→vermelho: com ``git rev-parse HEAD`` sem ``-C <pacote>`` (a versão antiga que
    herdava o CWD), ``commit()`` retornaria o HEAD do repo B — quebrando as duas asserções.
    """
    monkeypatch.delenv("CHAVEIRO_COMMIT", raising=False)
    # Repo B, um repositório git QUALQUER, distinto do da ferramenta.
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@t")
    _git(tmp_path, "config", "user.name", "t")
    _git(tmp_path, "commit", "-q", "--allow-empty", "-m", "b")
    head_b = _git(tmp_path, "rev-parse", "HEAD")
    head_pacote = provenance._git_head(Path(provenance.__file__).resolve().parent)

    monkeypatch.chdir(tmp_path)  # processo rodando de DENTRO do repo B
    carimbado = provenance.commit()

    assert carimbado != head_b, "carimbou o HEAD do CWD (repo B), não o do pacote"
    assert carimbado == head_pacote, "commit deve vir do git do diretório do pacote"
