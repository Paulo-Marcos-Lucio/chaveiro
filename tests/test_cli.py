from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from chaveiro import __version__
from chaveiro.checks.perfil import PERFIS, Perfil
from chaveiro.cli import app
from chaveiro.core.models import Severity
from tests.conftest import hs_token, raw_token, sign_rs256

runner = CliRunner()
NOW = 1_800_000_000


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_rules_lists_checks() -> None:
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    assert "alg-none" in result.stdout


def test_inspect_none_token_json_exit1() -> None:
    token = raw_token({"alg": "none"}, {"sub": "admin"})
    result = runner.invoke(app, ["inspect", token, "-f", "json", "--now", str(NOW)])
    assert result.exit_code == 1
    doc = json.loads(result.stdout)
    assert any(f["id"] == "alg-none" for f in doc["findings"])


def test_inspect_output_grava_arquivo(tmp_path: Path) -> None:
    token = raw_token({"alg": "none"}, {"sub": "admin"})
    saida = tmp_path / "laudo.json"
    result = runner.invoke(
        app, ["inspect", token, "-f", "json", "-o", str(saida), "--now", str(NOW)]
    )
    assert result.exit_code == 1
    doc = json.loads(saida.read_text(encoding="utf-8"))
    assert any(f["id"] == "alg-none" for f in doc["findings"])


def test_output_com_console_e_erro_de_uso(tmp_path: Path) -> None:
    token = raw_token({"alg": "none"}, {"sub": "admin"})
    result = runner.invoke(app, ["inspect", token, "-o", str(tmp_path / "x.json")])
    assert result.exit_code == 2  # --output exige --format json


def test_crack_finds_weak_secret() -> None:
    token = hs_token({"sub": "a"}, secret="secret")
    result = runner.invoke(app, ["crack", token])
    assert result.exit_code == 1


def test_crack_wordlist_streaming(tmp_path: Path) -> None:
    # A wordlist é lida como gerador (linha a linha); o segredo no meio do
    # arquivo é encontrado sem materializar a lista inteira.
    wl = tmp_path / "wl.txt"
    wl.write_text("nope\ncorrect-horse\nother\n", encoding="utf-8")
    token = hs_token({"sub": "a"}, secret="correct-horse")
    result = runner.invoke(app, ["crack", token, "--no-defaults", "--wordlist", str(wl)])
    assert result.exit_code == 1


def test_crack_wordlist_inexistente_exit2() -> None:
    token = hs_token({"sub": "a"}, secret="x")
    result = runner.invoke(app, ["crack", token, "--wordlist", "/nao/existe/rockyou.txt"])
    assert result.exit_code == 2  # caminho inexistente -> erro de uso (Click)


def test_comandos_ofensivos_avisam_autorizacao() -> None:
    # crack/forge/forge-confusion têm que imprimir o aviso legal em tempo de execução.
    token = hs_token({"sub": "a"}, secret="k")
    for args in (["crack", token], ["forge", token, "--secret", "k"]):
        result = runner.invoke(app, args)
        assert "autoriza" in result.output.lower() or "12.737" in result.output


def test_forge_confusion(tmp_path: Path, rsa_keys: tuple[bytes, bytes]) -> None:
    private_pem, public_pem = rsa_keys
    key_file = tmp_path / "pub.pem"
    key_file.write_bytes(public_pem)
    token = sign_rs256({"sub": "user", "role": "user"}, private_pem)
    result = runner.invoke(
        app, ["forge-confusion", token, "--public-key", str(key_file), "--set", "role=admin"]
    )
    assert result.exit_code == 0
    forged = result.stdout.strip().splitlines()[0]
    assert forged.count(".") == 2  # é um JWT


def test_forge_with_secret() -> None:
    token = hs_token({"sub": "a"}, secret="k")
    result = runner.invoke(app, ["forge", token, "--secret", "k", "--set", "role=admin"])
    assert result.exit_code == 0
    assert result.stdout.strip().count(".") == 2


def test_inspect_perfil_desconhecido_e_erro_de_uso() -> None:
    token = raw_token({"alg": "none"}, {"sub": "admin"})
    result = runner.invoke(
        app, ["inspect", token, "-f", "json", "--now", str(NOW), "--perfil", "nao-existe-9f3a"]
    )
    assert result.exit_code == 2


def test_inspect_com_perfil_registrado_aplica_teto_e_muda_ruleset_hash() -> None:
    """Ponta a ponta (CH-11b): --perfil resolve pelo nome, chega em run_all (o teto
    de severidade aparece no achado) e em ruleset_hash (que fica diferente do
    laudo sem perfil) — a infraestrutura completa, não só uma peça isolada."""
    nome = "teste-cli-perfil-9f3a"
    PERFIS[nome] = Perfil(nome=nome, overrides_severidade={"alg-none": Severity.LOW})
    try:
        token = raw_token({"alg": "none"}, {"sub": "admin"})
        com_perfil = runner.invoke(
            app, ["inspect", token, "-f", "json", "--now", str(NOW), "--perfil", nome]
        )
        sem_perfil = runner.invoke(app, ["inspect", token, "-f", "json", "--now", str(NOW)])
    finally:
        del PERFIS[nome]
    doc_com = json.loads(com_perfil.stdout)
    doc_sem = json.loads(sem_perfil.stdout)
    assert doc_com["perfil"] == nome
    assert doc_sem["perfil"] is None
    [achado] = [f for f in doc_com["findings"] if f["id"] == "alg-none"]
    assert achado["severity"] == "low"
    assert doc_com["ruleset_hash"] != doc_sem["ruleset_hash"]
