from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from chaveiro import __version__
from chaveiro.cli import app
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
    assert any(f["check"] == "alg-none" for f in doc["findings"])


def test_crack_finds_weak_secret() -> None:
    token = hs_token({"sub": "a"}, secret="secret")
    result = runner.invoke(app, ["crack", token])
    assert result.exit_code == 1


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
