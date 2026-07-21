from __future__ import annotations

import io
import json

from rich.console import Console
from tests.conftest import raw_token

from chaveiro.checks.detectors import run_all
from chaveiro.core.jwt import decode
from chaveiro.core.models import AuditResult
from chaveiro.report.console import render
from chaveiro.report.json_report import to_json

NOW = 1_800_000_000


def _result() -> AuditResult:
    token = decode(raw_token({"alg": "none"}, {"sub": "admin"}))
    return AuditResult(token=token, findings=run_all(token, NOW))


def test_json_structure() -> None:
    doc = json.loads(to_json(_result()))
    assert doc["tool"] == "chaveiro"
    assert doc["token"]["alg"] == "none"
    assert doc["summary"]["total"] == len(doc["findings"])
    assert any(f["check"] == "alg-none" for f in doc["findings"])


def test_console_render_does_not_crash() -> None:
    console = Console(file=io.StringIO(), width=200)
    render(_result(), console)
    output = console.file.getvalue()  # type: ignore[attr-defined]
    assert "alg-none" in output
