"""Proveniência do laudo (P1-03): amarra o JSON ao código e às regras.

Defeito de origem: o relatório era um documento solto — não dava para provar com
qual versão do Chaveiro nem com qual conjunto de checagens ele foi gerado, nem
detectar adulteração posterior. Três campos resolvem isso:

- ``commit`` — o SHA do código que rodou (env ``CHAVEIRO_COMMIT`` → ``git
  rev-parse HEAD`` → ``None``). Em pacote instalado sem git, cai em ``None`` sem
  quebrar.
- ``ruleset_hash`` — sha256 do catálogo de checagens. Muda quando qualquer regra
  muda; dois laudos com o mesmo hash foram medidos com as mesmas regras.
- ``artifact_sha256`` — sha256 do próprio documento (sem o campo), canônico. O
  cliente recomputa e detecta adulteração.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from typing import Any

from chaveiro.checks.catalog import CATALOG, OWASP_EDITION


def _git_head() -> str | None:
    """SHA do HEAD via git, ou ``None`` se não houver repositório/git disponível."""
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    sha = proc.stdout.strip()
    return sha if proc.returncode == 0 and sha else None


def commit() -> str | None:
    """Identidade do código: variável de ambiente tem prioridade sobre o git.

    ``CHAVEIRO_COMMIT`` existe para o caso do pacote instalado (sem .git) ou de CI
    que já conhece o SHA e não quer pagar um subprocesso por laudo.
    """
    env = os.environ.get("CHAVEIRO_COMMIT", "").strip()
    if env:
        return env
    return _git_head()


def ruleset_hash() -> str:
    """sha256 estável do catálogo de checagens (id, severidade, OWASP/CWE, texto)."""
    itens = [
        [
            meta.id,
            meta.severity.value,
            meta.owasp or "",
            meta.cwe or "",
            meta.title,
            meta.recommendation,
        ]
        for meta in sorted(CATALOG.values(), key=lambda m: m.id)
    ]
    blob = json.dumps(
        {"owasp_edition": OWASP_EDITION, "checks": itens},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def artifact_sha256(document: dict[str, Any]) -> str:
    """sha256 canônico do documento **excluindo** o próprio campo de hash.

    Serialização determinística (chaves ordenadas, sem espaços) para que o cliente
    recompute o mesmo valor a partir do JSON recebido.
    """
    sem_campo = {k: v for k, v in document.items() if k != "artifact_sha256"}
    blob = json.dumps(sem_campo, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()
