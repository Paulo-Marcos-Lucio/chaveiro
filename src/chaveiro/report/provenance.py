"""Proveniência do laudo (P1-03): amarra o JSON ao código e às regras.

Defeito de origem: o relatório era um documento solto — não dava para provar com
qual versão do Chaveiro nem com qual conjunto de checagens ele foi gerado, nem
detectar adulteração posterior. Três campos resolvem isso:

- ``commit`` — o SHA do código que rodou (env ``CHAVEIRO_COMMIT`` → ``git
  rev-parse HEAD`` **no diretório do próprio pacote** → ``None``). O Chaveiro
  audita um TOKEN, não varre um repositório: a identidade a carimbar é sempre a
  da FERRAMENTA que rodou, resolvida pelo diretório do pacote (``__file__``), e
  nunca pelo diretório de trabalho de onde o operador chamou o CLI — do
  contrário, rodar ``chaveiro`` de dentro de outro repositório git carimbaria o
  HEAD daquele repositório, silenciosamente errado. Em pacote instalado sem git,
  cai em ``None`` sem quebrar.
- ``ruleset_hash`` — sha256 do catálogo de checagens. Muda quando qualquer regra
  muda; dois laudos com o mesmo hash foram medidos com as mesmas regras.
- ``artifact_sha256`` — sha256 do próprio documento (sem o campo), canônico. O
  cliente recomputa e detecta adulteração.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

from chaveiro.checks.catalog import CATALOG, OWASP_EDITION

# Versão do schema do CATÁLOGO de regras (não confundir com o schema do envelope
# JSON, "suite-appsec/1"). Vai EMBUTIDA no blob de que o ``ruleset_hash`` é o
# sha256: assim, se um dia a estrutura do catálogo mudar (novos campos por regra),
# o hash muda mesmo que nenhuma regra individual tenha mudado — e um cliente que
# fixou a receita de verificação percebe a virada de versão. Padrão da suíte:
# ``<tool>-ruleset/1``.
RULESET_SCHEMA = "chaveiro-ruleset/1"

# SHA de commit é 40 hex minúsculos. Um valor fora desse formato (env com "HEAD",
# "v2" ou SHA truncado) NÃO é rastreabilidade: carimbá-lo daria aparência falsa de
# proveniência a um laudo não rastreável, então é IGNORADO em vez de propagado.
_SHA40 = re.compile(r"^[0-9a-f]{40}$")


def _git_head(base: Path) -> str | None:
    """``git -C <base> rev-parse HEAD``, ou ``None`` se não houver repositório/git.

    ``base`` é o diretório consultado pelo git — quem responde é o CÓDIGO que rodou
    (o diretório do pacote), não o diretório de trabalho do operador. Sem git no
    PATH, fora de um repositório ou com o git travado, o resultado é ``None``: uma
    auditoria jamais falha por causa do carimbo.
    """
    try:
        proc = subprocess.run(
            ["git", "-C", str(base), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    sha = proc.stdout.strip().lower()
    return sha if _SHA40.match(sha) else None


def commit() -> str | None:
    """Identidade do código que rodou: variável de ambiente tem prioridade sobre o git.

    ``CHAVEIRO_COMMIT`` existe para o caso do pacote instalado (sem .git) ou de CI
    que já conhece o SHA e não quer pagar um subprocesso por laudo — mas só é aceito
    se for um SHA de 40 hex (``^[0-9a-f]{40}$``); um valor malformado é ignorado.

    Sem env válida, o SHA é resolvido pelo git do DIRETÓRIO DO PACOTE
    (``Path(__file__).resolve().parent``), não pelo CWD: o Chaveiro audita um token,
    então o commit a carimbar é o da própria ferramenta, e rodar de dentro de outro
    repositório git não pode carimbar o HEAD daquele repositório.
    """
    env = os.environ.get("CHAVEIRO_COMMIT", "").strip().lower()
    if _SHA40.match(env):
        return env
    return _git_head(Path(__file__).resolve().parent)


def ruleset_hash() -> str:
    """Hash estável do catálogo de checagens, no formato auto-descritivo ``sha256:<hex>``.

    O prefixo ``sha256:`` (padrão da suíte, o mesmo do Sentinela) diz ao cliente QUAL
    algoritmo recomputar, em vez de deixá-lo adivinhar de um hex solto. A versão do
    schema do catálogo (:data:`RULESET_SCHEMA`) entra no blob hasheado, então a receita
    de verificação é única entre as ferramentas: mesmo formato de saída e mesmo conjunto
    de campos de entrada.
    """
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
        {"schema_version": RULESET_SCHEMA, "owasp_edition": OWASP_EDITION, "checks": itens},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"sha256:{hashlib.sha256(blob.encode('utf-8')).hexdigest()}"


def artifact_sha256(document: dict[str, Any]) -> str:
    """sha256 canônico do documento **excluindo** o próprio campo de hash.

    Serialização determinística (chaves ordenadas, sem espaços) para que o cliente
    recompute o mesmo valor a partir do JSON recebido.

    IMPORTANTE para quem recomputa: o hash é sobre os **bytes UTF-8** do JSON (o catálogo
    é PT-BR, então quase todo laudo tem acentos). No Windows, ``open(caminho)`` usa cp1252
    por padrão e recompõe bytes diferentes — dando um "adulterado" FALSO. Leia sempre como
    UTF-8: ``open(caminho, "rb").read().decode("utf-8")`` antes de recalcular.
    """
    sem_campo = {k: v for k, v in document.items() if k != "artifact_sha256"}
    blob = json.dumps(sem_campo, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()
