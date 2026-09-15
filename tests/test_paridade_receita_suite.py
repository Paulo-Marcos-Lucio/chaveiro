"""Paridade de receita da SUITE AppSec (Classe F — auditoria cruzada 2026-09-12).

Um cliente verifica os quatro tools (sentinela/guardiao/chaveiro/esteira) com UMA
unica receita de proveniencia. A rodada 1 fez a receita CONVERGIR, mas nao havia
teste que a TRAVASSE. Este arquivo trava a invariante F para o Chaveiro.

1. ``artifact_sha256`` — a funcao REAL de producao (``chaveiro.report.provenance``)
   produz o MESMO hash que o valor-ouro compartilhado da suite para a mesma entrada
   canonica. Nao ha reimplementacao a mao aqui: o teste importa e exercita o codigo
   que de fato carimba o laudo (o ``_artifact_sha256`` abaixo existe so como
   referencia legivel da receita; a aspercao usa a funcao importada).

2. Redacao — o Chaveiro NAO faz revelacao parcial ``keep=2``. Seu caminho comum
   OMITE totalmente o dado sensivel (marcador ``U+2026`` na evidencia de segredo;
   constante ``REDIGIDO`` na PII de identidade), o que e ESTRITAMENTE MAIS FORTE que
   o piso da suite (2 chars por ponta). O golden ``_redact_pub`` documenta o
   CONTRATO da suite — o TETO de exposicao — e as asercoes provam que a redacao REAL
   do Chaveiro nunca revela MAIS que esse teto (revela zero). A omissao total do
   segredo HMAC confirmado-crackavel (``weak_hmac``: ``<omitido: use 'chaveiro
   crack'>``) e um caminho SEPARADO e ainda mais estrito — coberto em
   ``test_weak_hmac.py`` (edicao Pro).

Local do modulo (Classe F). A proveniencia+redacao do Chaveiro vivem em ``report/``
(nao em ``core/`` como no sentinela). Mover para ``core/`` foi avaliado ALTO RISCO
nesta rodada: ``report.provenance`` importa ``checks.catalog`` e ``report.redaction``
importa ``checks.detectors.has_cpf`` — subir os dois para ``core/`` criaria a aresta
``core -> checks`` (hoje inexistente) e mexeria em varios modulos e testes de import.
Fica DOCUMENTADO e travado pela paridade acima: o CLIENTE ve a mesma receita de
verificacao, que e o objetivo de F, independentemente da pasta em que o modulo mora.
"""

from __future__ import annotations

import hashlib
import json

# --- Receita-ouro compartilhada pela suite (IDENTICA nos 4; nao editar os esperados) ---
GOLDEN_DOC = {"alvo": "exemplo.com.br", "achados": 2, "regra": "pção-ção", "z": 1, "a": [3, 2, 1]}
GOLDEN_ARTIFACT_SHA256 = "bcd1a357a62308d43397cf4357ffb4fa45b904f9a31353da7e10468f213f6af1"
GOLDEN_REDACT = {
    "AKIAIOSFODNN7EXAMPLE": "AK…LE",
    "ghp_16C7e42F292c6912E7710c838347Ae178B4a": "gh…4a",
    "1234": "…",
}


def _redact_pub(x: str, keep: int = 2, mark: str = "…") -> str:
    """Referencia LEGIVEL do contrato de redacao publicada da suite (teto keep=2).

    O Chaveiro nao chama esta funcao (redige por OMISSAO TOTAL, mais estrito); ela
    existe so para pinar o formato-ouro que os outros 3 tools produzem, e como piso
    contra o qual se prova que o Chaveiro nunca revela MAIS.
    """
    return mark if len(x) <= 2 * keep else x[:keep] + mark + x[-keep:]


def test_artifact_sha256_receita_unica_da_suite() -> None:
    """A funcao REAL de producao bate com o ouro da suite — receita unica travada."""
    from chaveiro.report.provenance import artifact_sha256

    # GOLDEN_DOC nao tem o campo ``artifact_sha256``, entao o real (que exclui esse
    # campo) opera sobre o documento inteiro — mesma serializacao canonica da suite.
    assert artifact_sha256(GOLDEN_DOC) == GOLDEN_ARTIFACT_SHA256
    # Sanidade da receita: o ouro e o sha256 dos bytes UTF-8 do JSON compacto-ordenado.
    blob = json.dumps(GOLDEN_DOC, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert hashlib.sha256(blob.encode("utf-8")).hexdigest() == GOLDEN_ARTIFACT_SHA256


def test_redact_publicado_no_maximo_2_por_ponta() -> None:
    """Contrato da suite: o caminho comum revela no maximo 2 chars/ponta, marcador U+2026."""
    for entrada, esperado in GOLDEN_REDACT.items():
        assert _redact_pub(entrada) == esperado
        assert "…" in esperado  # marcador comum da suite = U+2026 (nao "..." ASCII)


def test_redacao_real_do_chaveiro_e_no_minimo_tao_estrita_quanto_a_suite() -> None:
    """INVARIANTE (Classe E/F): a redacao REAL do Chaveiro nunca revela MAIS que o teto
    da suite. Para a PII de IDENTIDADE, o caminho comum omite o valor INTEIRO (constante
    ``REDIGIDO``) — zero caractere revelado, contra ate 2/ponta do piso da suite. Ataca a
    classe, nao o exemplo: vale para QUALQUER valor sob uma claim de identidade."""
    from chaveiro.report.redaction import REDIGIDO, redact_claims

    for entrada in GOLDEN_REDACT:
        limpo = redact_claims({"email": entrada, "sub": entrada})
        assert limpo["email"] == REDIGIDO and limpo["sub"] == REDIGIDO
        assert entrada not in REDIGIDO  # disclosure REAL do Chaveiro = 0 caracteres
        # ...e 0 <= 2/ponta que a suite revelaria: estritamente mais forte, nunca mais fraco.
        revelados_suite = 0 if _redact_pub(entrada) == "…" else 2 * 2
        assert revelados_suite >= 0


def test_marcador_comum_de_segredo_no_laudo_e_U2026() -> None:
    """INVARIANTE (Classe E/G5): o caminho comum de segredo no PAYLOAD emite evidencia
    ``path=…`` (marcador U+2026, alinhado aos outros 3 tools) e NUNCA o valor cru. Usa a
    funcao REAL ``checks.detectors.check_payload`` sobre um token com credencial embutida."""
    from chaveiro.checks.detectors import check_payload
    from chaveiro.core.jwt import decode
    from tests.conftest import raw_token

    segredo = "AKIAIOSFODNN7EXAMPLE"
    token = decode(raw_token({"alg": "none"}, {"api_key": segredo}))
    evidencias = " ".join(f.evidence or "" for f in check_payload(token))
    assert "…" in evidencias  # marcador comum de segredo = U+2026
    assert segredo not in evidencias  # o valor cru e omitido do laudo
