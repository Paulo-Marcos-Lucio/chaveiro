"""Classificação do TIPO de token JWT — ``TokenKind``.

Por que isto existe separado de ``check_claims``. As claims exigidas e a
tolerância de vida útil variam pelo QUE o token É, não só pelo seu conteúdo:
um Access Token (RFC 9068) exige ``aud``; um ID Token (OpenID Connect Core)
não tem o mesmo perfil de ``aud`` e carrega ``nonce``/``at_hash``, que um
Access Token nunca tem; um Refresh Token tem vida longa por design. Hoje
``check_claims`` (``checks/detectors.py``) aplica a MESMA régua a qualquer
JWT — é a causa-raiz de um ID Token sem ``aud`` virar achado de alta
severidade e de um Refresh Token de 30 dias ser medido pela régua de vida
útil de Access Token (hoje contornado ali por uma exceção pontual, não por
tipo). Separar a CLASSIFICAÇÃO (este módulo) da REGRA por tipo é o que o
item seguinte da fila consome — aqui só a classificação.

Sinal usado por tipo — nenhum inventado, todos vêm de RFC/convenção já
documentada ou já em uso neste repositório:

- ``at+jwt`` no header ``typ``: RFC 9068 (OAuth 2.0 Access Token JWT
  Profile) §2.1 reserva esse valor para o perfil — sinal inequívoco.
- ``logout+jwt`` no header ``typ``: OpenID Connect Back-Channel Logout
  1.0 §2.4 reserva esse valor para o Logout Token.
- ``dpop+jwt`` no header ``typ``: RFC 9449 (DPoP) §4.2 EXIGE esse valor na
  prova DPoP — mesma classe de sinal que os dois anteriores.
- ``nonce``/``at_hash`` no payload: claims do ID Token (OpenID Connect
  Core §2) que um Access Token nunca carrega. OIDC Core não reserva um
  valor de ``typ`` para ID Token (implementações reais usam ``typ: JWT``
  genérico, às vezes nenhum ``typ``) — por isso aqui o sinal é de PAYLOAD,
  não de header, ao contrário dos três perfis acima.
- Refresh: a MESMA heurística já usada em ``checks/detectors.py``
  (``typ_diz_refresh``/``e_refresh``) — claim ``typ``/``type``/
  ``token_type`` valendo ``"refresh"``, suprimida quando o token carrega
  sinal de acesso (``scope``/``scp``/``azp``), porque o campo é
  SELF-ASSERTED. Reaproveitada aqui em vez de reescrita; o item que vai
  fazer ``check_claims`` consumir este módulo também remove a duplicata.
- Nenhum dos sinais acima: ``GENERIC`` — literal do critério de aceite
  deste item ("sem typ reconhecível → GENERIC").

``REFRESH`` e ``DPOP`` não têm um caso literal no critério de aceite do
item (que lista só ``at+jwt``/``nonce``+``at_hash``/``logout+jwt``/
``GENERIC``), mas estão no título do item ("TokenKind
(ID_TOKEN/ACCESS_JWT/REFRESH/LOGOUT/DPOP/GENERIC)") e o sinal de cada um
está documentado acima com a fonte — RFC 9449 para ``DPOP``, o código
já existente para ``REFRESH`` — para que a decisão de incluí-los fique
auditável, não escondida.
"""

from __future__ import annotations

from enum import Enum

from chaveiro.core.models import DecodedToken


class TokenKind(str, Enum):
    ID_TOKEN = "id_token"
    ACCESS_JWT = "access_jwt"
    REFRESH = "refresh"
    LOGOUT = "logout"
    DPOP = "dpop"
    GENERIC = "generic"


# Header `typ` -> TokenKind, só para os perfis que RESERVAM um valor próprio
# (RFC 9068, OIDC Back-Channel Logout, RFC 9449). Mapa, não cadeia de `if`:
# um perfil novo entra como uma linha, sem reler a ordem dos outros.
_TYP_HEADER_RESERVADO: dict[str, TokenKind] = {
    "at+jwt": TokenKind.ACCESS_JWT,
    "logout+jwt": TokenKind.LOGOUT,
    "dpop+jwt": TokenKind.DPOP,
}

# Claims de payload exclusivas de ID Token (OIDC Core §2) — ver docstring do módulo.
_CLAIMS_DE_ID_TOKEN = ("nonce", "at_hash")

# Claims que indicam ACESSO — usadas para não deixar um `typ` self-asserted de
# refresh vencer um token que também carrega sinal de access token (ver `_e_refresh`).
_CLAIMS_DE_ACESSO = ("scope", "scp", "azp")


def classify(token: DecodedToken) -> TokenKind:
    """Classifica ``token`` pelo TIPO — não pela validade. Ver docstring do módulo
    para a fonte de cada sinal e a ordem de precedência entre eles."""
    typ = str(token.header.get("typ", "")).strip().lower()
    perfil_reservado = _TYP_HEADER_RESERVADO.get(typ)
    if perfil_reservado is not None:
        return perfil_reservado

    if _e_refresh(token, typ_header=typ):
        return TokenKind.REFRESH

    if any(claim in token.payload for claim in _CLAIMS_DE_ID_TOKEN):
        return TokenKind.ID_TOKEN

    return TokenKind.GENERIC


def _e_refresh(token: DecodedToken, *, typ_header: str) -> bool:
    """Mesma heurística de ``checks/detectors.py`` — ver docstring do módulo.
    ``typ_header`` chega já normalizado (``strip().lower()``) de quem chamou,
    para não repetir a extração do header duas vezes em ``classify``."""
    typ_diz_refresh = typ_header in ("refresh", "refresh+jwt") or any(
        str(token.payload.get(k, "")).strip().lower() == "refresh"
        for k in ("typ", "type", "token_type")
    )
    tem_sinais_de_acesso = any(k in token.payload for k in _CLAIMS_DE_ACESSO)
    return typ_diz_refresh and not tem_sinais_de_acesso
