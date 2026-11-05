"""Perfis de auditoria (CH-11b): toleram particularidade conhecida de UM emissor
sem alterar o comportamento padrão dos outros.

Por que existe: `check_claims` aplica hoje a mesma régua de claims a qualquer
JWT, e um item futuro (CH-03b) vai precisar relaxar uma checagem pontual (a
ausência de `aud`) só para tokens de um emissor com um quirk documentado
(perfil Cognito legado), sem afrouxar a régua padrão para todo o resto. Este
módulo é só a INFRAESTRUTURA genérica dessa troca de régua — nenhum perfil
concreto é definido aqui. Sem perfil (`None`), nada muda: `run_all` fica byte
a byte igual ao comportamento anterior a este módulo.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace

from chaveiro.core.models import DecodedToken, Finding, Severity

# Mesma assinatura das checagens em checks/detectors.py: (token, now) -> achados.
RegraExtra = Callable[[DecodedToken, int], list[Finding]]


@dataclass(frozen=True)
class Perfil:
    """Um perfil nomeado de auditoria.

    ``overrides_severidade`` é um TETO, nunca um piso: a severidade de um
    achado cujo ``check_id`` apareça aqui não passa do valor mapeado. Só
    abaixa — um perfil tolera uma particularidade conhecida do emissor, mas
    não pode fabricar gravidade que a checagem base não viu. ``regras_extra``
    roda ALÉM da bateria padrão, em toda camada (inclusive dentro de JWT
    aninhado), na mesma assinatura das funções de ``checks/detectors.py``.
    """

    nome: str
    overrides_severidade: dict[str, Severity] = field(default_factory=dict)
    regras_extra: tuple[RegraExtra, ...] = field(default_factory=tuple)

    def rodar_extra(self, token: DecodedToken, now: int) -> list[Finding]:
        achados: list[Finding] = []
        for regra in self.regras_extra:
            achados += regra(token, now)
        return achados

    def aplicar_teto(self, achados: list[Finding]) -> list[Finding]:
        if not self.overrides_severidade:
            return achados
        ajustados: list[Finding] = []
        for achado in achados:
            teto = self.overrides_severidade.get(achado.check_id)
            if teto is not None and teto.rank < achado.severity.rank:
                achado = replace(achado, severity=teto)
            ajustados.append(achado)
        return ajustados


# Catálogo público de perfis, por nome — é nele que a CLI (`--perfil nome`)
# procura. Começa vazio de propósito: nenhum perfil concreto é decisão deste
# item (CH-11b é só o mecanismo). Quem definir um perfil real (ex.: CH-03b)
# chama `registrar()` no módulo que o define.
PERFIS: dict[str, Perfil] = {}


def registrar(perfil: Perfil) -> Perfil:
    """Registra `perfil` em `PERFIS`, por nome, e o devolve (uso em definição:
    ``MEU_PERFIL = registrar(Perfil(...))``)."""
    PERFIS[perfil.nome] = perfil
    return perfil
