"""Mede o Chaveiro contra o corpus rotulado de `bench/`.

Uso:
    python bench/gerar.py       # (opcional) materializa os arquivos de token
    python bench/avaliar.py

Recall vem com intervalo de confiança de **Wilson**: com n=22 um número redondo
sozinho anuncia uma precisão que a amostra não comporta.
"""

from __future__ import annotations

import math
import os
import sys
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gerar import BENCH_NOW, negativos, positivos

from chaveiro.audit import audit_token


def wilson(acertos: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """Intervalo de confiança de Wilson — honesto para amostra pequena."""
    if total == 0:
        return (0.0, 0.0)
    p = acertos / total
    denom = 1 + z * z / total
    centro = (p + z * z / (2 * total)) / denom
    margem = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return (max(0.0, centro - margem), min(1.0, centro + margem))


@dataclass
class Medicao:
    tp: int = 0
    total_pos: int = 0
    fp: int = 0
    total_neg: int = 0
    escaparam: list[str] = field(default_factory=list)  # vetor cujo esperado não disparou
    ruidosos: list[str] = field(default_factory=list)  # negativo que gerou achado

    @property
    def recall(self) -> float:
        return self.tp / self.total_pos if self.total_pos else 0.0


def medir(now: int = BENCH_NOW) -> Medicao:
    m = Medicao()
    for caso in positivos():
        m.total_pos += 1
        ids = {f.check_id for f in audit_token(caso["token"], now).findings}
        if caso["esperado"] in ids:
            m.tp += 1
        else:
            m.escaparam.append(f"{caso['vetor']} (esperava {caso['esperado']})")
    for caso in negativos():
        m.total_neg += 1
        findings = audit_token(caso["token"], now).findings
        if findings:
            m.fp += 1
            m.ruidosos.append(f"{caso['vetor']}: {[f.check_id for f in findings]}")
    return m


def main() -> None:
    m = medir()
    baixo, alto = wilson(m.tp, m.total_pos)
    print("== corpus do Chaveiro ==")
    print(
        f"  RECALL         : {m.tp}/{m.total_pos} = {m.recall:.0%}   IC95% = [{baixo:.0%} ; {alto:.0%}]"
    )
    print(f"  FALSO-POSITIVO : {m.fp} em {m.total_neg} tokens legítimos")
    if m.escaparam:
        print("  ESCAPARAM:")
        for item in m.escaparam:
            print(f"    - {item}")
    if m.ruidosos:
        print("  RUÍDO em negativos:")
        for item in m.ruidosos:
            print(f"    - {item}")


if __name__ == "__main__":
    main()
