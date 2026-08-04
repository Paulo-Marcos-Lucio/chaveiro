# Corpus de referência do Chaveiro

Corpus rotulado, versionado, com script de avaliação. Existe por um motivo:
**número de detecção sem corpus público não é métrica, é lembrança.** O perfil
publicava "22/22 vetores, medido" e o corpus não existia — este diretório fecha
esse buraco de honestidade.

## Como reproduzir

```bash
pip install -e ".[dev]"
python bench/gerar.py       # materializa os tokens rotulados (positivos.txt / negativos.txt)
python bench/avaliar.py     # mede recall + IC95% de Wilson e falso-positivo
```

> **Por que `gerar.py` existe.** Um corpus de tokens não versiona credenciais/tokens
> prontos: o mesmo princípio do *push protection* do GitHub. Os tokens são gerados
> de forma **determinística** na hora de rodar a bateria e ficam no `.gitignore`. O
> que é versionado é o `manifest.json` (os rótulos) e o código que os reconstrói.

## O que tem aqui

| | Quantidade | O que é |
|---|---|---|
| `positivos` | **22 vetores** | `alg:none`/ausente/desconhecido, `jku`/`x5u`/`jwk`/`x5c`, `kid` injection, `crit`, `cty:JWT`, aninhamento real, claim carregando JWT, `exp`/`iat`/`aud`/`iss` ausentes, expirado, vida longa, tempo malformado, `nbf` futuro, segredo no payload, CPF (mód-11) |
| `negativos` | **6 tokens** | RS256/PS256/ES256/EdDSA completos (`sub`/`exp`/`iat`/`aud`/`iss`), um com `roles`/`scope`, um com `nbf` no passado — todos devem passar limpos |
| `manifest.json` | 28 rótulos | Para cada positivo, o `check_id` que **deve** disparar; para cada negativo, o rótulo do vetor |

## O que este corpus **não** é

- **Não é campo.** Os tokens foram plantados por quem escreveu a ferramenta. O
  número mede *cobertura dos vetores conhecidos*, não acurácia contra tráfego real.
- **Negativos assimétricos de propósito.** Um HS* bem-formado ainda dispara o aviso
  `alg-hmac-advisory` (LOW) — não é falso-positivo, é conselho. Por isso os
  negativos limpos são RS*/PS*/ES*/EdDSA, onde "zero achados" é o esperado.
- **Não tem tamanho de amostra para três algarismos.** Com n=22 o intervalo de
  confiança de Wilson é largo; todo número derivado daqui vem com o IC, não com
  precisão falsa.

## Medição de referência

Medido em 2026-08-04, Python 3.12.8, Windows 11:

| Métrica | Valor |
|---|---|
| **Recall** (positivos) | **22/22 = 100%** · IC95% (Wilson) **[85% ; 100%]** |
| **Falso-positivo** (negativos) | **0 / 6** |

## Regra da casa

Quem alterar detecção **roda esta bateria antes e depois** e registra os dois
números no CHANGELOG. Recall que sobe às custas de falso-positivo não é melhoria —
é troca, e a troca precisa estar visível. O teste `tests/test_bench.py` trava o
número: se um detector regredir, o CI cai aqui, não num README que ninguém executa.
