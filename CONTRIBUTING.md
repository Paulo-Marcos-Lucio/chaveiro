<p align="center"><a href="CONTRIBUTING.en.md"><img src="https://raw.githubusercontent.com/Paulo-Marcos-Lucio/chaveiro/main/assets/btn-lang-en.svg" alt="Read this document in English" width="300"/></a></p>

# Contribuindo

Contribuições são bem-vindas — sobretudo **novas checagens**.

## Ambiente

```bash
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Antes do PR

```bash
ruff check . && ruff format --check . && mypy src && pytest
```

## Adicionando uma checagem

1. Declare os metadados em `src/chaveiro/checks/catalog.py` (id, título, severidade, OWASP, CWE, recomendação).
2. Emita o achado a partir da função apropriada em `src/chaveiro/checks/detectors.py` usando `make_finding`.
3. Adicione um teste positivo em `tests/test_detectors.py` **e** garanta que um token bem-formado não dispara a checagem.

Ataques novos (`attacks/`) devem vir com PoC reprodutível em teste.

## Definição de pronto para correção de defeito

Corrigir o exemplo que apareceu no relatório e chamar de resolvido não fecha
o item: é preciso um teste que falhava contra o código anterior à correção,
mais um invariante — property-based com Hypothesis quando a classe for uma
família de entradas — que impeça a classe inteira de voltar. Critério e
exemplos reais em [`docs/definicao-de-pronto.md` da
Sentinela](https://github.com/Paulo-Marcos-Lucio/sentinela/blob/main/docs/definicao-de-pronto.md),
válido para as cinco ferramentas da suíte, não só para ela.
