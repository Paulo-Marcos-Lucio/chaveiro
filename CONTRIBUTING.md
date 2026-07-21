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
