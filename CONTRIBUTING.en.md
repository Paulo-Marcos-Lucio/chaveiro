<p align="center"><a href="CONTRIBUTING.md"><img src="https://raw.githubusercontent.com/Paulo-Marcos-Lucio/chaveiro/main/assets/btn-lang-pt.svg" alt="Ler este documento em Português" width="300"/></a></p>

# Contributing

Contributions are welcome — especially **new checks**.

## Environment

```bash
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Before the PR

```bash
ruff check . && ruff format --check . && mypy src && pytest
```

## Adding a check

1. Declare the metadata in `src/chaveiro/checks/catalog.py` (id, title, severity, OWASP, CWE, recommendation).
2. Emit the finding from the appropriate function in `src/chaveiro/checks/detectors.py` using `make_finding`.
3. Add a positive test in `tests/test_detectors.py` **and** ensure that a well-formed token does not trigger the check.

New attacks (`attacks/`) must come with a reproducible PoC in a test.
