<div align="center">

# 🗝️ Chaveiro

### Auditor de segurança de tokens **JWT/JWS** — do diagnóstico ao PoC, com o lado da correção junto.

*Decodifica, audita e ataca (com autorização) tokens JWT: `alg:none`, confusão de algoritmo (RS→HS), segredo HMAC fraco, `kid`/`jku`/`x5u` como vetor de SSRF/injeção, e validação de claims. Inclui um módulo de **referência de validação correta** — porque encontrar a falha e mostrar como corrigir é o serviço completo.*

[![CI](https://github.com/Paulo-Marcos-Lucio/chaveiro/actions/workflows/ci.yml/badge.svg)](https://github.com/Paulo-Marcos-Lucio/chaveiro/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Ruff](https://img.shields.io/badge/lint-ruff-261230.svg)](https://github.com/astral-sh/ruff)
[![Checked with mypy](https://img.shields.io/badge/mypy-strict-2A6DB2.svg)](https://mypy-lang.org/)
[![OWASP](https://img.shields.io/badge/OWASP-A07%2FA02-000000.svg)](https://owasp.org/Top10/)

</div>

---

## 📌 Por que JWT quebra tanto

JWT é simples de emitir e **fácil de validar errado**. A maioria dos bypasses não ataca a criptografia — ataca o **verificador**:

- ele confia no `alg` que vem **dentro do token** (aceitando `none`, ou trocando RS256 por HS256);
- ele não confere `exp`/`nbf`;
- ele resolve a chave a partir de um campo do cabeçalho (`jku`/`x5u`/`jwk`) controlado pelo atacante;
- ele usa `kid` direto num caminho de arquivo ou numa query SQL.

O Chaveiro cobre esses vetores dos dois lados: **audita** um token, **prova** a falha com um PoC quando aplicável, e mostra a **validação correta** como referência.

> **Contexto:** venho de **Open Finance / FAPI**, onde JWT/JWS (DPoP, client assertions, `id_token`) são o coração da autenticação. Este é o ferramental que uso para revisar esse tipo de integração.

---

## 🔎 O que ele audita

| Checagem | Risco | Severidade | OWASP / CWE |
| --- | --- | --- | --- |
| `alg-none` | Token não assinado aceito como válido | 🔴 Crítica | A07 · CWE-347 |
| `alg-missing` / `alg-unknown` | Verificação ambígua de algoritmo | 🟠/🟡 | A07 · CWE-347 |
| `alg-hmac-advisory` | HS* → risco de segredo fraco e de confusão RS→HS | 🔵 Baixa | A02 · CWE-326 |
| `header-jku` / `header-x5u` | Chave carregada de URL do token → **SSRF** / key injection | 🟠 Alta | A10 · CWE-918 |
| `header-jwk` | Chave pública embutida (atacante fornece a própria) | 🟠 Alta | A07 · CWE-347 |
| `header-kid-injection` | `kid` com `../`, `'`, `;` → path traversal / SQLi | 🟠 Alta | A03 · CWE-91 |
| `claim-no-exp` / `claim-long-lifetime` | Token eterno / longevo demais | 🟠/🟡 | A07 · CWE-613 |
| `claim-no-aud` / `claim-no-iss` / `claim-no-iat` | Falta amarração de destino/emissor | 🔵 Baixa | A07 · CWE-345 |
| `payload-sensitive` | Segredo/PII no payload (JWT é base64, **não** cifrado) | 🟡 Média | A02 · CWE-522 |

---

## 🚀 Instalação

```bash
git clone https://github.com/Paulo-Marcos-Lucio/chaveiro.git
cd chaveiro
pip install .        # ou: pip install -e ".[dev]"
```

---

## 🧑‍💻 Uso

```bash
# audita um token (decodifica + todas as checagens passivas)
chaveiro inspect "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."

# em JSON, para pipelines
chaveiro inspect "$TOKEN" -f json --fail-on high

# o segredo HMAC é fraco? (ataque de dicionário — lista embutida + sua wordlist)
chaveiro crack "$TOKEN" --wordlist rockyou.txt

# PoC de confusão de algoritmo: forja um HS256 com a chave PÚBLICA como segredo
chaveiro forge-confusion "$RS256_TOKEN" --public-key server.pub --set role=admin

# reassina um token modificado com um segredo conhecido (teste autorizado)
chaveiro forge "$TOKEN" --secret leaked-secret --set role=admin

# lista todas as checagens
chaveiro rules
```

### O lado da correção — validação de referência

```python
from chaveiro.reference.secure_validation import validate, InvalidToken

# allowlist FIXA de algoritmos, rejeita 'none', confere assinatura + exp/nbf + aud/iss
claims = validate(
    token,
    key=public_key_pem,          # segredo HMAC (HS*) ou chave pública PEM (RS*/ES*)
    algorithms=["RS256"],        # nunca leia o alg do token
    audience="minha-api",
    issuer="https://auth.exemplo",
)
```

O que torna essa função segura está documentado nela mesma — é o material que entrego ao cliente junto do diagnóstico.

---

## 🏗️ Arquitetura

```
src/chaveiro/
├── core/        # jwt (base64url, HMAC, verificação RS/ES via cryptography), modelos
├── checks/      # catálogo declarativo + detectores (alg, header, claims, payload)
├── attacks/     # crack (dicionário HMAC) e confusion (PoC RS→HS)
├── reference/   # validação CORRETA, documentada — o lado da correção
├── report/      # console (rich) e json
└── cli.py       # interface typer
```

---

## ⚖️ Uso ético

Ferramentas de ataque (`crack`, `forge`, `forge-confusion`) são para **sistemas que você possui ou tem autorização explícita para testar**. O objetivo é defensivo: comprovar a falha para justificar a correção. No Brasil, acesso não autorizado é crime (Lei 12.737/2012). Use com escopo definido.

---

## 🧭 Roadmap

- [ ] Verificação de assinatura PS*/EdDSA na referência.
- [ ] Detecção de `jwt` confusion via `cty`/nested tokens.
- [ ] Modo batch (auditar muitos tokens de um arquivo/log).
- [ ] Checagem de tamanho mínimo de segredo HMAC por análise de força.

---

## 📄 Licença

[MIT](LICENSE) © 2026 Paulo Marcos Lucio.

---

<div align="center">
<sub>Parte da suíte AppSec — junto do <a href="https://github.com/Paulo-Marcos-Lucio/sentinela">Sentinela</a> e do <a href="https://github.com/Paulo-Marcos-Lucio/guardiao">Guardião</a>.</sub>
</div>
