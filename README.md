<p align="right"><a href="README.en.md">🇺🇸 Read in English</a></p>

<a href="https://paulo-marcos-lucio.github.io"><img src="https://raw.githubusercontent.com/Paulo-Marcos-Lucio/chaveiro/main/assets/banner-abismo-v2.svg" alt="Chaveiro — as chaves que flutuam no escuro: auditor de segurança de tokens JWT/JWS" width="100%"/></a>

<div align="center">

# 🗝️ Chaveiro

### Auditor de segurança de tokens **JWT/JWS** — do diagnóstico ao PoC, com o lado da correção junto.

*Decodifica, audita e ataca (com autorização) tokens JWT: `alg:none`, confusão de algoritmo (RS→HS), segredo HMAC fraco, `kid`/`jku`/`x5u` como vetor de SSRF/injeção, e validação de claims. Inclui uma **referência mínima segura** de validação — porque encontrar a falha e mostrar como corrigir é o serviço completo.*

[![CI](https://github.com/Paulo-Marcos-Lucio/chaveiro/actions/workflows/ci.yml/badge.svg)](https://github.com/Paulo-Marcos-Lucio/chaveiro/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Ruff](https://img.shields.io/badge/lint-ruff-261230.svg)](https://github.com/astral-sh/ruff)
[![Checked with mypy](https://img.shields.io/badge/mypy-strict-2A6DB2.svg)](https://mypy-lang.org/)
[![Tests](https://img.shields.io/badge/tests-191%20passing-brightgreen.svg)](#-qualidade-de-engenharia--método)
[![Coverage](https://img.shields.io/badge/coverage-95%25-green.svg)](#-qualidade-de-engenharia--método)
[![OWASP](https://img.shields.io/badge/OWASP_2025-A07%2FA04-000000.svg)](https://owasp.org/Top10/2025/)

</div>

---

## 📌 Por que JWT quebra tanto

JWT é simples de emitir e **fácil de validar errado**. A maioria dos bypasses não ataca a criptografia — ataca o **verificador**:

- ele confia no `alg` que vem **dentro do token** (aceitando `none`, ou trocando RS256 por HS256);
- ele não confere `exp`/`nbf`;
- ele resolve a chave a partir de um campo do cabeçalho (`jku`/`x5u`/`jwk`) controlado pelo atacante;
- ele usa `kid` direto num caminho de arquivo ou numa query SQL.

O Chaveiro cobre esses vetores dos dois lados: **audita** um token, **prova** a falha com um PoC quando aplicável, e traz uma **referência mínima segura** de validação para você espelhar no seu verificador.

> **Contexto:** venho de **Open Finance / FAPI**, onde JWT/JWS (DPoP, client assertions, `id_token`) são o coração da autenticação. Este é o ferramental que uso para revisar esse tipo de integração.

---

## 🔎 O que ele audita

| Checagem | Risco | Severidade | OWASP 2025 / CWE |
| --- | --- | --- | --- |
| `alg-none` | Token não assinado aceito como válido | 🔴 Crítica | A07 · CWE-347 |
| `alg-missing` / `alg-unknown` | Verificação ambígua de algoritmo | 🟠/🟡 | A07 · CWE-347 |
| `alg-hmac-advisory` | HS* → risco de segredo fraco e de confusão RS→HS | 🔵 Baixa | A04 · CWE-326 |
| `header-jku` / `header-x5u` | Chave carregada de URL do token → **SSRF** / key injection | 🟠 Alta | A01 · CWE-918 |
| `header-jwk` | Chave pública embutida (atacante fornece a própria) | 🟠 Alta | A07 · CWE-347 |
| `header-kid-injection` | `kid` com `../`, `'`, `;` → path traversal / SQLi | 🟠 Alta | A05 · CWE-91 |
| `header-zip-jws` | `zip` (compressão) num JWS — viola o RFC, abre DoS por descompressão (caso Apache James) | 🟠 Alta | A06 · CWE-409 |
| `claim-no-exp` / `claim-long-lifetime` | Token eterno / longevo demais | 🟠/🟡 | A07 · CWE-613 |
| `claim-malformed-time` | `exp`/`nbf` presente mas não numérico → verificador falha aberto | 🟡 Média | A07 · CWE-613 |
| `claim-no-aud` / `claim-no-iss` / `claim-no-iat` | Falta amarração de destino/emissor | 🔵 Baixa | A07 · CWE-345 |
| `header-cty-nested` / `payload-nested-jwt` | JWT aninhado (`cty: JWT` ou payload que **é** outro JWS) — valide as duas camadas | 🟡/🔵 | A07 · CWE-347 |
| `payload-sensitive` | Segredo/PII no payload (JWT é base64, **não** cifrado) — varre também objetos aninhados e CPF | 🟡 Média | A04 · CWE-522 |

> A coluna cita o código do **OWASP Top 10:2025** (edição vigente, publicada em 2025-11-06). O JSON traz `owasp_edition: "2025"` e o rótulo completo em cada achado.

---

## 📊 Prova de campo

Não é folheto: os números abaixo saem de um **corpus rotulado e versionado** (`bench/`), reproduzível com dois comandos — vetores de ataque de um lado, tokens legítimos do outro. O corpus é **gerado pelo próprio script** (não se versiona token pronto) e o recall vem com **intervalo de confiança de Wilson**, porque com n=22 um número redondo sozinho anuncia uma precisão que a amostra não comporta.

```bash
python bench/gerar.py       # materializa os tokens rotulados (gitignored)
python bench/avaliar.py     # mede recall + IC95% e falso-positivo
```

| Métrica | Valor medido |
| --- | --- |
| **Recall** em vetores de ataque | **22 / 22 = 100%** · IC95% (Wilson) **[85% ; 100%]** — `alg:none`/ausente/desconhecido, `jku`/`x5u`/`jwk`/`x5c`, `kid` injection, `crit`, `cty:JWT`, aninhamento real, claim carregando JWT, `exp`/`iat`/`aud`/`iss` ausentes, expirado, vida longa, tempo malformado, `nbf` futuro, segredo no payload, CPF (mód-11) |
| **Falso-positivo** em tokens legítimos | **0 / 6** — RS256/PS256/ES256/EdDSA completos passaram limpos |
| **Resiliência a token hostil** | um JWT com aninhamento profundo **não derruba o lote** — é isolado, registrado no campo `error` e a auditoria dos demais segue |

O corpus **não é campo**: os tokens foram plantados por quem escreveu a ferramenta, então o número mede *cobertura dos vetores conhecidos*, não acurácia contra tráfego de produção. Ver `bench/README.md` para o que ele cobre e o que **não** cobre.

**Falso-positivo conhecido (transparência, não vitrine):** o detector `payload-sensitive` casa `secret` como *substring* do nome da claim, de propósito, para pegar as formas compostas reais (`client_secret`, `db_secret`, `dbSecret`). O custo é que uma claim chamada `secretary` também é sinalizada. É um aviso de severidade **baixa**, nunca um bypass — mas prefiro documentar aqui a decidir por você que você não ia notar.

---

## 🚀 Início rápido

**Pré-requisito:** Python **3.10+** (o CI cobre 3.10 / 3.11 / 3.12). Nada além
disso — sem serviço, sem chave de API, sem rede: a auditoria é local e passiva.

```bash
# 1. instale direto do Git (não há pacote no PyPI — ver a nota em Instalação)
pip install "git+https://github.com/Paulo-Marcos-Lucio/chaveiro.git"

# 2. audite um token — este exemplo público é um alg:none (token NÃO assinado)
echo "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9." | chaveiro inspect -
```

Do zero ao primeiro laudo em dois comandos. A saída traz a claim `sub` **redigida**
(LGPD), um achado **CRÍTICA `alg-none`** e os avisos de claims ausentes
(`exp`/`aud`/`iss`), e o processo **sai com código 1** (achado ≥ `high`). Para uma
saída de pipeline, troque por `chaveiro inspect - -f json`. É só isso para começar —
o resto deste README aprofunda cada comando e opção.

---

## 📦 Instalação

O Chaveiro **não está no PyPI** (`pip install chaveiro` traria outro pacote ou
nada). Instale direto do repositório:

```bash
# direto do Git (use pipx para isolar o CLI, se preferir)
pip install "git+https://github.com/Paulo-Marcos-Lucio/chaveiro.git"

# ou clonando, para desenvolver
git clone https://github.com/Paulo-Marcos-Lucio/chaveiro.git
cd chaveiro
pip install -e ".[dev]"
```

> Em CI, prefira fixar um commit: `pip install "git+https://github.com/Paulo-Marcos-Lucio/chaveiro.git@<sha>"`.

---

## 🧑‍💻 Uso

```bash
# audita um token (decodifica + todas as checagens passivas)
chaveiro inspect "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."

# PREFIRA ler o token do stdin ('-'): passá-lo por argumento deixa a credencial
# no histórico do shell e na lista de processos (ps/EDR). Por isso o argv avisa.
echo "$TOKEN" | chaveiro inspect - -f json --fail-on high

# audita vários tokens de uma vez — UM TOKEN POR LINHA (ignora branco/comentário e prefixo 'Bearer')
chaveiro batch tokens.txt --fail-on high        # sai 1 se algum token atingir o limiar
# extraia os tokens de um log antes de auditar (o batch não varre subtoken dentro da linha):
grep -oE 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*' access.log | chaveiro batch - -f json

# o segredo HMAC é fraco? (ataque de dicionário — lista embutida + sua wordlist)
chaveiro crack "$TOKEN" --wordlist rockyou.txt

# PoC de confusão de algoritmo: forja um HS256 com a chave PÚBLICA como segredo
chaveiro forge-confusion "$RS256_TOKEN" --public-key server.pub --set role=admin

# reassina um token modificado com um segredo conhecido (teste autorizado)
chaveiro forge "$TOKEN" --secret leaked-secret --set role=admin

# lista todas as checagens
chaveiro regras          # 'rules' continua funcionando como alias
```

**Código de saída** (`inspect`/`batch`): `1` se a pior severidade atingir
`--fail-on`, senão `0`; `2` é erro de uso (opção inválida, arquivo ilegível). O
default de `--fail-on` é **`high`** — um scanner de token não deve derrubar um
build por um achado informativo. No `batch`, linha malformada é ruído normal de
log: vai para o stderr e **não** falha o build (use `--strict` para travar
nela). Níveis aceitos: `none | info | low | medium | high | critical`.

**Token no argv e no stdin.** `inspect`, `crack`, `forge` e `forge-confusion`
aceitam `-` para ler o token do **stdin** (o `batch` também). Passar o token por
argumento vaza no histórico do shell e na lista de processos, então o argv **emite
um aviso** apontando o caminho seguro. Prefira o stdin em qualquer terminal
compartilhado ou com histórico.

**Privacidade das claims (LGPD).** Um JWT de cliente carrega rotineiramente PII do
**titular final** (`sub`, `email`, `cpf`, nome). Por padrão o laudo **redige** as
claims de identidade e qualquer valor que aparente e-mail/CPF, mantendo visíveis as
claims estruturais que a auditoria precisa (`exp`, `iat`, `nbf`, `iss`, `aud`,
`jti`, `typ`, `kid`). Use `--claims-completas` para ver tudo em claro — é opt-in
explícito, com aviso, porque quem grava o laudo é o operador desse dado.

O envelope JSON traz ainda `commit`, `ruleset_hash` (sha256 do catálogo de
checagens) e `artifact_sha256` (autoverificável), para o laudo ser vinculável ao
código e às regras que o produziram.

> **Para recomputar o `artifact_sha256`:** o hash é sobre os **bytes UTF-8** do JSON
> (o catálogo é PT-BR, com acentos). No Windows, `open(caminho)` lê em cp1252 e dá um
> "adulterado" falso — leia o arquivo como UTF-8 antes de recalcular:
> `open(caminho, "rb").read().decode("utf-8")`.

### Configuração — as opções que mais importam

Nada aqui é obrigatório: o Chaveiro roda com os defaults. Mude só quando o
contexto pedir. (`chaveiro <comando> --help` lista tudo.)

| Opção | Onde | Default | Quando mudar |
| --- | --- | --- | --- |
| `-f, --format` | `inspect`, `batch` | `console` | `json` para consumir em pipeline/painel (schema `suite-appsec/1`) |
| `--fail-on` | `inspect`, `batch` | `high` | baixe para `low`/`medium` num gate rígido; `none` para nunca falhar o build por severidade |
| `--claims-completas` | `inspect`, `batch` | desligado | só quando precisar ver a PII em claro — opt-in com aviso, você vira o operador LGPD do laudo |
| `--strict` | `batch` | desligado | quando linha malformada **deve** derrubar o build (por padrão é só ruído de log) |
| `-w, --wordlist` | `crack` | — | somar sua wordlist (ex.: `rockyou.txt`) à lista fraca embutida |
| `--no-defaults` | `crack` | desligado | testar **só** a sua wordlist, sem a lista embutida |
| `--set chave=valor` | `forge`, `forge-confusion` | — | editar claims no PoC (repetível: `--set sub=admin --set role=admin`) |
| `--alg` | `forge`, `forge-confusion` | `HS256` | forjar com outro HMAC (`HS384`/`HS512`) |
| `CHAVEIRO_COMMIT` (env) | todos | `git rev-parse HEAD` | fixar o SHA de proveniência quando rodar de um pacote instalado (sem `.git`) |

### O lado da correção — referência mínima segura

```python
from chaveiro.reference.secure_validation import validate, InvalidToken

# allowlist FIXA de algoritmos, rejeita 'none', confere assinatura + exp/nbf + aud/iss
claims = validate(
    token,
    key=public_key_pem,  # segredo HMAC (HS*) ou chave pública PEM (RS*/PS*/ES*/EdDSA)
    algorithms=["RS256"],  # nunca leia o alg do token
    audience="minha-api",
    issuer="https://auth.exemplo",
    typ="at+jwt",  # opcional: fixa o 'typ' esperado (RFC 9068)
)
```

É uma **referência mínima segura**, não um verificador completo pronto para
produção. O que ela **cobre**: allowlist obrigatória de algoritmos, rejeição de
`none` (inclusive na allowlist), verificação de assinatura HS*/RS*/PS*/ES*/EdDSA,
`exp`/`nbf` (com `leeway`) rejeitando NumericDate malformado (fail-closed),
`aud`/`iss`, `typ` quando exigido, e **falha explícita em JWT aninhado** (`cty:JWT`)
em vez de devolver claims vazias. O que ela **não** cobre: revogação/`jti`,
rotação e resolução de chave (JWKS/`kid`), `azp`/`nonce`/PKCE, replay e a validação
da segunda camada de um token aninhado. Adapte ao seu stack — é o material que
entrego ao cliente junto do diagnóstico, não um drop-in.

---

## 🔓 Versão Pro (privada) — o motor é o mesmo, o Pro é trabalho humano

**Para não haver dúvida: o Pro não é um motor diferente.** O detector deste repositório é o mesmo que roda no serviço — não existe "engine turbinada" escondida atrás de paywall, nem checagem que só nasce na versão paga. O que está público aqui é o que faz o trabalho. A tabela separa o que a **ferramenta** faz (você roda sozinho) do que o **serviço** acrescenta (trabalho humano sobre a mesma engine):

| | Ferramenta pública — **você roda** | Pro · serviço — **eu conduzo com você** |
| --- | --- | --- |
| **Motor de detecção** | O mesmo — **22/22** vetores (corpus `bench/`, IC95% [85%;100%]), **0** falso-positivo em 6 tokens legítimos | O **mesmo** motor, apontado para o seu fluxo real de autenticação |
| **Escopo** | O token que você colar, ou o arquivo/log que você tiver | Emissor **e** verificador do sistema inteiro, mais o histórico de tokens em log |
| **PoC de exploração** | `crack` / `forge` / `forge-confusion` na sua bancada | PoC **autorizado**, com escopo assinado, rodado no seu ambiente e documentado |
| **Correção** | Módulo `reference/` (referência mínima segura) documentado — você adapta ao seu código | Validação **implementada e testada no seu stack**, entregue via PR |
| **Segredo HMAC fraco** | A ferramenta aponta o risco | **Rotação conduzida com reteste** — confirmo que o novo segredo resiste |
| **Transferência** | README + código-fonte aberto | **Mentoria**: seu time entende o porquê de cada bypass, não só o patch |

> A engine é a mesma dos dois lados. O que você contrata no Pro é **tempo humano** — de quem construiu emissor e verificador em Open Finance / FAPI — nunca um recurso técnico escondido. Todo PoC é **gated**: só roda em sistema seu ou com autorização explícita por escrito.

<div align="center">

[![Pacotes e valores](https://img.shields.io/badge/Pacotes_e_valores-paulo--marcos--lucio.github.io-0f766e?style=for-the-badge)](https://paulo-marcos-lucio.github.io)
[![Falar no LinkedIn](https://img.shields.io/badge/LinkedIn-Falar_agora-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/paulo-marcos-a07379174/)

</div>

---

## 🏗️ Arquitetura

O Chaveiro resolve uma pergunta específica: *este token seria aceito por um verificador mal configurado?* — e responde antes que um atacante faça a mesma pergunta. O dado percorre um pipeline curto: você passa um token (ou um arquivo/log de tokens), ele é **decodificado sem verificar assinatura**, os detectores varrem cabeçalho, algoritmo, claims e payload, e cada fraqueza vira um `Finding` já classificado por **OWASP 2025 / CWE**. No fim sai um relatório — no **console** (rich) para ler, ou em **JSON** (`schema suite-appsec/1`) para pipeline. A auditoria é **100% passiva**, não toca a rede; os comandos de ataque (`crack`/`forge`) são separados e exigem autorização.

```mermaid
flowchart TD
    A["<b>cli.py</b><br/>Typer · token ou arquivo"] --> AUD["<b>audit.py</b><br/>orquestra a auditoria"]
    AUD --> DEC["<b>core/jwt.py</b><br/>decodifica sem verificar"]
    DEC --> CHK["<b>checks/detectors.py</b><br/>alg · header · claims · payload"]
    CHK --> CAT["<b>checks/catalog.py</b><br/>taxonomia OWASP 2025 · CWE"]
    CAT --> FND["<b>core/models.py</b><br/>Finding imutável"]
    FND --> RPT["<b>report/</b><br/>renderização · redação de PII"]
    RPT --> OUT
    A --> ATK["<b>attacks/</b><br/>crack · confusion (PoC autorizado)"]
    FND -.->|correção de referência| REF["<b>reference/</b><br/>validação mínima segura"]
    subgraph OUT [" Formatos de saída "]
        direction LR
        CON["console (rich)"] ~~~ JS["JSON · suite-appsec/1"]
    end
    classDef nucleo fill:#0e2a24,stroke:#3fb79e,stroke-width:2px,color:#e7ede9;
    classDef saida fill:#241d0f,stroke:#d6a94e,color:#f5ecd9;
    class A,AUD,DEC,CHK,CAT,FND,RPT nucleo;
    class CON,JS,ATK,REF saida;
```

```
src/chaveiro/
├── core/        # jwt (base64url, HMAC, verificação RS/PS/ES/EdDSA via cryptography), modelos
├── checks/      # catálogo declarativo + detectores (alg, header, claims, payload)
├── attacks/     # crack (dicionário HMAC) e confusion (PoC RS→HS)
├── reference/   # referência mínima segura, documentada — o lado da correção
├── report/      # console (rich) e json
├── audit.py     # orquestração: auditar um token e em lote (batch)
└── cli.py       # interface typer
```

---

## 🔬 Qualidade de engenharia & método

**Portões (medidos agora, não prometidos):** **191 testes** verdes (incluindo *property-based* com Hypothesis) · cobertura **95%** (o gate trava em `--cov-fail-under=90`) · `mypy --strict` limpo em **20 arquivos** · `ruff` (lint + format) limpo · CI em matriz **Python 3.10 / 3.11 / 3.12**.

**Teste que fica vermelho se a detecção for desfeita.** A suíte não confirma só o caso positivo — guarda a *inversão silenciosa*. Cada detector tem um par negativo (`_CASOS_NEGATIVOS` em `tests/test_detectors.py`): trocar `nbf > agora` por `nbf < agora` passa em qualquer teste que só olhe o positivo, mas deixa o negativo vermelho. E um meta-teste (`test_toda_checagem_do_catalogo_tem_caso_positivo`) reprova o build se uma checagem nova nascer sem caso que a exercite — disciplina humana virou invariante.

**Padrões que estão de fato no código:**
- **Separação de responsabilidades:** detecção (`checks/detectors.py`, decide *quando* emitir) × taxonomia (`checks/catalog.py`, os metadados) × orquestração (`audit.py`) × renderização (`report/console.py` e `report/json_report.py`).
- **Fonte única de verdade:** o mapa OWASP 2025 / CWE de cada achado vive só no `CATALOG` de `catalog.py`; a edição do OWASP é constante explícita (`OWASP_EDITION`), porque `A03` muda de significado entre 2021 e 2025.
- **Contrato de saída versionado:** JSON com `schema: "suite-appsec/1"`, `severity_rank` e `by_severity` sempre com as 5 chaves (inclusive zeradas) — um painel ordena e agrega sem fazer parsing do rótulo.
- **Tipos estritos e imutabilidade:** os modelos de domínio são `@dataclass(frozen=True)` (`DecodedToken`, `Finding`, `CheckMeta`); `mypy --strict` sobre `src`.

**Cadeia de suprimentos do próprio repo:** as actions do CI são fixadas por **SHA** (não por tag móvel), com o **Dependabot** atualizando esses SHAs mensalmente — `github-actions` e `pip`. Fixar sem Dependabot congelaria a versão vulnerável para sempre; as duas peças só fazem sentido juntas.

**PT-BR em código, teste e doc** é decisão consciente de consistência: o mesmo idioma do relatório que chega ao cliente, sem troca de contexto entre o achado e a recomendação.

---

## ⚖️ Uso ético

Ferramentas de ataque (`crack`, `forge`, `forge-confusion`) são para **sistemas que você possui ou tem autorização explícita para testar**. O objetivo é defensivo: comprovar a falha para justificar a correção. No Brasil, acesso não autorizado é crime (Lei 12.737/2012, agravada pela Lei 14.155/2021). Use com escopo definido — e esses três comandos **imprimem esse aviso ao rodar**.

---

## 🧭 Roadmap

- [x] Verificação de assinatura PS*/EdDSA na referência.
- [x] Detecção de `jwt` confusion via `cty`/nested tokens — inclusive JWT aninhado **real** (payload que é outro JWS compacto, RFC 7519 §5.2).
- [x] Modo batch (auditar muitos tokens de um arquivo/log), resistente a token hostil (aninhamento profundo não derruba o lote).
- [ ] Checagem de tamanho mínimo de segredo HMAC por análise de força.

---

## 📄 Licença

[MIT](LICENSE) © 2026 Paulo Marcos Lucio.

---

<div align="center">
<sub>Parte da suíte AppSec — junto do <a href="https://github.com/Paulo-Marcos-Lucio/sentinela">Sentinela</a> e do <a href="https://github.com/Paulo-Marcos-Lucio/guardiao">Guardião</a>.</sub>
</div>
