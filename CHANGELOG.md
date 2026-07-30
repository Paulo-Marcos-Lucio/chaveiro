# Changelog

O formato segue [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e
[SemVer](https://semver.org/lang/pt-BR/).

## [Não lançado]

### Documentação

- **README com prova de campo e Pro honesto**: nova seção "Prova de campo" com
  os números medidos da bateria real (recall 22/22 vetores, 0 falso-positivo em
  6/6 tokens legítimos, 24.606 tokens/s no `batch`, token hostil não derruba o
  lote) e o falso-positivo conhecido (`secret` como substring casa `secretary`)
  documentado em vez de escondido. A seção Pro passa a dizer com todas as letras
  que **a engine é a mesma** — o Pro é **serviço** (auditoria guiada, PoC
  autorizado, validação de referência aplicada ao stack do cliente), não código
  diferente atrás de paywall.

### Corrigido

- **Token hostil não derruba mais o lote** (`batch`): um JWT com payload
  profundamente aninhado levantava `RecursionError` (`json.loads`/`json.dumps`
  são recursivos), abortava o lote inteiro e apagava a auditoria dos demais —
  quebrando o contrato documentado de isolamento por token. Agora `decode`
  aplica um **teto explícito de aninhamento** (64 níveis, medido sem recursão
  sobre os bytes), o que protege decodificação, render e serialização de uma vez;
  `audit_batch` isola **qualquer** exceção por token (não só `JWTError`),
  registrando o tipo no campo `error`. Nenhum JWT legítimo passa de poucos níveis.
- **base64url estrito** (RFC 7515 §2): `b64url_decode` rejeita segmentos com
  caractere fora do alfabeto `A-Za-z0-9-_`, com espaço/quebra de linha, ou em
  base64 padrão (`+/`). O decodificador era tolerante (herdado do
  `urlsafe_b64decode`, que descarta bytes inválidos em silêncio) — um auditor
  leniente laudava um token que verificador estrito nenhum aceita.
- **`exp`/`nbf` não-numérico agora falha fechado**: a referência de validação e
  o detector passivo tratavam uma claim temporal presente-mas-não-numérica
  (`exp: "1"`, `Infinity`) como **ausente** — um token com `exp` em string nunca
  expirava. A referência passa a **rejeitar** (RFC 7519 §2: NumericDate é número)
  e o detector emite o novo achado `claim-malformed-time` (Média).
- **`claim-long-lifetime` dispara sem `iat`**: um token de 10 anos sem `iat`
  (mais perigoso, não menos) escapava porque a checagem exigia `exp` **e** `iat`.
  Sem `iat`, a vida útil passa a ser aproximada por `exp - agora`.
- **`payload-sensitive` varre em profundidade**: segredo/PII em objeto aninhado
  (`{"user": {"cpf": …}}` — a forma mais comum de payload JWT no Brasil) escapava
  porque o loop só olhava o primeiro nível. Agora percorre dicts/listas aninhados
  (sem recursão), casa chaves compostas (`user_password`, `db_secret`) e detecta
  **CPF de 11 dígitos crus** (com validação dos dígitos verificadores, para não
  gerar falso positivo em telefone/id).
- **JWT aninhado real** (RFC 7519 §5.2): apresentar um JWS-in-JWS legítimo
  (payload da casca = outro JWS compacto) fazia o `decode` abortar com "payload
  não é JSON" — a auditoria inteira parava no exato vetor que a ferramenta diz
  cobrir. Agora a casca é decodificada, o token interno fica em `token.nested` e
  `payload-nested-jwt` é emitido.
- **Injeção de marcação do Rich no relatório**: dado controlado pelo emissor do
  token (`alg`, `kid`, claims, mensagem de erro) contendo `[/]`/`[bold]` derrubava
  o console com `MarkupError` **ou** — pior — saía interpretado (cor/hyperlink
  forjados no laudo). Todo campo externo passa por `Text`, saindo literal.
- Removido arquivo de resíduo versionado por engano na raiz do repositório.

### Mudado

- **Contrato JSON alinhado à suíte** (`schema: "suite-appsec/1"`): identificador
  do achado em **`id`** (era `check`), `severity_rank` para ordenar entre
  ferramentas sem tabela de-para, `by_severity` sempre com as **5 chaves**
  (inclusive zeradas) e `owasp_edition` como campo próprio. **Quebra** quem
  consumia a chave `check`.
- **OWASP Top 10 migrado para a edição 2025** (vigente): o ano vai no cabeçalho
  da coluna (`OWASP 2025 / CWE`) e no JSON; os códigos passam a
  `A02→A04` (Cryptographic Failures), `A03→A05` (Injection), `A10→A01`
  (SSRF absorvido em Broken Access Control). Antes o dado não estava errado, mas
  incoerente com o resto da suíte.
- **`batch`: código de saída depende só de `--fail-on`.** Linha malformada é
  ruído normal de token colhido de log — a contagem vai para o stderr e não
  derruba mais o build (era exit 2). O `2` fica reservado a erro de uso. Novo
  `--strict` para quem quiser travar em entrada malformada.
- `--fail-on` passa a aceitar `info`.
- Subcomando `rules` renomeado para **`regras`** (`rules` continua como alias).

### Adicionado

- **Aviso de autorização em tempo de execução** nos comandos ofensivos (`crack`,
  `forge`, `forge-confusion`): imprimem o enquadramento legal (Lei 12.737/2012 c/
  14.155/2021) no stderr antes de agir.
- `--wordlist` do `crack` é lida **em streaming** (linha a linha): consumo de
  memória O(1) e o primeiro acerto encerra a leitura, em vez de materializar a
  lista inteira (rockyou ~140 MB carregava centenas de MB antes do 1º palpite).
- Portão de cobertura no CI (`--cov-fail-under=90`), `dependabot.yml` e actions
  do CI fixadas por SHA.
- **Meta-teste de catálogo**: toda checagem do `CATALOG` passa a exigir um caso
  positivo (e casos negativos que matam a inversão silenciosa de um detector) —
  uma checagem nova nasce vermelha até ter teste.
- **Detecção de JWT confusion por aninhamento** (checagem passiva, sem rede):
  `header-cty-nested` sinaliza quando o cabeçalho declara `cty: JWT` (comparação
  case-insensitive e com o prefixo `application/` opcional — RFC 7515 §4.1.10 /
  RFC 7519 §5.2), indicando um token aninhado cuja casca um verificador pode
  validar sem checar o miolo; `payload-nested-jwt` sinaliza quando uma claim
  carrega o que aparenta ser outro JWS compacto (heurística conservadora: 3
  segmentos e um cabeçalho base64url que decodifica para um objeto JSON com
  `alg`). Ambas com A07 · CWE-347. Fecha o item de roadmap "jwt confusion via
  cty/nested tokens".
- **Modo batch** (`chaveiro batch`): audita vários tokens — um por linha — de um
  arquivo ou do stdin (`-`), reusando o mesmo pipeline de auditoria passiva do
  `inspect`. Ignora linhas em branco e comentários (`#`) e remove um prefixo
  `Bearer ` opcional. Reporta cada token e um resumo agregado (console ou JSON,
  `mode: "batch"`). Exit-code coerente com `--fail-on`: 1 se a pior severidade
  do lote atingir o limiar, 2 se houver token malformado (sem atingir o limiar),
  0 caso contrário. Um token malformado é reportado sem interromper o lote. Fecha
  o item de roadmap "Modo batch". A composição decode + checagens virou
  `audit.audit_token`, fonte única usada por `inspect` e `batch`.
- Verificação de assinatura **PS256/PS384/PS512** (RSASSA-PSS, MGF1 e salt do
  tamanho do hash — RFC 7518 §3.5) e **EdDSA/Ed25519** (RFC 8037) em
  `core.jwt.verify_asymmetric`, e ambos na allowlist do módulo de referência.
  Verificação real via `cryptography`; testes de round-trip provam que a
  assinatura válida passa e que a adulterada (ou verificada com a chave errada)
  é rejeitada. Fecha o item de roadmap "PS*/EdDSA na referência".

## [0.1.0] — 2026-07-21

### Adicionado

- Decodificação de JWS compacto e primitivas de assinatura/verificação
  (HMAC HS*, RS*/ES* via `cryptography`).
- 17 checagens passivas: `alg:none`, alg ausente/desconhecido, `jku`/`x5u`/`jwk`/`x5c`,
  `kid` injection, `exp`/`iat`/`aud`/`iss`, vida útil longa e dado sensível no payload.
- Ataques: `crack` (dicionário HMAC com lista embutida) e `forge-confusion`
  (PoC de confusão de algoritmo RS→HS).
- Módulo de **referência** de validação correta (allowlist de algoritmos, rejeita
  `none`, confere assinatura + `exp`/`nbf` + `aud`/`iss`).
- CLI `chaveiro` (`inspect`, `crack`, `forge-confusion`, `forge`, `rules`).
- Suíte de testes com par RSA real e PoC de confusão reproduzido; mypy strict; CI.
