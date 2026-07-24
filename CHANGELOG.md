# Changelog

O formato segue [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e
[SemVer](https://semver.org/lang/pt-BR/).

## [Não lançado]

### Adicionado

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
