# Changelog

O formato segue [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e
[SemVer](https://semver.org/lang/pt-BR/).

## [Não lançado]

### Adicionado

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
