"""Corpus de tokens com o SHAPE real de emissores conhecidos (item C02 do backlog).

`bench/gerar.py` mede vetor de ataque; isto mede o outro lado da mesma moeda:
texto **legítimo**, no jargão de cada provedor — `realm_access` do Keycloak,
`tid`/`oid` do Entra, `token_use` do Cognito — não pode se confundir com
achado. Um auditor que nunca viu a forma real de um emissor valida contra um
boneco de palha; aqui ele vê o boneco de verdade.

Cada função devolve tokens moldados no formato **documentado publicamente**
pelo próprio emissor (RFC/doc oficial — ver comentário de cada função). Nenhum
dado é de pessoa real: nome, e-mail, `sub`/`oid`/`kid` são fabricados — mesmo
assim com a FORMA certa (UUID onde o emissor usa UUID, string numérica onde o
Google usa string numérica), porque é a forma, não o conteúdo, que decide se
a ferramenta confunde claim de emissor com achado.

Como `bench/gerar.py`, o token é computado em tempo de IMPORTAÇÃO a partir de
dict literal — nunca existe como string `eyJ...` fixa no código-fonte (o push
protection do GitHub recusaria, e estaria certo: ele não sabe que é sintético).
"""

from __future__ import annotations

import json
from collections.abc import Callable

from chaveiro.core.jwt import b64url_encode

#: 'agora' fixo do corpus: torna exp/iat reprodutíveis entre execuções.
AGORA = 1_800_000_000


def _token(header: dict[str, object], payload: dict[str, object]) -> str:
    """JWS compacto com assinatura RSA sintética — a forma que todo emissor
    aqui usa de verdade (nenhum destes assina com HMAC em produção)."""
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return f"{h}.{p}.{b64url_encode(b'assinatura-rsa-sintetica-nao-e-real')}"


def tokens_keycloak() -> list[str]:
    """Access token de Keycloak num realm próprio (self-hosted ou Red Hat SSO).

    Shape documentado em keycloak.org/docs (Server Administration Guide,
    "Identity Brokering" / token introspection): `azp` (client que pediu o
    token), `realm_access`/`resource_access` (roles por realm e por client,
    é a forma própria do Keycloak — nenhum outro emissor usa esses dois
    nomes), `session_state`, `acr`, `scope`, `typ: "Bearer"`.
    """
    header = {"alg": "RS256", "typ": "JWT", "kid": "zAeW9k2B1QvD4mX7pL0f8tRcN3hY6sJu"}
    emissor = "https://id.exemplo-corp.com.br/realms/exemplo"

    def _base(sub: str, azp: str) -> dict[str, object]:
        return {
            "exp": AGORA + 3600,
            "iat": AGORA,
            "jti": f"{sub[:8]}-aaaa-bbbb-cccc-{sub[-12:]}",
            "iss": emissor,
            "aud": "account",
            "sub": sub,
            "typ": "Bearer",
            "azp": azp,
            "session_state": "c5a1f3e2-7b9d-4a6e-8c1f-2d9b4e7a1f3c",
            "acr": "1",
            "scope": "openid profile email",
        }

    return [
        _token(
            header,
            {
                **_base("f47ac10b-58cc-4372-a567-0e02b2c3d479", "portal-cliente"),
                "realm_access": {"roles": ["offline_access", "uma_authorization"]},
                "resource_access": {"portal-cliente": {"roles": ["user"]}},
                "preferred_username": "maria.exemplo",
                "email": "maria.exemplo@exemplo-corp.com.br",
                "email_verified": True,
                "name": "Maria Exemplo",
                "given_name": "Maria",
                "family_name": "Exemplo",
            },
        ),
        _token(
            header,
            {
                **_base("7c9e6679-7425-40de-944b-e07fc1f90ae7", "portal-cliente"),
                "realm_access": {"roles": ["admin", "offline_access"]},
                "resource_access": {"portal-cliente": {"roles": ["admin", "user"]}},
                "preferred_username": "joao.exemplo",
                "email": "joao.exemplo@exemplo-corp.com.br",
                "email_verified": True,
                "name": "João Exemplo",
            },
        ),
        _token(
            header,
            {
                **_base("2f1e8a4d-6c3b-4f91-9a7d-1b5e8c2f4a6d", "api-interna"),
                "realm_access": {"roles": ["service"]},
                "resource_access": {"api-interna": {"roles": ["batch-job"]}},
                "clientHost": "10.0.4.12",
                "clientId": "api-interna",
            },
        ),
        _token(
            header,
            {
                **_base("9b3d6a1f-4e8c-4a2d-b7f1-3c6e9a2d5f8b", "portal-cliente"),
                "realm_access": {"roles": ["user"]},
                "resource_access": {"portal-cliente": {"roles": ["user"]}},
                "preferred_username": "ana.exemplo",
                "email": "ana.exemplo@exemplo-corp.com.br",
                "email_verified": False,
                "name": "Ana Exemplo",
            },
        ),
        _token(
            header,
            {
                **_base("5e8b2d4f-1a6c-4e9d-8b3f-6a1d4e8c2b5f", "mobile-app"),
                "realm_access": {"roles": ["user"]},
                "resource_access": {"mobile-app": {"roles": ["user"]}},
                "preferred_username": "pedro.exemplo",
                "email": "pedro.exemplo@exemplo-corp.com.br",
                "email_verified": True,
                "name": "Pedro Exemplo",
                "acr": "urn:keycloak:loa:2fa",
            },
        ),
    ]


def tokens_auth0() -> list[str]:
    """Tokens do Auth0: access token de usuário, de M2M (client-credentials) e
    um ID token OIDC.

    Shape documentado em auth0.com/docs/secure/tokens: `sub` no formato
    `<connection>|<id>` (`auth0|…`, `google-oauth2|…`), `azp` só aparece com
    múltiplas audiences, `gty` marca o grant type (`client-credentials` nos
    M2M — aí `sub` É o `client_id`, não um usuário), claim custom sempre
    **namespaced** por URL própria (`https://exemplo-corp.com.br/roles`) —
    Auth0 documenta que claim não-namespaced é descartada pelo próprio OIDC.
    """
    header = {"alg": "RS256", "typ": "JWT", "kid": "NjJBRjg5QzQyRDQ0QUZCNTk3QjE1NDJB"}
    emissor = "https://exemplo-corp.us.auth0.com/"

    return [
        _token(
            header,
            {
                "iss": emissor,
                "sub": "auth0|60a7f3c1e4b0f1001f3a2b11",
                "aud": ["https://api.exemplo-corp.com.br", emissor + "userinfo"],
                "iat": AGORA,
                "exp": AGORA + 3600,
                "azp": "n2D4f8kQpL0vX7mZ9tR3cY6sJ1hA5bE2",
                "scope": "openid profile email read:pedidos",
                "https://exemplo-corp.com.br/roles": ["cliente"],
            },
        ),
        _token(
            header,
            {
                "iss": emissor,
                "sub": "google-oauth2|107350356123456789012",
                "aud": "https://api.exemplo-corp.com.br",
                "iat": AGORA,
                "exp": AGORA + 3600,
                "scope": "read:pedidos write:pedidos",
                "https://exemplo-corp.com.br/roles": ["cliente", "beta-tester"],
            },
        ),
        _token(
            header,
            {
                "iss": emissor,
                "sub": "svc-faturamento@clients",
                "aud": "https://api.exemplo-corp.com.br",
                "iat": AGORA,
                "exp": AGORA + 7200,
                "gty": "client-credentials",
                "scope": "write:faturas read:faturas",
            },
        ),
        _token(
            header,
            {
                "iss": emissor,
                "sub": "auth0|5f1b8c2d6e4a3f001e2d3c44",
                "aud": "n2D4f8kQpL0vX7mZ9tR3cY6sJ1hA5bE2",
                "iat": AGORA,
                "exp": AGORA + 3600,
                "email": "cliente.exemplo@exemplo-corp.com.br",
                "email_verified": True,
                "name": "Cliente Exemplo",
                "picture": "https://s.gravatar.com/avatar/0000000000000000000000000000000",
                "nickname": "cliente.exemplo",
                "updated_at": "2026-09-01T10:00:00.000Z",
            },
        ),
        _token(
            header,
            {
                "iss": emissor,
                "sub": "sms|5e9a1b3c7d2f4e001a6b8c99",
                "aud": "https://api.exemplo-corp.com.br",
                "iat": AGORA,
                "exp": AGORA + 1800,
                "scope": "openid read:perfil",
                "https://exemplo-corp.com.br/roles": ["cliente"],
            },
        ),
    ]


def tokens_entra() -> list[str]:
    """Tokens do Microsoft Entra ID (Azure AD) — v2.0 e um v1.0 para contraste.

    Shape documentado em learn.microsoft.com/entra/identity-platform/id-token
    e access-token: `tid`/`oid` (GUID de tenant/objeto), `v2.0` tem `iss` em
    `.../v2.0` e usa `azp`+`ver:"2.0"`; `v1.0` usa `appid`+`ver:"1.0"` no
    lugar de `azp` e não tem `/v2.0` no `iss`. `scp` é o scope delegado;
    `roles` é o App Role (aplicação, não usuário).
    """
    tenant = "72f988bf-86f1-41af-91ab-2d7cd011db47"
    header = {
        "typ": "JWT",
        "alg": "RS256",
        "kid": "nOo3ZDrODXEK1jKWhXslHR_KXEg",
        "x5t": "nOo3ZDrODXEK1jKWhXslHR_KXEg",
    }

    return [
        _token(
            header,
            {
                "aud": "00001111-aaaa-2222-bbbb-333344445555",
                "iss": f"https://login.microsoftonline.com/{tenant}/v2.0",
                "iat": AGORA,
                "nbf": AGORA,
                "exp": AGORA + 3600,
                "aio": "AXQAi/8TAAAARwaWE5MlbYb4FSP4F2VudzuPLLnxPWhr",
                "azp": "00001111-aaaa-2222-bbbb-333344445555",
                "azpacr": "0",
                "name": "Carlos Exemplo",
                "oid": "4f8c2d6e-1a3b-4f9d-8e7c-2b5a1d4e8c3f",
                "preferred_username": "carlos.exemplo@exemplocorp.onmicrosoft.com",
                "rh": "0.AXoAv4j5cvGBr0GRqy181B2kRwAA.",
                "scp": "User.Read Mail.Read",
                "sub": "9c3e6a1b-5d8f-4c2a-b7e4-1f6a9d3c5e8b",
                "tid": tenant,
                "uti": "a1B2c3D4e5F6g7H8i9J0",
                "ver": "2.0",
            },
        ),
        _token(
            header,
            {
                "aud": "00001111-aaaa-2222-bbbb-333344445555",
                "iss": f"https://login.microsoftonline.com/{tenant}/v2.0",
                "iat": AGORA,
                "nbf": AGORA,
                "exp": AGORA + 3600,
                "azp": "00001111-aaaa-2222-bbbb-333344445555",
                "name": "Beatriz Exemplo",
                "oid": "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
                "preferred_username": "beatriz.exemplo@exemplocorp.onmicrosoft.com",
                "scp": "openid profile email",
                "sub": "6d9c2a5e-8b1f-4d7a-9c3e-5f8a1b4d7c9e",
                "tid": tenant,
                "ver": "2.0",
            },
        ),
        # Token v1.0: appid+ver"1.0" no lugar de azp/v2.0 — contraste deliberado.
        _token(
            header,
            {
                "aud": "https://graph.microsoft.com",
                "iss": f"https://sts.windows.net/{tenant}/",
                "iat": AGORA,
                "nbf": AGORA,
                "exp": AGORA + 3600,
                "appid": "00001111-aaaa-2222-bbbb-333344445555",
                "appidacr": "1",
                "oid": "2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e",
                "roles": ["Directory.Read.All"],
                "sub": "8f1a3c5e-9b2d-4e6a-8c1f-3d5e8a2b4c6d",
                "tid": tenant,
                "upn": "svc-integracao@exemplocorp.onmicrosoft.com",
                "ver": "1.0",
            },
        ),
        _token(
            header,
            {
                "aud": "00001111-aaaa-2222-bbbb-333344445555",
                "iss": f"https://login.microsoftonline.com/{tenant}/v2.0",
                "iat": AGORA,
                "nbf": AGORA,
                "exp": AGORA + 3600,
                "azp": "00001111-aaaa-2222-bbbb-333344445555",
                "name": "Equipe Financeiro Exemplo",
                "oid": "5c8a1f3d-7b2e-4c9d-8a1f-3e6c9a2d5f8b",
                "preferred_username": "financeiro@exemplocorp.onmicrosoft.com",
                "scp": "Mail.Send Files.ReadWrite",
                "sub": "3e6a9d1c-5f8b-4a2d-9e7c-1b4d8a2f6c9e",
                "tid": tenant,
                "ver": "2.0",
            },
        ),
        _token(
            header,
            {
                "aud": "00001111-aaaa-2222-bbbb-333344445555",
                "iss": f"https://login.microsoftonline.com/{tenant}/v2.0",
                "iat": AGORA,
                "nbf": AGORA,
                "exp": AGORA + 3600,
                "azp": "00001111-aaaa-2222-bbbb-333344445555",
                "name": "Rafael Exemplo",
                "oid": "7a2d4f6c-8b1e-4d9a-9c3e-6f8a1d4c7e9b",
                "preferred_username": "rafael.exemplo@exemplocorp.onmicrosoft.com",
                "roles": ["Reader"],
                "sub": "1f4c7a9d-3e6b-4a8c-8d1f-5e9c3a6d8b2f",
                "tid": tenant,
                "ver": "2.0",
            },
        ),
    ]


def tokens_cognito() -> list[str]:
    """ID token e access token do AWS Cognito User Pool.

    Shape documentado em docs.aws.amazon.com/cognito (Understanding the ID
    token / access token): o DISCRIMINANTE é `token_use` (`id` vs `access`).
    Só o ID token tem `email`/`cognito:username` como identidade; só o access
    token tem `client_id`+`scope`. Os dois compartilham `origin_jti` (liga ao
    refresh token, para revogação) e o mesmo `iss` de user pool.

    Nota: o próprio AWS documenta que `aud` só aparece no access token
    quando a aplicação pediu *resource binding* — na ausência disso (os
    2 access tokens abaixo), `audit_token` acerta ao reportar
    `claim-no-aud`. Não é falso-positivo do Chaveiro: é um achado real
    sobre a forma como o Cognito emite o token por padrão.
    """
    pool = "sa-east-1_AbCdEfGhI"
    client_id = "3n9q9h9r9s9t9u9v9w9x9y9z9a"
    header = {"kid": "rT6vQpL0fXc3mZ9kY7sJ1hA5bE2nD4", "alg": "RS256"}
    emissor = f"https://cognito-idp.sa-east-1.amazonaws.com/{pool}"

    return [
        _token(
            header,
            {
                "sub": "6d9c2a5e-8b1f-4d7a-9c3e-5f8a1b4d7c9e",
                "email_verified": True,
                "iss": emissor,
                "cognito:username": "lucas.exemplo",
                "origin_jti": "4f8c2d6e-1a3b-4f9d-8e7c-2b5a1d4e8c3f",
                "aud": client_id,
                "event_id": "9c3e6a1b-5d8f-4c2a-b7e4-1f6a9d3c5e8b",
                "token_use": "id",
                "auth_time": AGORA,
                "exp": AGORA + 3600,
                "iat": AGORA,
                "jti": "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
                "email": "lucas.exemplo@exemplo-corp.com.br",
            },
        ),
        _token(
            header,
            {
                "sub": "2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e",
                "email_verified": True,
                "iss": emissor,
                "cognito:username": "fernanda.exemplo",
                "origin_jti": "8f1a3c5e-9b2d-4e6a-8c1f-3d5e8a2b4c6d",
                "aud": client_id,
                "event_id": "5c8a1f3d-7b2e-4c9d-8a1f-3e6c9a2d5f8b",
                "token_use": "id",
                "auth_time": AGORA,
                "exp": AGORA + 3600,
                "iat": AGORA,
                "jti": "3e6a9d1c-5f8b-4a2d-9e7c-1b4d8a2f6c9e",
                "email": "fernanda.exemplo@exemplo-corp.com.br",
            },
        ),
        _token(
            header,
            {
                "sub": "7a2d4f6c-8b1e-4d9a-9c3e-6f8a1d4c7e9b",
                "iss": emissor,
                "client_id": client_id,
                "origin_jti": "1f4c7a9d-3e6b-4a8c-8d1f-5e9c3a6d8b2f",
                "event_id": "4a7c9d1f-6e3b-4a8d-9c2e-7f1a4d6c9e3b",
                "token_use": "access",
                "scope": "aws.cognito.signin.user.admin",
                "auth_time": AGORA,
                "exp": AGORA + 3600,
                "iat": AGORA,
                "jti": "9e3c6a1d-4f8b-4a2e-8c1d-5b9a3e6c8f1a",
                "username": "lucas.exemplo",
            },
        ),
        _token(
            header,
            {
                "sub": "1f4c7a9d-3e6b-4a8c-8d1f-5e9c3a6d8b2f",
                "iss": emissor,
                "client_id": client_id,
                "origin_jti": "6e3b9d1f-4a8c-4e9d-8b3f-6a1d4e8c2b5f",
                "event_id": "8c1f3d5e-7a2b-4c9d-8a1f-3e6c9a2d5f8b",
                "token_use": "access",
                "scope": "aws.cognito.signin.user.admin",
                "auth_time": AGORA,
                "exp": AGORA + 3600,
                "iat": AGORA,
                "jti": "5f8a1b4d-7c9e-4a2d-9e7c-1b4d8a2f6c9e",
                "username": "fernanda.exemplo",
                "cognito:groups": ["financeiro"],
            },
        ),
        _token(
            header,
            {
                "sub": "9c3e6a1b-5d8f-4c2a-b7e4-1f6a9d3c5e8b",
                "email_verified": False,
                "iss": emissor,
                "cognito:username": "rafael.exemplo",
                "origin_jti": "2b5a1d4e-8c3f-4a6d-9e1a-3c5e8a2b4c6d",
                "aud": client_id,
                "event_id": "6f8a1d4c-7e9b-4a2d-8c1f-5e9c3a6d8b2f",
                "token_use": "id",
                "auth_time": AGORA,
                "exp": AGORA + 3600,
                "iat": AGORA,
                "jti": "4a2d6c9e-8b1f-4d7a-9c3e-5f8a1b4d7c9e",
                "email": "rafael.exemplo@exemplo-corp.com.br",
            },
        ),
    ]


def tokens_google() -> list[str]:
    """ID token do Google (Sign In With Google / OAuth2 OIDC).

    Shape documentado em developers.google.com/identity/openid-connect:
    `iss` é `https://accounts.google.com` (ou `accounts.google.com`, os dois
    são válidos por doc), `sub` é string NUMÉRICA (nunca UUID — é o
    identificador estável do Google), `azp` só aparece quando `aud` ≠ `azp`
    (fluxos com múltiplos clients), `at_hash` liga o id_token ao access token.
    """
    header = {"alg": "RS256", "kid": "f36dcf20b2d6b4f5a1c0b3e9d8a7c6f5e4d3c2b1", "typ": "JWT"}
    client_id = "123456789012-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6.apps.googleusercontent.com"

    return [
        _token(
            header,
            {
                "iss": "https://accounts.google.com",
                "azp": client_id,
                "aud": client_id,
                "sub": "107350356123456789012",
                "email": "gabriela.exemplo@gmail.com",
                "email_verified": True,
                "at_hash": "Hk9mP2qAtZ7uLvB3cD5fG6h",
                "iat": AGORA,
                "exp": AGORA + 3600,
                "name": "Gabriela Exemplo",
                "picture": "https://lh3.googleusercontent.com/a/exemplo-01=s96-c",
                "given_name": "Gabriela",
                "family_name": "Exemplo",
                "locale": "pt-BR",
            },
        ),
        _token(
            header,
            {
                "iss": "accounts.google.com",
                "azp": client_id,
                "aud": client_id,
                "sub": "116204981234567890123",
                "email": "thiago.exemplo@gmail.com",
                "email_verified": True,
                "at_hash": "Qp0vX7mZ9tR3cY6sJ1hA5bE2nD4fG6",
                "iat": AGORA,
                "exp": AGORA + 3600,
                "name": "Thiago Exemplo",
                "picture": "https://lh3.googleusercontent.com/a/exemplo-02=s96-c",
                "given_name": "Thiago",
                "family_name": "Exemplo",
                "locale": "pt-BR",
            },
        ),
        _token(
            header,
            {
                "iss": "https://accounts.google.com",
                "aud": client_id,
                "sub": "101987654321098765432",
                "email": "exemplo.servico@exemplo-corp.com.br",
                "email_verified": True,
                "hd": "exemplo-corp.com.br",
                "at_hash": "B3cD5fG6hJ9kMnP2qAtZ7uLvB3cD5",
                "iat": AGORA,
                "exp": AGORA + 3600,
                "name": "Conta de Serviço Exemplo",
                "locale": "pt-BR",
            },
        ),
        _token(
            header,
            {
                "iss": "https://accounts.google.com",
                "azp": client_id,
                "aud": client_id,
                "sub": "112233445566778899001",
                "email": "camila.exemplo@gmail.com",
                "email_verified": False,
                "at_hash": "mZ9tR3cY6sJ1hA5bE2nD4fG6hJ9kMn",
                "iat": AGORA,
                "exp": AGORA + 3600,
                "name": "Camila Exemplo",
                "picture": "https://lh3.googleusercontent.com/a/exemplo-03=s96-c",
                "given_name": "Camila",
                "family_name": "Exemplo",
                "locale": "en",
            },
        ),
        _token(
            header,
            {
                "iss": "https://accounts.google.com",
                "aud": "987654321098-z9y8x7w6v5u4t3s2r1q0p9o8n7m6l5k4.apps.googleusercontent.com",
                "azp": client_id,
                "sub": "119876543210987654321",
                "email": "bruno.exemplo@outlook.com",
                "email_verified": True,
                "at_hash": "sJ1hA5bE2nD4fG6hJ9kMnP2qAtZ7uL",
                "iat": AGORA,
                "exp": AGORA + 3600,
                "name": "Bruno Exemplo",
                "given_name": "Bruno",
                "family_name": "Exemplo",
                "locale": "pt-BR",
            },
        ),
    ]


def tokens_open_finance_br() -> list[str]:
    """ID token FAPI do Open Finance Brasil (fluxo hybrid, autorização de consentimento).

    Shape conforme o Open Finance Brasil FAPI Security Profile (perfil
    Financial-grade API, cláusula de autenticação/consentimento): `acr` é
    OBRIGATÓRIO em todo id_token e assume `urn:brasil:openbanking:loa2` (ou
    `loa3` para autenticação forte) — é a claim que não existe em nenhum dos
    emissores genéricos acima. Assinatura em `PS256`/`ES256`: o perfil FAPI
    avançado (que o Open Finance Brasil adota) não permite `RS256` nem
    algoritmo simétrico. `s_hash`/`nonce` são do fluxo *hybrid* do FAPI
    (ligam o id_token ao code/state emitidos na mesma autorização).
    """
    header = {"alg": "PS256", "typ": "JWT", "kid": "8b1e4d7a9c3f6b2e5d8a1c4f7b9e2d5a"}
    participante = "https://auth.instituicao-exemplo.com.br"
    client_id = "9f3e6a1b-5d8f-4c2a-b7e4-1f6a9d3c5e8b"  # client_id do diretório é UUID

    return [
        _token(
            header,
            {
                "iss": participante,
                "sub": "pairwise-4f8c2d6e1a3b4f9d8e7c2b5a1d4e8c3f",
                "aud": client_id,
                "iat": AGORA,
                "exp": AGORA + 300,
                "auth_time": AGORA - 120,
                "nonce": "n-0S6_WzA2Mj",
                "acr": "urn:brasil:openbanking:loa2",
                "amr": ["pwd"],
                "s_hash": "LPJNul3XEgLP6J5Z5A9Iyg",
                "sid": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            },
        ),
        _token(
            header,
            {
                "iss": participante,
                "sub": "pairwise-1a2b3c4d5e6f4a7b8c9d0e1f2a3b4c5d",
                "aud": client_id,
                "iat": AGORA,
                "exp": AGORA + 300,
                "auth_time": AGORA - 60,
                "nonce": "n-7Yx2_QpR9z",
                "acr": "urn:brasil:openbanking:loa3",
                "amr": ["pwd", "otp"],
                "s_hash": "9mP2qAtZ7uLvB3cD5fG6hJ",
                "sid": "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5",
            },
        ),
        _token(
            header,
            {
                "iss": "https://auth.banco-parceiro-exemplo.com.br",
                "sub": "pairwise-6d9c2a5e8b1f4d7a9c3e5f8a1b4d7c9e",
                "aud": client_id,
                "iat": AGORA,
                "exp": AGORA + 300,
                "auth_time": AGORA - 90,
                "nonce": "n-3Kp8_VzL1q",
                "acr": "urn:brasil:openbanking:loa2",
                "amr": ["pwd"],
                "s_hash": "kMnP2qAtZ7uLvB3cD5fG6hJ9",
                "sid": "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6",
            },
        ),
        _token(
            header,
            {
                "iss": participante,
                "sub": "pairwise-9b3d6a1f4e8c4a2db7f13c6e9a2d5f8b",
                "aud": "7a2d4f6c-8b1e-4d9a-9c3e-6f8a1d4c7e9b",
                "iat": AGORA,
                "exp": AGORA + 300,
                "auth_time": AGORA - 30,
                "nonce": "n-5Hf1_TuY6w",
                "acr": "urn:brasil:openbanking:loa3",
                "amr": ["pwd", "otp"],
                "s_hash": "cY6sJ1hA5bE2nD4fG6hJ9kMn",
                "sid": "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1",
            },
        ),
        _token(
            header,
            {
                "iss": participante,
                "sub": "pairwise-2f1e8a4d6c3b4f919a7d1b5e8c2f4a6d",
                "aud": client_id,
                "iat": AGORA,
                "exp": AGORA + 300,
                "auth_time": AGORA - 45,
                "nonce": "n-8Wq4_NbE3r",
                "acr": "urn:brasil:openbanking:loa2",
                "amr": ["pwd"],
                "s_hash": "tZ7uLvB3cD5fG6hJ9kMnP2qA",
                "sid": "e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            },
        ),
    ]


#: Nome do emissor -> função que devolve os tokens dele. Usado pelo
#: `main()` abaixo e pelos testes (`tests/test_bench_emissores.py`).
EMISSORES: dict[str, Callable[[], list[str]]] = {
    "keycloak": tokens_keycloak,
    "auth0": tokens_auth0,
    "entra": tokens_entra,
    "cognito": tokens_cognito,
    "google": tokens_google,
    "open_finance_br": tokens_open_finance_br,
}


def main() -> None:
    total = 0
    for nome, fn in EMISSORES.items():
        tokens = fn()
        total += len(tokens)
        print(f"{nome:16s} {len(tokens):2d} tokens")
    print(f"total: {total} tokens de {len(EMISSORES)} emissores")


if __name__ == "__main__":
    main()
