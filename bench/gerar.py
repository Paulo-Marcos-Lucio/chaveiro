"""Gera o corpus rotulado do Chaveiro — tokens de ataque e tokens legítimos.

Por que existe (P2-05). O perfil publicava "22/22 vetores de ataque, medido" sem
corpus público: número sem corpus é lembrança, não métrica. Aqui os vetores são
**gerados pelo próprio script** e ficam fora do versionamento (`.gitignore`) — um
corpus de tokens não deve versionar credenciais/segredos prontos (o push
protection do GitHub recusa e está certo). O que é versionado é o `manifest.json`
(os rótulos) e o código que reconstrói os tokens de forma determinística.

Uso:
    python bench/gerar.py            # materializa positivos.txt / negativos.txt / manifest.json
    python bench/avaliar.py          # mede recall + IC de Wilson e falso-positivo
"""

from __future__ import annotations

import json
import os
from typing import Any

from chaveiro.core.jwt import b64url_encode, encode_hmac

BASE = os.path.dirname(os.path.abspath(__file__))
# 'agora' fixo do corpus: torna exp/nbf/iat reprodutíveis entre execuções.
BENCH_NOW = 1_800_000_000
CPF_VALIDO = "529.982.247-25"  # dígitos verificadores corretos (mód-11)
SEGREDO = "k"


def _raw(header: dict[str, Any], payload: dict[str, Any], signature: bytes = b"sig") -> str:
    """JWS compacto arbitrário — para 'none', 'alg' ausente/desconhecido e aninhado.

    A assinatura é irrelevante: a auditoria é **passiva** e nunca verifica assinatura.
    """
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return f"{h}.{p}.{b64url_encode(signature)}"


def _hs(payload: dict[str, Any], **header_extra: Any) -> str:
    """Token HS256 assinado (segredo fixo e público — é corpus, não produção)."""
    header = {"alg": "HS256", "typ": "JWT", **header_extra}
    return encode_hmac(header, payload, SEGREDO.encode("utf-8"))


def _nested_real() -> str:
    """Casca cujo payload É outro JWS compacto (JWT aninhado real, RFC 7519 §5.2)."""
    interno = _hs({"sub": "a", "exp": BENCH_NOW + 60})
    h = b64url_encode(json.dumps({"alg": "HS256"}, separators=(",", ":")).encode("utf-8"))
    p = b64url_encode(interno.encode("utf-8"))
    return f"{h}.{p}.{b64url_encode(b'sig')}"


# Claims "bem-comportadas" reutilizadas nos vetores de HEADER, para que o único
# achado interessante seja o do cabeçalho (o resto do payload está completo).
_CLAIMS_OK = {
    "sub": "user-1",
    "exp": BENCH_NOW + 3600,
    "iat": BENCH_NOW,
    "aud": "api",
    "iss": "https://auth",
}


def positivos() -> list[dict[str, str]]:
    """22 vetores de ataque/fraqueza, cada um com o check_id que DEVE disparar."""
    return [
        {
            "vetor": "alg:none",
            "esperado": "alg-none",
            "token": _raw({"alg": "none"}, {"sub": "admin"}),
        },
        {"vetor": "alg ausente", "esperado": "alg-missing", "token": _raw({}, {"sub": "x"})},
        {
            "vetor": "alg desconhecido",
            "esperado": "alg-unknown",
            "token": _raw({"alg": "HS128"}, {"sub": "x"}),
        },
        {
            "vetor": "jku (SSRF)",
            "esperado": "header-jku",
            "token": _hs(_CLAIMS_OK, jku="https://evil.example/keys"),
        },
        {
            "vetor": "x5u (SSRF)",
            "esperado": "header-x5u",
            "token": _hs(_CLAIMS_OK, x5u="https://evil.example/cert"),
        },
        {
            "vetor": "jwk embutida",
            "esperado": "header-jwk",
            "token": _hs(_CLAIMS_OK, jwk={"kty": "oct"}),
        },
        {
            "vetor": "x5c embutida",
            "esperado": "header-x5c",
            "token": _hs(_CLAIMS_OK, x5c=["MIIB..."]),
        },
        {
            "vetor": "kid path-traversal",
            "esperado": "header-kid-injection",
            "token": _hs(_CLAIMS_OK, kid="../../etc/passwd"),
        },
        {
            "vetor": "crit presente",
            "esperado": "header-crit",
            "token": _hs(_CLAIMS_OK, crit=["exp"]),
        },
        {
            "vetor": "cty:JWT declarado",
            "esperado": "header-cty-nested",
            "token": _hs(_CLAIMS_OK, cty="JWT"),
        },
        {"vetor": "aninhamento real", "esperado": "payload-nested-jwt", "token": _nested_real()},
        {
            "vetor": "claim carrega JWT",
            "esperado": "payload-nested-jwt",
            "token": _hs({**_CLAIMS_OK, "embedded": _hs({"sub": "z", "exp": BENCH_NOW + 60})}),
        },
        {
            "vetor": "sem exp",
            "esperado": "claim-no-exp",
            "token": _hs({"sub": "x", "iat": BENCH_NOW, "aud": "api", "iss": "https://auth"}),
        },
        {
            "vetor": "expirado",
            "esperado": "claim-expired",
            "token": _hs(
                {
                    "sub": "x",
                    "exp": BENCH_NOW - 100,
                    "iat": BENCH_NOW - 160,
                    "aud": "api",
                    "iss": "https://auth",
                }
            ),
        },
        {
            "vetor": "vida longa",
            "esperado": "claim-long-lifetime",
            "token": _hs(
                {
                    "sub": "x",
                    "iat": BENCH_NOW,
                    "exp": BENCH_NOW + 40 * 3600,
                    "aud": "api",
                    "iss": "https://auth",
                }
            ),
        },
        {
            "vetor": "sem iat",
            "esperado": "claim-no-iat",
            "token": _hs({"sub": "x", "exp": BENCH_NOW + 60, "aud": "api", "iss": "https://auth"}),
        },
        {
            "vetor": "sem aud",
            "esperado": "claim-no-aud",
            "token": _hs(
                {"sub": "x", "exp": BENCH_NOW + 60, "iat": BENCH_NOW, "iss": "https://auth"}
            ),
        },
        {
            "vetor": "sem iss",
            "esperado": "claim-no-iss",
            "token": _hs({"sub": "x", "exp": BENCH_NOW + 60, "iat": BENCH_NOW, "aud": "api"}),
        },
        {
            "vetor": "exp não-numérico",
            "esperado": "claim-malformed-time",
            "token": _hs(
                {"sub": "x", "exp": "soon", "iat": BENCH_NOW, "aud": "api", "iss": "https://auth"}
            ),
        },
        {
            "vetor": "nbf no futuro",
            "esperado": "claim-nbf-future",
            "token": _hs(
                {
                    "sub": "x",
                    "exp": BENCH_NOW + 3600,
                    "iat": BENCH_NOW,
                    "nbf": BENCH_NOW + 1800,
                    "aud": "api",
                    "iss": "https://auth",
                }
            ),
        },
        {
            "vetor": "segredo no payload",
            "esperado": "payload-sensitive",
            "token": _hs({**_CLAIMS_OK, "password": "hunter2"}),
        },
        {
            "vetor": "CPF no payload (LGPD)",
            "esperado": "payload-sensitive",
            "token": _hs({**_CLAIMS_OK, "cpf": CPF_VALIDO}),
        },
    ]


def negativos() -> list[dict[str, str]]:
    """Tokens legítimos: RS*/PS*/EdDSA completos — devem passar SEM nenhum achado.

    Assimétricos de propósito: um HS* bem-formado ainda dispara o aviso
    'alg-hmac-advisory' (LOW), então não serve de negativo limpo.
    """
    base = {"iat": BENCH_NOW, "exp": BENCH_NOW + 3600, "aud": "api", "iss": "https://auth"}
    return [
        {
            "vetor": "RS256 completo",
            "token": _raw({"alg": "RS256", "typ": "JWT"}, {"sub": "u1", **base}),
        },
        {
            "vetor": "PS256 completo",
            "token": _raw({"alg": "PS256", "typ": "JWT"}, {"sub": "u2", **base}),
        },
        {
            "vetor": "EdDSA completo",
            "token": _raw({"alg": "EdDSA", "typ": "JWT"}, {"sub": "u3", **base}),
        },
        {
            "vetor": "RS256 com roles",
            "token": _raw(
                {"alg": "RS256", "typ": "JWT"},
                {"sub": "u4", "roles": ["user"], "scope": "read", **base},
            ),
        },
        {
            "vetor": "RS256 com nbf passado",
            "token": _raw(
                {"alg": "RS256", "typ": "JWT"}, {"sub": "u5", "nbf": BENCH_NOW - 60, **base}
            ),
        },
        {
            "vetor": "ES256 completo",
            "token": _raw({"alg": "ES256", "typ": "JWT"}, {"sub": "u6", **base}),
        },
    ]


def escreve_manifest() -> None:
    manifesto = {
        "now": BENCH_NOW,
        "positivos": [{"vetor": p["vetor"], "esperado": p["esperado"]} for p in positivos()],
        "negativos": [{"vetor": n["vetor"]} for n in negativos()],
    }
    with open(os.path.join(BASE, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifesto, fh, ensure_ascii=False, indent=1)
        fh.write("\n")


def _escreve_tokens(nome: str, itens: list[dict[str, str]]) -> None:
    with open(os.path.join(BASE, nome), "w", encoding="utf-8") as fh:
        for item in itens:
            fh.write(item["token"] + "\n")


def main() -> None:
    _escreve_tokens("positivos.txt", positivos())
    _escreve_tokens("negativos.txt", negativos())
    escreve_manifest()
    print(f"corpus materializado: {len(positivos())} positivos, {len(negativos())} negativos")
    print("agora rode: python bench/avaliar.py")


if __name__ == "__main__":
    main()
