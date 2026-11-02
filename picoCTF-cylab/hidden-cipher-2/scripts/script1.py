#!/usr/bin/env python3
# Hidden Cipher 2 — o serviço pede uma conta de aritmética (a operação VARIA
# entre instâncias: +, - ou *), e a RESPOSTA dessa conta é a chave do cipher:
# cada caractere da flag foi codificado como ord(c) * resposta.
# Então eu respondo a conta, leio a lista de valores e divido cada um pela
# resposta para recuperar os bytes da flag.
#
# Uso: TARGET_HOST=host TARGET_PORT=porta python3 scripts/script1.py

import socket, os, re, time

HOST = os.environ.get("TARGET_HOST", "xebec.cylabacademy.net")
PORT = int(os.environ.get("TARGET_PORT", "48109"))

def recv_all(s, wait=0.7):
    time.sleep(wait)
    s.settimeout(3)
    out = b""
    try:
        while True:
            d = s.recv(65535)
            if not d:
                break
            out += d
            if len(d) < 4096:
                break
    except Exception:
        pass
    return out.decode(errors="replace")

s = socket.create_connection((HOST, PORT), timeout=15)

# 1) Lê a pergunta e resolve a conta (operador qualquer).
q = recv_all(s)
print("Pergunta:", q.strip())
a, op, b = re.search(r"(\d+)\s*([*+\-/x])\s*(\d+)", q).groups()
a, b = int(a), int(b)
answer = {"+": a + b, "-": a - b, "*": a * b, "x": a * b, "/": a // b if b else 0}[op]
print("Resposta:", answer)

# 2) Envia a resposta e recebe os valores cifrados.
s.sendall(str(answer).encode() + b"\n")
resp = recv_all(s)

# 3) Cada valor = ord(char) * answer  ->  char = chr(valor // answer).
values = [int(x) for x in re.findall(r"\d+", resp.split("values", 1)[-1])]
flag = "".join(chr(v // answer) for v in values)
print(flag)
s.close()
