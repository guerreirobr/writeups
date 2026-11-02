#!/usr/bin/env python3
# Solve do gogo (enter_password): DOIS estágios.
#
# Estágio 1 (main.checkPassword): para i em 0..31,  input[i] XOR key[i] == cmp[i]
#   logo:  senha[i] = key[i] XOR cmp[i]
#   - key: os 8 imediatos MOVL de 32 bits escritos no buffer (decodificados LE)
#          = a string ASCII "861836f13e3d627dfa375bdb8389214e".
#   - cmp: os 32 bytes de main.statictmp_4, lidos da seção .rodata do binário.
#
# Estágio 2 (main.ambush): le uma segunda entrada e exige
#   md5(input2) == "861836f13e3d627dfa375bdb8389214e"  (o MESMO valor do estágio 1,
#   que na verdade é um hash MD5). Errar chama os.Exit. Quebrando o MD5 -> "goldfish".
#
# Uso: python3 script1.py ./enter_password [wordlist]

import struct, subprocess, sys, hashlib

binpath  = sys.argv[1] if len(sys.argv) > 1 else "./enter_password"
wordlist = sys.argv[2] if len(sys.argv) > 2 else "/usr/share/wordlists/rockyou.txt"

# ---- Estágio 1: recuperar a senha ----
# Os 8 dwords imediatos de checkPassword, na ordem em que são escritos.
KEY_DWORDS = [0x38313638, 0x31663633, 0x64336533, 0x64373236,
              0x37336166, 0x62646235, 0x39383338, 0x65343132]
key = b"".join(struct.pack("<I", d) for d in KEY_DWORDS)   # 32 bytes ASCII

# Endereço do símbolo main.statictmp_4 (tabela de símbolos do ELF).
syms = subprocess.run(["objdump", "-t", binpath], capture_output=True, text=True).stdout
addr = next(int(l.split()[0], 16) for l in syms.splitlines()
            if l.strip().endswith("main.statictmp_4"))

# Dump dos 32 bytes a partir desse endereço.
dump = subprocess.run(
    ["objdump", "-s", "--start-address", hex(addr), "--stop-address", hex(addr + 32), binpath],
    capture_output=True, text=True).stdout
cmp_bytes = b""
for line in dump.splitlines():
    cols = line.split()
    if len(cols) >= 2 and all(c in "0123456789abcdef" for c in cols[0]):
        for grp in cols[1:5]:
            if all(c in "0123456789abcdef" for c in grp):
                cmp_bytes += bytes.fromhex(grp)
cmp_bytes = cmp_bytes[:32]

password = bytes(k ^ c for k, c in zip(key, cmp_bytes))
print("estagio 1 (senha) =", password.decode())

# ---- Estágio 2: quebrar o MD5 ----
target = key.decode()   # "861836f13e3d627dfa375bdb8389214e" é um hash MD5
unhashed = None
try:
    with open(wordlist, "rb") as f:
        for line in f:
            w = line.rstrip(b"\n")
            if hashlib.md5(w).hexdigest() == target:
                unhashed = w.decode(errors="replace")
                break
except FileNotFoundError:
    print(f"[!] wordlist {wordlist} nao encontrada")
print("estagio 2 (unhashed key) =", unhashed or "(nao quebrado nesta wordlist)")
