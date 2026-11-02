#!/usr/bin/env python3
# Recupera a senha do gogo (enter_password) a partir do que o disassembly
# de main.checkPassword revela:
#   checkPassword faz, para i em 0..31:  input[i] XOR key[i] == cmp[i]
#   logo:  senha[i] = key[i] XOR cmp[i]
#
# - key: os 8 imediatos MOVL de 32 bits escritos no buffer (decodificados LE).
# - cmp: os 32 bytes de main.statictmp_4, lidos da seção .rodata do binário.
#
# Uso: python3 script1.py ./enter_password

import struct, subprocess, sys

binpath = sys.argv[1] if len(sys.argv) > 1 else "./enter_password"

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
print("key  =", key.decode())
print("senha=", password.decode())
