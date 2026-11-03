#!/usr/bin/env python3
import hashlib
import json
import os
import random
import re
import secrets
import sys
import time
from decimal import Decimal, ROUND_HALF_EVEN, getcontext

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from sympy import Matrix, Rational
except Exception as e:
    print("[-] O módulo sympy não está disponível.")
    print("[-] Ele é necessário para rodar o LLL neste exploit.")
    print("[-] Erro:", repr(e))
    print("[*] Se precisar instalar depois, use: python3 -m pip install sympy")
    sys.exit(1)


# ============================================================
# Parâmetros oficiais da curva NIST P-256 / secp256r1.
# O servidor usa ecdsa.NIST256p, então estes parâmetros são fixos.
# ============================================================

P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = P - 3
B_CURVE = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5

ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
G = (GX, GY)


# O bug limita k para menos de 2^248.
# Isso significa que os 8 bits mais altos do nonce são sempre zero.
NONCE_BOUND = 1 << 248


def normalize_target(raw_target):
    """
    Aceita TARGET com ou sem esquema.
    Exemplo:
      101b40dca2b2ccc4.chal.ctf.ae
      https://101b40dca2b2ccc4.chal.ctf.ae
    """
    raw_target = raw_target.strip().rstrip("/")
    if raw_target.startswith("http://") or raw_target.startswith("https://"):
        return raw_target
    return "https://" + raw_target


def inv_mod(x, m):
    """Inverso modular usando pow nativo do Python."""
    return pow(x % m, -1, m)


def point_add(p1, p2):
    """
    Soma de pontos em curva elíptica.
    None representa o ponto no infinito.
    """
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and (y1 + y2) % P == 0:
        return None

    if p1 == p2:
        slope = ((3 * x1 * x1 + A) * inv_mod(2 * y1, P)) % P
    else:
        slope = ((y2 - y1) * inv_mod(x2 - x1, P)) % P

    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return (x3, y3)


def point_mul(k, point):
    """
    Multiplicação escalar k * ponto.
    Usada para validar a chave privada recuperada e assinar o token admin.
    """
    result = None
    addend = point

    while k > 0:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1

    return result


def ecdsa_sign(private_key, message_bytes):
    """
    Assinatura ECDSA local.
    Aqui usamos nonce seguro localmente, porque depois que recuperamos a chave
    privada não precisamos repetir o bug do servidor.
    """
    z = int.from_bytes(hashlib.sha256(message_bytes).digest(), "big")

    while True:
        k = secrets.randbelow(ORDER - 1) + 1
        point = point_mul(k, G)
        r = point[0] % ORDER

        if r == 0:
            continue

        s = (inv_mod(k, ORDER) * (z + r * private_key)) % ORDER

        if s == 0:
            continue

        return r, s


def ecdsa_verify(public_key, message_bytes, r, s):
    """
    Verificação ECDSA compatível com a lógica do servidor.
    Usada apenas para checagem local antes de enviar o token admin.
    """
    if not (1 <= r < ORDER and 1 <= s < ORDER):
        return False

    z = int.from_bytes(hashlib.sha256(message_bytes).digest(), "big")
    w = inv_mod(s, ORDER)
    u1 = (z * w) % ORDER
    u2 = (r * w) % ORDER

    point = point_add(point_mul(u1, G), point_mul(u2, public_key))
    return point is not None and point[0] % ORDER == r


def babai_closest_vector(reduced_basis, target, precision=180):
    """
    Babai nearest plane para resolver CVP aproximado depois do LLL.

    O lattice encontra um vetor próximo de:
      (-b1, -b2, ..., -bm)

    A diferença entre esse vetor e o alvo são justamente os nonces pequenos k_i.
    """
    getcontext().prec = precision

    rows = len(reduced_basis)
    cols = len(reduced_basis[0])

    basis_dec = [[Decimal(x) for x in row] for row in reduced_basis]

    # Gram-Schmidt
    b_star = [[Decimal(0) for _ in range(cols)] for _ in range(rows)]
    norms = [Decimal(0) for _ in range(rows)]
    mu = [[Decimal(0) for _ in range(rows)] for _ in range(rows)]

    for i in range(rows):
        vector = basis_dec[i].copy()

        for j in range(i):
            if norms[j] == 0:
                continue

            mu[i][j] = sum(
                basis_dec[i][k] * b_star[j][k]
                for k in range(cols)
            ) / norms[j]

            for k in range(cols):
                vector[k] -= mu[i][j] * b_star[j][k]

        b_star[i] = vector
        norms[i] = sum(vector[k] * vector[k] for k in range(cols))

    diff = [Decimal(x) for x in target]

    for i in range(rows - 1, -1, -1):
        if norms[i] == 0:
            continue

        coeff = sum(
            diff[k] * b_star[i][k]
            for k in range(cols)
        ) / norms[i]

        nearest_int = int(coeff.to_integral_value(rounding=ROUND_HALF_EVEN))

        if nearest_int:
            for k in range(cols):
                diff[k] -= Decimal(nearest_int) * basis_dec[i][k]

    closest = [
        int(Decimal(target[i]) - diff[i])
        for i in range(cols)
    ]

    return closest


def recover_private_key(samples, public_key):
    """
    Recupera a chave privada explorando o fato de que:
      k = (z + r*d) / s mod n

    Reorganizando:
      k = a*d + b mod n

    Como k < 2^248, cada assinatura dá uma desigualdade modular.
    O conjunto dessas desigualdades é resolvido com lattice.
    """
    transformed = []

    for sample in samples:
        r = sample["r"]
        s = sample["s"]
        z = sample["z"]

        s_inv = inv_mod(s, ORDER)
        a_i = (r * s_inv) % ORDER
        b_i = (z * s_inv) % ORDER

        transformed.append((a_i, b_i))

    a0, _ = transformed[0]
    a0_inv = inv_mod(a0, ORDER)

    # Normalização:
    # usamos x = a0*d mod n, então a primeira coordenada do lattice
    # vira diretamente x. Depois recuperamos d = x/a0 mod n.
    coefficients = [1]
    for i in range(1, len(transformed)):
        coefficients.append((transformed[i][0] * a0_inv) % ORDER)

    b_values = [item[1] for item in transformed]

    # Base do lattice:
    # primeira linha: relação entre todas as assinaturas
    # demais linhas: múltiplos da ordem da curva
    basis = [coefficients]

    for i in range(1, len(transformed)):
        row = [0] * len(transformed)
        row[i] = ORDER
        basis.append(row)

    print(f"[*] Rodando LLL em dimensão {len(transformed)}...")

    reduced = Matrix(basis).lll(delta=Rational(3, 4))
    reduced_basis = [
        [int(reduced[i, j]) for j in range(reduced.cols)]
        for i in range(reduced.rows)
    ]

    target = [-b for b in b_values]
    closest = babai_closest_vector(reduced_basis, target)

    x = closest[0] % ORDER
    private_key = (x * a0_inv) % ORDER

    # Validação forte:
    # a chave privada correta precisa gerar exatamente a public key do servidor.
    recovered_public_key = point_mul(private_key, G)

    if recovered_public_key != public_key:
        return None

    # Validação adicional:
    # com a chave correta, todos os k_i calculados devem cair no intervalo pequeno.
    small_count = 0

    for sample in samples:
        r = sample["r"]
        s = sample["s"]
        z = sample["z"]

        k_candidate = ((z + r * private_key) * inv_mod(s, ORDER)) % ORDER

        if 0 < k_candidate < NONCE_BOUND:
            small_count += 1

    print(f"[+] Nonces pequenos confirmados: {small_count}/{len(samples)}")

    if small_count < len(samples) * 0.85:
        return None

    return private_key


def collect_signatures(base_url, count):
    """
    Coleta assinaturas de tokens normais.
    O endpoint bloqueia somente type=admin.
    Tokens standard são assinados livremente.
    """
    samples = []

    for i in range(count):
        message = json.dumps(
            {
                "user": "guerreiro",
                "type": "standard",
                "idx": i,
                "tag": secrets.token_hex(8),
            },
            sort_keys=True,
            separators=(",", ":"),
        )

        while True:
            response = requests.post(
                base_url + "/api/sign",
                json={"message": message},
                timeout=15,
                verify=False,
            )

            if response.status_code == 429:
                print("[*] Rate limit recebido. Aguardando 1.2s...")
                time.sleep(1.2)
                continue

            break

        if response.status_code != 200:
            print("[-] Falha ao coletar assinatura.")
            print("[-] Status:", response.status_code)
            print("[-] Corpo:", response.text)
            sys.exit(1)

        data = response.json()

        r = int(data["signature"]["r"], 16)
        s = int(data["signature"]["s"], 16)
        z = int(data["hash"], 16)

        samples.append(
            {
                "message": message,
                "r": r,
                "s": s,
                "z": z,
            }
        )

        print(f"[*] Assinatura coletada {i + 1}/{count}")

        # O servidor permite 10 req/s. Mantemos margem para não perder tempo com 429.
        if (i + 1) % 8 == 0:
            time.sleep(1.05)

    return samples


def main():
    raw_target = os.environ.get("TARGET", "https://101b40dca2b2ccc4.chal.ctf.ae")
    base_url = normalize_target(raw_target)

    os.makedirs("loot", exist_ok=True)

    print("[*] Target:", base_url)
    print("[*] Buscando informações públicas da curva e chave pública...")

    info_response = requests.get(
        base_url + "/api/info",
        timeout=15,
        verify=False,
    )

    if info_response.status_code != 200:
        print("[-] /api/info falhou.")
        print("[-] Status:", info_response.status_code)
        print("[-] Corpo:", info_response.text)
        sys.exit(1)

    info = info_response.json()

    with open("loot/api_info.json", "w", encoding="utf-8") as f:
        json.dump(info, f, indent=2)

    server_order = int(info["order"], 16)
    if server_order != ORDER:
        print("[-] Ordem da curva inesperada.")
        print("[-] Server:", hex(server_order))
        print("[-] Local :", hex(ORDER))
        sys.exit(1)

    public_key = (
        int(info["public_key"]["x"], 16),
        int(info["public_key"]["y"], 16),
    )

    print("[+] Public key carregada.")

    sample_count = int(os.environ.get("SAMPLES", "70"))
    samples = collect_signatures(base_url, sample_count)

    with open("loot/signatures.json", "w", encoding="utf-8") as f:
        json.dump(samples, f, indent=2)

    print("[+] Assinaturas salvas em loot/signatures.json")

    # Testamos dimensões progressivas.
    # 8 bits de vazamento normalmente exigem algo na faixa de 45 a 60 assinaturas.
    private_key = None

    for dimension in [45, 50, 55, 60, 65, 70]:
        if len(samples) < dimension:
            continue

        print()
        print("=" * 80)
        print(f"[*] Tentando recuperar chave privada com {dimension} assinaturas")
        print("=" * 80)

        candidate = recover_private_key(samples[:dimension], public_key)

        if candidate is not None:
            private_key = candidate
            print("[+] CHAVE PRIVADA RECUPERADA!")
            print("[+] d =", hex(private_key))
            break

        print("[-] Essa dimensão não recuperou a chave.")

    if private_key is None:
        print("[-] Não foi possível recuperar a chave privada nesta execução.")
        print("[*] Tente rodar novamente com mais assinaturas, por exemplo:")
        print("[*] TARGET=" + base_url + " SAMPLES=90 python3 script1.py")
        sys.exit(1)

    with open("loot/private_key.txt", "w", encoding="utf-8") as f:
        f.write(hex(private_key) + "\n")

    admin_token = json.dumps(
        {
            "user": "guerreiro",
            "type": "admin",
        },
        sort_keys=True,
        separators=(",", ":"),
    )

    print()
    print("=" * 80)
    print("[*] Token admin")
    print("=" * 80)
    print(admin_token)

    r_admin, s_admin = ecdsa_sign(private_key, admin_token.encode("utf-8"))

    if not ecdsa_verify(public_key, admin_token.encode("utf-8"), r_admin, s_admin):
        print("[-] Assinatura admin falhou na verificação local.")
        sys.exit(1)

    print("[+] Assinatura admin válida localmente.")
    print("[+] r =", hex(r_admin))
    print("[+] s =", hex(s_admin))

    activation_body = {
        "token": admin_token,
        "r": hex(r_admin),
        "s": hex(s_admin),
    }

    with open("loot/admin_activation_payload.json", "w", encoding="utf-8") as f:
        json.dump(activation_body, f, indent=2)

    print()
    print("=" * 80)
    print("[*] Enviando token admin para /api/activate")
    print("=" * 80)

    activation_response = requests.post(
        base_url + "/api/activate",
        json=activation_body,
        timeout=15,
        verify=False,
    )

    print("[*] Status:", activation_response.status_code)
    print("[*] Corpo:")
    print(activation_response.text)

    with open("loot/activation_response.txt", "w", encoding="utf-8") as f:
        f.write(activation_response.text + "\n")

    match = re.search(r"flag\{[^}\r\n]+\}", activation_response.text, re.IGNORECASE)

    if match:
        flag = match.group(0)
        print()
        print("=" * 80)
        print("[+] FLAG ENCONTRADA")
        print("=" * 80)
        print(flag)

        with open("flag.txt", "w", encoding="utf-8") as f:
            f.write(flag + "\n")

        print("[+] Flag salva em flag.txt")
        return

    print("[-] Flag não encontrada automaticamente.")
    print("[*] Verifique loot/activation_response.txt")


if __name__ == "__main__":
    main()
