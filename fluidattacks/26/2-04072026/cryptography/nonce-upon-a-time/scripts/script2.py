#!/usr/bin/env python3
import hashlib
import json
import os
import re
import secrets
import sys
from decimal import Decimal, ROUND_HALF_EVEN, getcontext

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from sympy import Matrix, Rational
except Exception as e:
    print("[-] Sympy não está disponível.")
    print("[-] Erro:", repr(e))
    print("[*] Instale com: python3 -m pip install sympy")
    sys.exit(1)


# ============================================================
# Parâmetros NIST P-256 / secp256r1.
# O servidor usa ecdsa.NIST256p.
# ============================================================

P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = P - 3

GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5

ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
G = (GX, GY)

# Bug do servidor:
# random.getrandbits(256) >> 8
# Portanto o nonce k fica limitado a menos de 2^248.
NONCE_BOUND = 1 << 248

# Escala usada no lattice.
# Como ORDER tem cerca de 256 bits e o nonce tem 248 bits,
# multiplicar o erro por 256 equilibra a norma do vetor.
SCALE = 1 << 8


def normalize_target(raw_target):
    raw_target = raw_target.strip().rstrip("/")
    if raw_target.startswith("http://") or raw_target.startswith("https://"):
        return raw_target
    return "https://" + raw_target


def inv_mod(x, m):
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
    Usada para validar se a chave privada recuperada gera a public key do servidor.
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
    Assina localmente com ECDSA depois que recuperamos a chave privada.
    Aqui usamos nonce seguro local, não o nonce bugado do servidor.
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
    Verificação ECDSA local, equivalente à verificação do servidor.
    """
    if not (1 <= r < ORDER and 1 <= s < ORDER):
        return False

    z = int.from_bytes(hashlib.sha256(message_bytes).digest(), "big")
    w = inv_mod(s, ORDER)

    u1 = (z * w) % ORDER
    u2 = (r * w) % ORDER

    point = point_add(point_mul(u1, G), point_mul(u2, public_key))

    return point is not None and point[0] % ORDER == r


def babai_closest_vector(reduced_basis, target, precision=220):
    """
    Babai nearest plane para resolver CVP aproximado após LLL.

    O LLL reduz a base.
    O Babai pega o vetor do lattice mais próximo do alvo centralizado.
    """
    getcontext().prec = precision

    rows = len(reduced_basis)
    cols = len(reduced_basis[0])

    basis_dec = [[Decimal(x) for x in row] for row in reduced_basis]

    b_star = [[Decimal(0) for _ in range(cols)] for _ in range(rows)]
    norms = [Decimal(0) for _ in range(rows)]

    for i in range(rows):
        vector = basis_dec[i].copy()

        for j in range(i):
            if norms[j] == 0:
                continue

            mu = sum(
                basis_dec[i][k] * b_star[j][k]
                for k in range(cols)
            ) / norms[j]

            for k in range(cols):
                vector[k] -= mu * b_star[j][k]

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

        nearest = int(coeff.to_integral_value(rounding=ROUND_HALF_EVEN))

        if nearest:
            for k in range(cols):
                diff[k] -= Decimal(nearest) * basis_dec[i][k]

    closest = [
        int(Decimal(target[i]) - diff[i])
        for i in range(cols)
    ]

    return closest


def recover_private_key(samples, public_key):
    """
    Ataque Hidden Number Problem contra ECDSA com nonce pequeno.

    Para cada assinatura:
      k = (z + r*d) * s^-1 mod n

    Definimos:
      a = r * s^-1 mod n
      b = z * s^-1 mod n

    Então:
      k = a*d + b mod n

    O servidor garante:
      0 < k < 2^248

    Montamos um lattice onde a solução correta é o d que deixa todos
    os k próximos do centro do intervalo pequeno.
    """
    dimension = len(samples)
    transformed = []

    for sample in samples:
        r = sample["r"]
        s = sample["s"]
        z = sample["z"]

        s_inv = inv_mod(s, ORDER)
        a_i = (r * s_inv) % ORDER
        b_i = (z * s_inv) % ORDER

        transformed.append((a_i, b_i))

    basis = []

    # Linhas diagonais: permitem ajustar cada coordenada por múltiplos da ordem n.
    for i in range(dimension):
        row = [0] * (dimension + 1)
        row[i] = ORDER * SCALE
        basis.append(row)

    # Última linha: carrega a incógnita d.
    # Se multiplicarmos essa linha por d, as coordenadas viram a_i*d.
    last_row = []

    for a_i, _ in transformed:
        last_row.append(a_i * SCALE)

    # A última coluna guarda o próprio d.
    last_row.append(1)
    basis.append(last_row)

    # Alvo centralizado:
    # queremos k perto do centro de [0, 2^248), isto é, 2^247.
    # Isso transforma o erro em k - 2^247, bem menor em norma.
    center = NONCE_BOUND // 2

    target = []

    for _, b_i in transformed:
        target.append((center - b_i) * SCALE)

    target.append(0)

    print(f"[*] Rodando LLL em dimensão {dimension + 1}...")

    reduced = Matrix(basis).lll(delta=Rational(99, 100))

    reduced_basis = [
        [int(reduced[i, j]) for j in range(reduced.cols)]
        for i in range(reduced.rows)
    ]

    closest = babai_closest_vector(reduced_basis, target)

    private_key = closest[-1] % ORDER

    recovered_public_key = point_mul(private_key, G)

    if recovered_public_key != public_key:
        return None

    small_count = 0
    recovered_nonces = []

    for sample in samples:
        r = sample["r"]
        s = sample["s"]
        z = sample["z"]

        k_candidate = ((z + r * private_key) * inv_mod(s, ORDER)) % ORDER
        recovered_nonces.append(k_candidate)

        if 0 < k_candidate < NONCE_BOUND:
            small_count += 1

    print(f"[+] Nonces pequenos confirmados: {small_count}/{dimension}")

    if small_count != dimension:
        return None

    return private_key, recovered_nonces


def load_or_collect_samples(base_url, wanted_count):
    """
    Reaproveita loot/signatures.json se já existir.
    Se tiver menos assinaturas do que o necessário, coleta as restantes.
    """
    path = "loot/signatures.json"

    samples = []

    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            samples = json.load(f)

        print(f"[+] Reaproveitando {len(samples)} assinaturas de {path}")

    if len(samples) >= wanted_count:
        return samples[:wanted_count]

    print(f"[*] Coletando mais assinaturas até chegar em {wanted_count}...")

    import time

    start_idx = len(samples)

    for i in range(start_idx, wanted_count):
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
                print("[*] Rate limit. Aguardando 1.2s...")
                time.sleep(1.2)
                continue

            break

        if response.status_code != 200:
            print("[-] Falha ao coletar assinatura.")
            print("[-] Status:", response.status_code)
            print("[-] Corpo:", response.text)
            sys.exit(1)

        data = response.json()

        samples.append(
            {
                "message": data["message"],
                "r": int(data["signature"]["r"], 16),
                "s": int(data["signature"]["s"], 16),
                "z": int(data["hash"], 16),
            }
        )

        print(f"[*] Assinatura coletada {i + 1}/{wanted_count}")

        if (i + 1) % 8 == 0:
            time.sleep(1.05)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(samples, f, indent=2)

    return samples


def main():
    raw_target = os.environ.get("TARGET", "https://101b40dca2b2ccc4.chal.ctf.ae")
    base_url = normalize_target(raw_target)

    os.makedirs("loot", exist_ok=True)

    print("[*] Target:", base_url)
    print("[*] Baixando /api/info...")

    info_response = requests.get(
        base_url + "/api/info",
        timeout=15,
        verify=False,
    )

    if info_response.status_code != 200:
        print("[-] Falha em /api/info.")
        print("[-] Status:", info_response.status_code)
        print("[-] Corpo:", info_response.text)
        sys.exit(1)

    info = info_response.json()

    public_key = (
        int(info["public_key"]["x"], 16),
        int(info["public_key"]["y"], 16),
    )

    print("[+] Public key carregada.")

    wanted_count = int(os.environ.get("SAMPLES", "70"))
    samples = load_or_collect_samples(base_url, wanted_count)

    # Começamos por dimensões menores porque LLL fica mais pesado conforme cresce.
    # Em geral, 40 a 55 assinaturas já bastam para 8 bits vazados.
    dimensions = [35, 40, 45, 50, 55, 60, 65, 70]

    private_key = None
    recovered_nonces = None

    for dimension in dimensions:
        if len(samples) < dimension:
            continue

        print()
        print("=" * 80)
        print(f"[*] Tentando recuperar chave privada com {dimension} assinaturas")
        print("=" * 80)

        result = recover_private_key(samples[:dimension], public_key)

        if result is None:
            print("[-] Não recuperou com essa dimensão.")
            continue

        private_key, recovered_nonces = result
        print("[+] CHAVE PRIVADA RECUPERADA!")
        print("[+] d =", hex(private_key))
        break

    if private_key is None:
        print("[-] Ainda não recuperou a chave.")
        print("[*] Próxima tentativa sugerida:")
        print(f"[*] TARGET={base_url} SAMPLES=90 python3 script2.py")
        sys.exit(1)

    with open("loot/private_key_script2.txt", "w", encoding="utf-8") as f:
        f.write(hex(private_key) + "\n")

    with open("loot/recovered_nonces_script2.txt", "w", encoding="utf-8") as f:
        for k in recovered_nonces:
            f.write(hex(k) + "\n")

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
        print("[-] A assinatura admin falhou na verificação local.")
        sys.exit(1)

    print("[+] Assinatura admin válida localmente.")
    print("[+] r =", hex(r_admin))
    print("[+] s =", hex(s_admin))

    body = {
        "token": admin_token,
        "r": hex(r_admin),
        "s": hex(s_admin),
    }

    with open("loot/admin_activation_payload_script2.json", "w", encoding="utf-8") as f:
        json.dump(body, f, indent=2)

    print()
    print("=" * 80)
    print("[*] Enviando token admin para /api/activate")
    print("=" * 80)

    activation_response = requests.post(
        base_url + "/api/activate",
        json=body,
        timeout=15,
        verify=False,
    )

    print("[*] Status:", activation_response.status_code)
    print("[*] Corpo:")
    print(activation_response.text)

    with open("loot/activation_response_script2.txt", "w", encoding="utf-8") as f:
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
    print("[*] Veja loot/activation_response_script2.txt")


if __name__ == "__main__":
    main()
