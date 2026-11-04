#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Enumeração inicial da API Coupon Collector.

Objetivo:
1. Manter uma sessão HTTP com cookies.
2. Testar formatos comuns para adicionar produto no carrinho.
3. Mostrar qual payload é aceito pela API.
4. Consultar o carrinho depois de cada tentativa.

Não estamos explorando ainda.
Estamos descobrindo o contrato real da API.
"""

import json
import urllib.request
import urllib.error
import http.cookiejar


TARGET = "https://d1986f8c1c794d65.chal.ctf.ae"


# CookieJar mantém automaticamente o cookie de sessão entre as requisições.
cookie_jar = http.cookiejar.CookieJar()

opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(cookie_jar)
)


def request(method, path, body=None):
    """
    Envia uma requisição HTTP para a API.

    method: GET, POST, PUT etc.
    path: endpoint da API, por exemplo /api/cart.
    body: dicionário Python que será enviado como JSON.
    """

    url = TARGET + path

    data = None
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "ctf-api-tester/1.0",
    }

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


def print_response(title, status, body):
    """
    Imprime a resposta de forma organizada.
    """
    print()
    print("=" * 80)
    print(title)
    print("=" * 80)
    print(f"HTTP STATUS: {status}")
    print(body)


def main():
    # Primeiro inicializamos a sessão acessando produtos e carrinho.
    status, body = request("GET", "/api/products")
    print_response("GET /api/products", status, body)

    status, body = request("GET", "/api/cart")
    print_response("GET /api/cart inicial", status, body)

    # Testes de formatos comuns para adicionar item.
    # Produto escolhido: id 3, Mechanical Keyboard, o mais caro da loja.
    candidates = [
        {
            "method": "POST",
            "path": "/api/cart",
            "body": {"product_id": 3, "quantity": 1},
        },
        {
            "method": "POST",
            "path": "/api/cart",
            "body": {"id": 3, "quantity": 1},
        },
        {
            "method": "POST",
            "path": "/api/cart",
            "body": {"productId": 3, "quantity": 1},
        },
        {
            "method": "POST",
            "path": "/api/cart",
            "body": {"product_id": 3, "qty": 1},
        },
        {
            "method": "POST",
            "path": "/api/cart",
            "body": {"product": 3, "quantity": 1},
        },
        {
            "method": "PUT",
            "path": "/api/cart",
            "body": {"product_id": 3, "quantity": 1},
        },
    ]

    for index, candidate in enumerate(candidates, start=1):
        title = (
            f"TENTATIVA {index}: "
            f"{candidate['method']} {candidate['path']} "
            f"{candidate['body']}"
        )

        status, body = request(
            candidate["method"],
            candidate["path"],
            candidate["body"],
        )
        print_response(title, status, body)

        # Depois de cada tentativa, consultamos o carrinho para ver se mudou.
        status, body = request("GET", "/api/cart")
        print_response(f"GET /api/cart depois da tentativa {index}", status, body)

    # Também testamos o endpoint de cupom sem assumir ainda o formato certo.
    coupon_candidates = [
        {"coupon": "WELCOME20"},
        {"code": "WELCOME20"},
        {"coupon_code": "WELCOME20"},
        {"promo": "WELCOME20"},
    ]

    for index, payload in enumerate(coupon_candidates, start=1):
        status, body = request("POST", "/api/apply-coupon", payload)
        print_response(
            f"TENTATIVA CUPOM {index}: POST /api/apply-coupon {payload}",
            status,
            body,
        )

        status, body = request("GET", "/api/cart")
        print_response(f"GET /api/cart depois do cupom {index}", status, body)


if __name__ == "__main__":
    main()
