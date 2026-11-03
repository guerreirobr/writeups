#!/usr/bin/env python3
import json
import re
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Constantes copiadas diretamente do CryptoManager.java.
SEED = "fluidvault_master_seed_2026"
SALT = bytes.fromhex("a915c3e00dbb5a55ba13d7cdaf3a126e")
ITERATIONS = 10000
KEY_LENGTH_BYTES = 32
IV_LENGTH = 12

BACKUP_PATH = Path("extracted/vault_backup.enc")
LOOT_DIR = Path("loot")


def java_string_hashcode(value: str) -> int:
    """
    Reimplementa String.hashCode() do Java.

    Fórmula Java:
        h = 31 * h + char

    O resultado é um inteiro assinado de 32 bits.
    """
    h = 0

    for ch in value:
        h = (31 * h + ord(ch)) & 0xFFFFFFFF

    # Converte para assinado, igual ao int do Java.
    if h & 0x80000000:
        h -= 0x100000000

    return h


def java_integer_to_hex_string(value: int) -> str:
    """
    Reimplementa Integer.toHexString(int) do Java.

    Para valores negativos, Java imprime o valor em complemento de dois
    como hexadecimal unsigned de 32 bits.
    """
    return format(value & 0xFFFFFFFF, "x")


def get_device_identifier(serial):
    """
    Reimplementa getDeviceIdentifier() do CryptoManager.java.

    Se Build.SERIAL for null ou "unknown", o app usa DEFAULT_DEVICE_ID.
    Depois calcula hashCode() e converte para hex.
    """
    if serial is None or serial == "unknown":
        serial = "DEFAULT_DEVICE_ID"

    java_hash = java_string_hashcode(serial)
    device_id = java_integer_to_hex_string(java_hash)

    return serial, java_hash, device_id


def derive_key(device_id: str) -> bytes:
    """
    Reimplementa PBKDF2WithHmacSHA256 usado pelo app.

    passphrase = SEED + deviceId
    salt = SALT hardcoded
    iterations = 10000
    key = 32 bytes para AES-256
    """
    passphrase = (SEED + device_id).encode("utf-8")

    return hashlib.pbkdf2_hmac(
        "sha256",
        passphrase,
        SALT,
        ITERATIONS,
        dklen=KEY_LENGTH_BYTES,
    )


def decrypt_backup(key: bytes, blob: bytes) -> bytes:
    """
    O vault_decrypt.py informa o layout:

        [ 12-byte IV ][ ciphertext ][ 16-byte GCM tag ]

    A biblioteca AESGCM espera ciphertext || tag junto.
    """
    iv = blob[:IV_LENGTH]
    ciphertext_and_tag = blob[IV_LENGTH:]

    return AESGCM(key).decrypt(iv, ciphertext_and_tag, None)


def main():
    LOOT_DIR.mkdir(exist_ok=True)

    if not BACKUP_PATH.exists():
        print(f"[-] Arquivo não encontrado: {BACKUP_PATH}")
        return 1

    blob = BACKUP_PATH.read_bytes()

    print("[*] Backup:", BACKUP_PATH)
    print("[*] Tamanho do backup:", len(blob), "bytes")

    # Candidatos coerentes com o código Java.
    # None e "unknown" ativam o fallback DEFAULT_DEVICE_ID.
    serial_candidates = [
        None,
        "unknown",
        "DEFAULT_DEVICE_ID",
    ]

    for serial_candidate in serial_candidates:
        real_serial, java_hash, device_id = get_device_identifier(serial_candidate)
        key = derive_key(device_id)

        print()
        print("=" * 80)
        print("[*] Testando candidato")
        print("=" * 80)
        print("[*] Build.SERIAL candidato:", repr(serial_candidate))
        print("[*] Serial usado pelo app:", real_serial)
        print("[*] Java hashCode:", java_hash)
        print("[*] Device ID hex:", device_id)
        print("[*] AES key hex:", key.hex())

        try:
            plaintext = decrypt_backup(key, blob)
        except Exception as exc:
            print("[-] Falhou:", type(exc).__name__)
            continue

        print()
        print("=" * 80)
        print("[+] DECRIPTAÇÃO OK")
        print("=" * 80)

        text = plaintext.decode("utf-8", errors="replace")
        print(text)

        Path("loot/script1_key.txt").write_text(key.hex() + "\n", encoding="utf-8")
        Path("loot/script1_plaintext.txt").write_text(text, encoding="utf-8")

        # Se for JSON, salva também formatado para leitura.
        try:
            parsed = json.loads(text)
            Path("loot/script1_plaintext.json").write_text(
                json.dumps(parsed, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
        except Exception:
            pass

        flags = re.findall(r"flag\{[^}\r\n]+\}", text, re.IGNORECASE)

        if flags:
            print()
            print("=" * 80)
            print("[+] FLAG ENCONTRADA")
            print("=" * 80)

            for flag in flags:
                print(flag)

            Path("flag.txt").write_text(flags[0] + "\n", encoding="utf-8")
            print("[+] Primeira flag salva em flag.txt")
        else:
            print("[!] Decriptou, mas não achei flag automaticamente.")
            print("[*] Revise loot/script1_plaintext.txt")

        return 0

    print()
    print("=" * 80)
    print("[-] Nenhum candidato funcionou")
    print("=" * 80)
    print("[*] Próximo passo: analisar LoginActivity, VaultApiClient e ContentProvider.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
