# writeups

Writeups de CTF em português do Brasil, escritos para **reproduzir**, **entender** e **aprender**. O padrão segue a skill [`ctf-writeup`](https://github.com/guerreirobr/skills/tree/main/ctf-writeup).

| Plataforma | Desafio | Categoria | Técnica | Link |
|---|---|---|---|---|
| picoCTF 2026 | Absolute Nano | General Skills | privesc via sudo: `nano /etc/sudoers` | [writeup](picoCTF-cylab/absolute-nano/README.md) |
| picoCTF 2026 | Credential Stuffing | Web | credential stuffing automatizado em dump vazado | [writeup](picoCTF-cylab/credential-stuffing/README.md) |
| picoCTF 2026 | Hashgate | Web | IDOR com ID sequencial hasheado em MD5 | [writeup](picoCTF-cylab/hashgate/README.md) |
| picoCTF 2026 | Hidden Cipher 2 | Reverse | cipher multiplicativo (`valor / resposta`) | [writeup](picoCTF-cylab/hidden-cipher-2/README.md) |
| picoCTF 2026 | Secret Box | Web | SQL injection em query concatenada (PostgreSQL) | [writeup](picoCTF-cylab/secret-box/README.md) |
| picoCTF 2021 | gogo | Reverse | binário Go 2 estágios: XOR em `checkPassword` + quebra de MD5 em `ambush` | [writeup](picoCTF-cylab/gogo/README.md) |
| picoCTF 2021 | Here's a LIBC | Pwn | ret2libc com leak de `puts` (glibc 2.27) | [writeup](picoCTF-cylab/heres-a-libc/README.md) |
| picoCTF 2021 | The Office | Pwn | heap overflow + canário previsível (`srand(time)`) | [writeup](picoCTF-cylab/the-office/README.md) |
| picoCTF 2021 | Turboflan | Pwn | V8 TurboFan: `CheckMaps` removido → type confusion | [writeup](picoCTF-cylab/turboflan/README.md) |
| Fluid Attacks 26/2 | Crumble Cookie | Cryptography | length extension em `SHA256(secret‖msg)` | [writeup](fluidattacks/26/2-04072026/cryptography/crumble-cookie/README.md) |
| Fluid Attacks 26/2 | Nonce Upon a Time | Cryptography | ECDSA com nonce enviesado (HNP + LLL) | [writeup](fluidattacks/26/2-04072026/cryptography/nonce-upon-a-time/README.md) |
| Fluid Attacks 26/2 | Phantom Decrypt | Cryptography | fallback inseguro de AES-GCM (fail-open) | [writeup](fluidattacks/26/2-04072026/cryptography/phantom-decrypt/README.md) |
| Fluid Attacks 26/2 | Coupon Collector | API | coupon stacking por normalização de case | [writeup](fluidattacks/26/2-04072026/api/coupon-collector/README.md) |
| Fluid Attacks 26/2 | Ni8mare Lite | API | leak + XOR por timestamp + JWT + sandbox escape | [writeup](fluidattacks/26/2-04072026/api/ni8mare-lite/README.md) |
| Fluid Attacks 26/2 | Read Between the Lines | API | path traversal `....//` em gateway/proxy | [writeup](fluidattacks/26/2-04072026/api/read-between-the-lines/README.md) |
| Fluid Attacks 26/2 | Deadbolt | Mobile | chave de cofre derivada de constantes do APK | [writeup](fluidattacks/26/2-04072026/mobile/deadbolt/README.md) |
| Fluid Attacks 26/2 | Glass Houses | Mobile | WebView `addJavascriptInterface` vaza token | [writeup](fluidattacks/26/2-04072026/mobile/glass-houses/README.md) |
| Fluid Attacks 26/2 | Phantom Thread | Mobile | intent redirection (confused deputy) | [writeup](fluidattacks/26/2-04072026/mobile/phantom-thread/README.md) |
| Fluid Attacks 26/2 | Whispers in the Wire | Mobile | endpoint admin oculto + API key compartilhada | [writeup](fluidattacks/26/2-04072026/mobile/whispers-in-the-wire/README.md) |
| Fluid Attacks 26/2 | Canary Wharf | Pwn | format string (leak canary+libc) + ret2libc | [writeup](fluidattacks/26/2-04072026/pwn/canary-wharf/README.md) |
| Fluid Attacks 26/2 | The Password Is Swordfish | Pwn | bug signed/unsigned + ret2win | [writeup](fluidattacks/26/2-04072026/pwn/the-password-is-swordfish/README.md) |
| Fluid Attacks 26/2 | Crosstalk | Web | template injection + broadcast ignora filtro | [writeup](fluidattacks/26/2-04072026/web/crosstalk/README.md) |
| Fluid Attacks 26/2 | Mise en Place | Web | IDOR/BOLA em `/profile/<uuid>` | [writeup](fluidattacks/26/2-04072026/web/mise-en-place/README.md) |
| Fluid Attacks 26/2 | Overqualified | Web | mass assignment (`is_staff=true`) | [writeup](fluidattacks/26/2-04072026/web/overqualified/README.md) |
| Fluid Attacks 26/2 | SELEC isn't a Choice | Web | SQLi via Django `_connector` (CVE-2025-64459) | [writeup](fluidattacks/26/2-04072026/web/selec-isnt-a-choice/README.md) |
| Fluid Attacks 26/2 | Withdraw Under Pressure | Web | abuso de bônus de cadastro (multi-conta) | [writeup](fluidattacks/26/2-04072026/web/withdraw-under-pressure/README.md) |
| Fluid Attacks 26/2 | YAML Ain't Safe | Web | desserialização insegura de YAML (RCE) | [writeup](fluidattacks/26/2-04072026/web/yaml/README.md) |
