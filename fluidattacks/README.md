# Fluid Attacks CTF

Writeups dos desafios que resolvi no campeonato da Fluid Attacks, organizados por edição e categoria.

## 26 / etapa 2 (04/07/2026)

Pasta: [`26/2-04072026/`](26/2-04072026/)

| Categoria | Desafio | Técnica | Link |
|---|---|---|---|
| Cryptography | Crumble Cookie | length extension em `SHA256(secret‖msg)` | [writeup](26/2-04072026/cryptography/crumble-cookie/README.md) |
| Cryptography | Nonce Upon a Time | ECDSA com nonce enviesado (HNP + LLL) | [writeup](26/2-04072026/cryptography/nonce-upon-a-time/README.md) |
| Cryptography | Phantom Decrypt | fallback inseguro de AES-GCM (fail-open) | [writeup](26/2-04072026/cryptography/phantom-decrypt/README.md) |
| API | Coupon Collector | coupon stacking por normalização de case | [writeup](26/2-04072026/api/coupon-collector/README.md) |
| API | Ni8mare Lite | leak + XOR por timestamp + JWT + sandbox escape | [writeup](26/2-04072026/api/ni8mare-lite/README.md) |
| API | Read Between the Lines | path traversal `....//` em gateway/proxy | [writeup](26/2-04072026/api/read-between-the-lines/README.md) |
| Mobile | Deadbolt | chave de cofre derivada de constantes do APK | [writeup](26/2-04072026/mobile/deadbolt/README.md) |
| Mobile | Glass Houses | WebView `addJavascriptInterface` vaza token | [writeup](26/2-04072026/mobile/glass-houses/README.md) |
| Mobile | Phantom Thread | intent redirection (confused deputy) | [writeup](26/2-04072026/mobile/phantom-thread/README.md) |
| Mobile | Whispers in the Wire | endpoint admin oculto + API key compartilhada | [writeup](26/2-04072026/mobile/whispers-in-the-wire/README.md) |
| Pwn | Canary Wharf | format string (leak canary+libc) + ret2libc | [writeup](26/2-04072026/pwn/canary-wharf/README.md) |
| Pwn | The Password Is Swordfish | bug signed/unsigned + ret2win | [writeup](26/2-04072026/pwn/the-password-is-swordfish/README.md) |
| Web | Crosstalk | template injection + broadcast ignora filtro | [writeup](26/2-04072026/web/crosstalk/README.md) |
| Web | Mise en Place | IDOR/BOLA em `/profile/<uuid>` | [writeup](26/2-04072026/web/mise-en-place/README.md) |
| Web | Overqualified | mass assignment (`is_staff=true`) | [writeup](26/2-04072026/web/overqualified/README.md) |
| Web | SELEC isn't a Choice | SQLi via Django `_connector` (CVE-2025-64459) | [writeup](26/2-04072026/web/selec-isnt-a-choice/README.md) |
| Web | Withdraw Under Pressure | abuso de bônus de cadastro (multi-conta) | [writeup](26/2-04072026/web/withdraw-under-pressure/README.md) |
| Web | YAML Ain't Safe | desserialização insegura de YAML (RCE) | [writeup](26/2-04072026/web/yaml/README.md) |
