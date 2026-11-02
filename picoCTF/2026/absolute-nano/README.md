# Absolute Nano | picoCTF 2026

## 1. Identificação e status

**Nome:** Absolute Nano  
**Plataforma / edição:** picoCTF 2026  
**Categoria:** General Skills  
**Dificuldade:** Medium  
**Pontuação informada:** 200 pts  
**Solves observados no enunciado fornecido:** 2.893  
**Autor do desafio:** Darkraicg492  
**Resolução:** Resolvido  
**Reprodução:** Não reexecutada nesta revisão. A solução está sustentada pelo transcript da sessão.  
**Publicação:** Este arquivo está armazenado no repositório privado `guerreirobr/writeups`. A publicação pública permanece uma etapa separada.  
**Data da documentação e revisão:** 01/11/2026

A conversa em que a solução foi registrada ocorreu em 01/11/2026, enquanto o arquivo de terminal contém timestamps de 18/05/2026. A divergência é preservada como parte da proveniência e sua causa não foi estabelecida. Ela não altera a cadeia técnica observada.

### Resumo

O usuário `ctf-player` conseguia acessar a instância por SSH, mas não podia ler `flag.txt`. A enumeração de privilégios mostrou uma regra `sudo` que autorizava exatamente `/bin/nano /etc/sudoers` sem senha. Como o arquivo autorizado era a própria política do sudo, o Nano executado com privilégios elevados conseguiu regravar a regra, ampliando a autorização. Depois disso, `sudo cat` leu a flag protegida.

### English abstract

Absolute Nano is a short Linux privilege escalation challenge from picoCTF 2026. The recorded session shows that the unprivileged `ctf-player` account could not read `flag.txt`, but `sudo -l` allowed Nano to edit `/etc/sudoers` without a password. By modifying the authorization rule, the user gained permission to execute other commands through sudo and then read the protected flag. The central lesson is that a narrowly written sudo rule can still grant full privilege escalation when it allows privileged modification of the authorization policy itself.

**Palavras-chave:** picoCTF, Linux, sudo, sudoers, Nano, privilege escalation, General Skills

> **Aviso de spoilers:** as próximas seções contêm a resolução completa e a flag observada na sessão.

## 2. Enunciado, dica e escopo

### Enunciado original fornecido

```text
You have complete power with nano.

Think you can get the flag?
```

### Hint original fornecida

```text
What can you do with nano?
```

A instância disponibilizada pelo desafio era temporária. Na sessão registrada, o acesso ocorreu pelo host `crystal-peak.picoctf.net`, porta `55591`, com o usuário `ctf-player`. A senha da instância não aparece no transcript porque a entrada do prompt SSH não foi capturada.

O endpoint e a porta devem ser tratados como dados históricos da sessão. Uma reprodução futura deve usar os valores fornecidos pela nova instância do picoCTF.

## 3. Ambiente, pré-requisitos e parâmetros

A máquina atacante registrada no log era um Kali Linux, no diretório `~/ctf/picoctf/absolute-nano`. O alvo apresentou Ubuntu 20.04.3 LTS após o login SSH.

Para uma nova reprodução, é recomendável iniciar o registro antes da conexão.

***INSERIR esse comando no terminal

```bash
script -a sessao-terminal-absolute-nano.log
```

O comando `script -a` grava a sessão de terminal e acrescenta conteúdo ao arquivo caso ele já exista. Ao final da reprodução, `exit` encerra a gravação.

Na sessão histórica, a conexão foi feita assim:

***INSERIR esse comando no terminal

```bash
ssh -p 55591 ctf-player@crystal-peak.picoctf.net
```

O parâmetro `-p 55591` seleciona a porta SSH não padrão. Em uma nova instância, substitua host e porta pelos valores atuais fornecidos pelo desafio.

## 4. Visão da cadeia técnica

A cadeia observada foi curta e linear. Primeiro, `flag.txt` foi localizado, mas a leitura direta falhou. Em seguida, `sudo -l` revelou que o usuário podia abrir `/etc/sudoers` com Nano como usuário privilegiado e sem senha. O arquivo de política foi então editado para ampliar a regra de `ctf-player`. Por fim, um comando que não era autorizado originalmente, `sudo cat`, conseguiu ler a flag.

A hipótese inicial de simplesmente abrir `flag.txt` no Nano foi descartada pelo próprio erro de permissão. A evidência direcionou a investigação para a configuração de sudo.

## 5. Enumeração e exploração

### 5.1. Confirmando o arquivo protegido

**Objetivo e motivo:** verificar se a flag estava presente no diretório e determinar se o problema era realmente uma restrição de leitura do usuário atual.

**Contexto:** shell do alvo, usuário `ctf-player`, diretório pessoal `~`.

**Execução observada:**

***INSERIR esse comando no terminal

```bash
ls
```

**Resultado observado:**

```text
flag.txt
```

**Evidência:** E01, `sessao-absolute-nano(1).md`, linhas 41 a 42.

**Interpretação:** o arquivo existia no diretório pessoal. Isso ainda não dizia se o conteúdo podia ser lido.

A leitura direta foi testada em seguida.

***INSERIR esse comando no terminal

```bash
cat flag.txt
```

**Resultado observado:**

```text
cat: flag.txt: Permission denied
```

**Evidência:** E01, linhas 43 a 44.

**Interpretação:** a existência do arquivo estava confirmada, mas o usuário atual não possuía permissão suficiente para lê-lo por meio do `cat`.

Como o enunciado destacava o Nano, também foi testada a abertura direta pelo editor.

***INSERIR esse comando no terminal

```bash
nano flag.txt
```

**Resultado observado:**

```text
[ Error reading flag.txt: Permission denied ]
```

**Evidência:** E01, linhas 45 a 48.

**Interpretação:** executar Nano como o próprio `ctf-player` não contornava as permissões do arquivo. O teste negativo descartou a hipótese de que o editor, sozinho e sem elevação, pudesse ler a flag.

**Conclusão e próximo passo:** era necessário procurar uma forma de executar o Nano ou outro recurso com privilégios maiores. A próxima verificação lógica era enumerar as permissões de sudo.

### 5.2. Enumerando as permissões de sudo

**Objetivo e motivo:** descobrir exatamente quais comandos o usuário podia executar por meio do `sudo` e em qual contexto de privilégio.

**Contexto:** shell do alvo, usuário `ctf-player`.

**Execução observada:**

***INSERIR esse comando no terminal

```bash
sudo -l
```

**Resultado observado:**

```text
User ctf-player may run the following commands on challenge:
    (ALL) NOPASSWD: /bin/nano /etc/sudoers
```

**Evidência:** E02, `sessao-absolute-nano(1).md`, linhas 50 a 56.

**Interpretação:** a regra não autorizava Nano com argumentos arbitrários. Ela permitia uma invocação específica, `/bin/nano /etc/sudoers`, sem solicitar senha. O detalhe crítico era o objeto permitido: `/etc/sudoers` define a própria política utilizada pelo sudo para decidir quais comandos cada usuário pode executar.

Portanto, a regra concedia ao usuário uma primitiva de escrita privilegiada sobre o mecanismo que limitava seus próprios privilégios.

**Conclusão e próximo passo:** a hipótese de má configuração de sudo foi confirmada. O próximo passo era executar exatamente a invocação autorizada e observar se o arquivo podia ser modificado e salvo.

### 5.3. Editando a política de autorização

**Objetivo e motivo:** usar a permissão observada para alterar somente a regra de `ctf-player` e verificar se o arquivo de política podia realmente ser regravado.

**Contexto:** shell do alvo. O comando é iniciado por `ctf-player`, mas o Nano é aberto pelo sudo com privilégios suficientes para acessar `/etc/sudoers`.

**Execução observada:**

***INSERIR esse comando no terminal

```bash
sudo /bin/nano /etc/sudoers
```

**Resultado observado no editor:**

```text
ctf-player ALL=(ALL) NOPASSWD: /bin/nano /etc/sudoers
```

**Evidência:** E03, `sessao-absolute-nano(1).md`, linhas 57 a 78.

A parte final da regra foi editada para resultar em:

```text
ctf-player ALL=(ALL) NOPASSWD: ALL
```

Essa linha não é um comando de terminal. É o conteúdo da regra de autorização editada dentro do Nano.

O arquivo foi salvo pelo editor. O transcript registrou:

```text
[ Wrote 31 lines ]
```

**Evidência:** E03, linhas 79 a 81.

**Interpretação:** como o Nano foi iniciado por sudo, o processo conseguiu regravar `/etc/sudoers`. Substituir a lista restrita de comandos por `ALL` ampliou a autorização de `ctf-player` para outros comandos via sudo sem senha.

O transcript interativo registra a edição e a mensagem de gravação, mas não contém uma leitura textual posterior de `/etc/sudoers`. Por isso, a linha final é tratada como reconstrução sustentada pela edição visível e confirmada indiretamente pelo sucesso da etapa seguinte.

**Conclusão e próximo passo:** a política aparentava ter sido ampliada. Para validar a mudança, era necessário executar por sudo um comando que não fazia parte da regra original.

### 5.4. Validando a elevação e lendo a flag

**Objetivo e motivo:** confirmar que a autorização havia sido ampliada e acessar o arquivo protegido.

**Contexto:** shell do alvo, usuário `ctf-player`, usando a política sudo modificada.

**Execução observada:**

***INSERIR esse comando no terminal

```bash
sudo cat /home/ctf-player/flag.txt
```

**Resultado observado:**

```text
picoCTF{n4n0_411_7h3_w4y_aae4aa32}
```

**Evidência:** E04, `sessao-absolute-nano(1).md`, linhas 84 a 85.

**Interpretação:** `sudo cat` não aparecia na regra original retornada por `sudo -l`. Seu sucesso demonstra que a fronteira de autorização foi alterada. O conteúdo protegido foi então lido com privilégios elevados.

**Conclusão:** a cadeia de exploração foi concluída e a flag foi observada diretamente no terminal.

## 6. Tentativas relevantes e ajustes

A primeira tentativa de leitura, `cat flag.txt`, falhou com `Permission denied`. Isso mostrou que a solução não era simplesmente localizar o arquivo.

A segunda tentativa, `nano flag.txt` sem sudo, falhou com o mesmo tipo de restrição. Esse teste foi importante porque diferenciou a presença do Nano da execução privilegiada do Nano. A partir desse resultado, a investigação mudou de leitura direta para enumeração de privilégios com `sudo -l`.

Não há evidência no transcript de tentativas adicionais necessárias para chegar à solução.

## 7. Achado técnico

### V01. Edição privilegiada da própria política sudo

**Componente:** configuração sudo e arquivo `/etc/sudoers`.

**Pré-condição:** acesso autenticado como `ctf-player` e presença da regra `(ALL) NOPASSWD: /bin/nano /etc/sudoers`.

**Causa raiz:** uma conta não administrativa recebeu permissão para executar um editor com privilégios elevados diretamente sobre o arquivo que define a política de autorização do próprio sudo.

**Impacto comprovado no desafio:** a regra foi ampliada e um comando diferente do originalmente autorizado conseguiu ler a flag protegida.

**Impacto potencial:** em um sistema real com a mesma configuração, a capacidade de redefinir a política sudo pode permitir execução de comandos com privilégios administrativos. Essa consequência decorre da natureza da política modificável, mas o writeup não afirma ações adicionais que não foram executadas na sessão.

**Correção:** não permitir que usuários não administrativos editem `/etc/sudoers` ou arquivos equivalentes com privilégios elevados. Regras sudo devem conceder somente a operação estritamente necessária e não podem entregar escrita privilegiada sobre arquivos que controlam autenticação, autorização, inicialização de serviços ou execução privilegiada. Para administração legítima do sudoers, `visudo` ajuda a validar sintaxe, mas a correção principal é remover a delegação insegura e aplicar menor privilégio.

**Reteste:** após a correção, `sudo -l` não deve listar um editor autorizado sobre `/etc/sudoers`, e `sudo cat /home/ctf-player/flag.txt` deve permanecer indisponível ao usuário não autorizado.

Em termos de metodologia, este desafio representa uma etapa de pós-exploração com elevação local de privilégios. OWASP WSTG e OWASP API Security não acrescentam classificação útil aqui porque o vetor demonstrado é uma configuração local de privilégios em Linux, não uma falha Web ou de API.

## 8. Flag e validação

**Flag observada:**

```text
picoCTF{n4n0_411_7h3_w4y_aae4aa32}
```

A flag foi observada diretamente como output do comando `sudo cat /home/ctf-player/flag.txt` em E04.

Não há evidência anexada de submissão da flag na interface do picoCTF. Portanto, o estado documentado é **flag obtida**, não **submissão aceita**.

## 9. Reprodução mínima

A sequência abaixo é uma reprodução ajustada para uma nova instância equivalente. Ela não foi reexecutada durante esta revisão documental. Use somente em uma instância autorizada do desafio.

Primeiro, registre a nova sessão.

***INSERIR esse comando no terminal

```bash
script -a sessao-terminal-absolute-nano.log
```

Conecte usando os dados atuais fornecidos pelo picoCTF.

***INSERIR esse comando no terminal

```bash
ssh -p <TARGET_PORT> ctf-player@<TARGET_HOST>
```

Confirme a regra sudo.

***INSERIR esse comando no terminal

```bash
sudo -l
```

Se a nova instância apresentar a mesma regra vulnerável observada na sessão, abra o arquivo autorizado.

***INSERIR esse comando no terminal

```bash
sudo /bin/nano /etc/sudoers
```

Dentro do Nano, altere somente a regra de `ctf-player` de:

```text
ctf-player ALL=(ALL) NOPASSWD: /bin/nano /etc/sudoers
```

para:

```text
ctf-player ALL=(ALL) NOPASSWD: ALL
```

Salve com `Ctrl+O`, confirme o caminho com `Enter` e saia com `Ctrl+X`.

Valide a leitura da flag.

***INSERIR esse comando no terminal

```bash
sudo cat /home/ctf-player/flag.txt
```

Ao terminar a nova sessão, encerre o registro.

***INSERIR esse comando no terminal

```bash
exit
```

Nenhum script Python é necessário para este desafio. A solução depende de comandos simples e de uma edição interativa no Nano, portanto criar um `scriptN.py` apenas para imprimir ou automatizar a flag não acrescentaria valor técnico.

## 10. Impacto, correção e aprendizado

O aprendizado transferível é que uma regra sudo deve ser analisada pelo efeito completo do comando autorizado, não apenas pelo nome do binário. Editores, interpretadores, utilitários de cópia e ferramentas capazes de modificar arquivos privilegiados podem transformar uma regra aparentemente específica em controle administrativo efetivo.

Neste caso, o problema não era uma vulnerabilidade intrínseca do Nano. O editor apenas executou com o privilégio concedido pela política. A falha estava na decisão de permitir que ele modificasse `/etc/sudoers` como usuário privilegiado.

Uma revisão defensiva deve perguntar quais arquivos o comando autorizado consegue alterar, quais subprocessos consegue iniciar, quais configurações carrega e se qualquer uma dessas capacidades permite modificar a fronteira de privilégio.

## 11. Evidências e proveniência

**E01.** Arquivo bruto fornecido: `sessao-absolute-nano(1).md`. Tamanho: `8782 bytes`. SHA-256: `a7fcdeca24ceb8e59d8212e8a1547c4a227dba5d53c60ac24ddf20531b23a9e0`. Sustenta a conexão, enumeração inicial, erros de permissão, regra sudo, edição interativa e flag final. O arquivo contém sequências ANSI de terminal e foi tratado como dado, não executado.

**E02.** Rascunho documental fornecido: `absolute-nano-writeup(1).md`. Tamanho: `5714 bytes`. SHA-256: `6785864641edf58e91eddac91a60cc8c6c5c0043912773380d64d8733954d0be`. É fonte secundária. Ele registra a mesma técnica, mas sanitiza a flag e marca o material como não pronto para publicação.

Os arquivos de evidência bruta não foram adicionados ao repositório GitHub nesta publicação. O writeup é a narrativa técnica; o log privado permanece separado.

## 12. Limitações

A instância registrada era temporária e não foi reaberta nesta revisão. Portanto, a reprodução atual está marcada como não reexecutada.

O transcript interativo não contém uma leitura posterior de `/etc/sudoers` depois do salvamento. A regra final é reconstruída a partir da edição visível no Nano, da mensagem `[ Wrote 31 lines ]` e do sucesso posterior de `sudo cat`.

Há divergência entre o timestamp interno do log, 18/05/2026, e a data da sessão de documentação em que o desafio foi resolvido e registrado, 01/11/2026. A causa não foi inferida.

Não há evidência de submissão aceita pela plataforma. Há evidência somente da obtenção da flag.

## 13. Resultado final

**Resolução:** Resolvido  
**Técnica principal:** abuso de configuração sudo por escrita privilegiada em `/etc/sudoers`  
**Flag:** `picoCTF{n4n0_411_7h3_w4y_aae4aa32}`  
**Reprodução nesta revisão:** Não reexecutada  
**Publicação no GitHub:** Arquivo enviado ao repositório privado `guerreirobr/writeups`
