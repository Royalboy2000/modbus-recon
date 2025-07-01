#!/bin/bash

# Basic Modbus Recon Script
TARGET="$1"

if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <IP_ADDRESS>"
    exit 1
fi

echo "[*] Checking if Modbus port 502 is open on $TARGET..."
nmap -Pn -p 502 "$TARGET" | grep "502/tcp" | grep -q "open"
if [[ $? -ne 0 ]]; then
    echo "[-] Port 502 is not open. Exiting."
    exit 1
fi

echo "[+] Port 502 is open. Beginning Modbus unit ID scan..."

for id in $(seq 1 10); do
    echo "[*] Trying unit ID $id..."
    mbpoll -m tcp -a "$id" -r 0 -c 5 -t 3 "$TARGET" 2>/dev/null | grep -q "values"
    if [[ $? -eq 0 ]]; then
        echo "[+] Unit ID $id is active. Dumping holding registers..."
        mbpoll -m tcp -a "$id" -r 0 -c 10 -t 3 "$TARGET"
    else
        echo "[-] No response from Unit ID $id."
    fi
done
