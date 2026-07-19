#!/bin/bash
# =============================================================================
# gen_cert.sh — Generuje self-signed certyfikat TLS dla panelu Flask (app.py)
# Idempotentny: jesli cert.pem + key.pem juz istnieja, nic nie robi.
# Uzycie: bash gen_cert.sh   (uruchamiany automatycznie przez start.sh / setup_systemd.sh)
# =============================================================================
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
CERT="$DIR/cert.pem"
KEY="$DIR/key.pem"

if [ -f "$CERT" ] && [ -f "$KEY" ]; then
    echo "[OK] cert.pem + key.pem juz istnieja — pomijam (usun oba, aby wygenerowac na nowo)"
    exit 0
fi

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -z "$IP" ] && IP="127.0.0.1"
HOST="$(hostname 2>/dev/null || echo raspberrypi)"

echo "[INFO] Generuje self-signed cert TLS (CN=$HOST, IP=$IP, waznosc 365 dni)..."
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout "$KEY" -out "$CERT" \
    -subj "/C=PL/O=Magisterka-IoT/CN=$HOST" \
    -addext "subjectAltName=DNS:$HOST,DNS:localhost,IP:$IP,IP:127.0.0.1"

chmod 600 "$KEY"
chmod 644 "$CERT"
echo "[OK] Wygenerowano: $CERT"
echo "[OK] Wygenerowano: $KEY  (uprawnienia 600 — tylko wlasciciel)"
