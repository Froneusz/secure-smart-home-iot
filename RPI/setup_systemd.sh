#!/bin/bash
# =============================================================================
# setup_systemd.sh — Konfiguracja autostartu na Raspberry Pi
# Uruchom jako root: sudo bash setup_systemd.sh
# =============================================================================
set -e

RPI_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON="$(which python3)"
USER_NAME="$(logname 2>/dev/null || echo pi)"

echo "[0/5] Generowanie certyfikatu TLS (self-signed)..."
if [ -f "${RPI_DIR}/gen_cert.sh" ]; then
    bash "${RPI_DIR}/gen_cert.sh"
    # Serwis dziala jako ${USER_NAME}, wiec on musi byc wlascicielem plikow
    chown "${USER_NAME}":"${USER_NAME}" "${RPI_DIR}/cert.pem" "${RPI_DIR}/key.pem" 2>/dev/null || true
else
    echo "  WARN: brak gen_cert.sh — panel wystartuje bez TLS (HTTP)"
fi

echo "[1/5] Dodawanie pliku SWAP (512 MB)..."
if ! grep -q "swapfile" /etc/fstab 2>/dev/null; then
    fallocate -l 512M /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=512
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
    echo "  Swap dodany."
else
    echo "  Swap juz istnieje."
fi

echo "[2/5] Tworzenie serwisu: iot-bridge.service (mqtt_to_influx.py)..."
cat > /etc/systemd/system/iot-bridge.service << EOF
[Unit]
Description=IoT MQTT-to-InfluxDB Bridge
After=network-online.target mosquitto.service influxdb.service
Wants=network-online.target

[Service]
Type=simple
User=${USER_NAME}
WorkingDirectory=${RPI_DIR}
ExecStart=${PYTHON} ${RPI_DIR}/mqtt_to_influx.py
Restart=always
RestartSec=5
# Limit pamieci — OOM killer zabije ten proces zanim crash caly system
MemoryMax=200M
# Restart gdy uzycie pamieci > 180 MB (memory leak protection)
MemoryHigh=180M

[Install]
WantedBy=multi-user.target
EOF

echo "[3/5] Tworzenie serwisu: iot-panel.service (app.py)..."
cat > /etc/systemd/system/iot-panel.service << EOF
[Unit]
Description=IoT Flask Panel
After=network-online.target iot-bridge.service

[Service]
Type=simple
User=${USER_NAME}
WorkingDirectory=${RPI_DIR}
ExecStart=${PYTHON} ${RPI_DIR}/app.py
Restart=always
RestartSec=5
MemoryMax=150M
MemoryHigh=130M

[Install]
WantedBy=multi-user.target
EOF

echo "[4/5] Tworzenie serwisu: iot-ganache.service (Ganache blockchain)..."
GANACHE_BIN="$(which ganache-cli 2>/dev/null || which ganache 2>/dev/null || echo '')"

if [ -n "$GANACHE_BIN" ]; then
cat > /etc/systemd/system/iot-ganache.service << EOF
[Unit]
Description=Ganache Local Blockchain (Ethereum testnet)
After=network.target

[Service]
Type=simple
User=${USER_NAME}
# --gasLimit i --accounts ograniczaja zuzycie pamieci
ExecStart=${GANACHE_BIN} --port 8545 --accounts 5 --deterministic --gasLimit 6000000
Restart=always
RestartSec=10
# Ganache (Node.js) — twarda granica pamieci
MemoryMax=300M
Environment=NODE_OPTIONS="--max-old-space-size=256"

[Install]
WantedBy=multi-user.target
EOF
    echo "  Ganache znaleziony: ${GANACHE_BIN}"
else
    echo "  WARN: ganache-cli nie znaleziony — pomin serwis lub zainstaluj: npm install -g ganache"
fi

echo "[5/5] Wlaczanie serwisow..."
systemctl daemon-reload
systemctl enable mosquitto
systemctl enable influxdb
[ -n "$GANACHE_BIN" ] && systemctl enable iot-ganache
systemctl enable iot-bridge
systemctl enable iot-panel

systemctl restart mosquitto
systemctl restart influxdb
[ -n "$GANACHE_BIN" ] && systemctl restart iot-ganache
sleep 3
systemctl restart iot-bridge
sleep 2
systemctl restart iot-panel

echo ""
echo "=============================================="
echo " Gotowe! Sprawdz status:"
echo "   systemctl status iot-bridge"
echo "   systemctl status iot-panel"
echo "   systemctl status iot-ganache"
echo "   journalctl -u iot-bridge -f   # logi na zywo"
echo "   free -h                        # stan RAM"
echo "=============================================="
