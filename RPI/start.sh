#!/bin/bash
# =============================================================================
# start.sh — Uruchamia caly system IoT (Ganache + Bridge + Panel)
# Uzycie: bash ~/Desktop/praca_mgr/start.sh
# Zatrzymanie: Ctrl+C
# =============================================================================

# Katalog projektu = lokalizacja tego skryptu (~/Desktop/praca_mgr)
BAZA="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="$BAZA/logi"
mkdir -p "$LOG_DIR"

CZERWONY='\033[0;31m'
ZIELONY='\033[0;32m'
ZOLTY='\033[1;33m'
NIEBIESKI='\033[0;34m'
RESET='\033[0m'
BOLD='\033[1m'

sep()      { echo -e "${NIEBIESKI}══════════════════════════════════════════${RESET}"; }
log_ok()   { echo -e " ${ZIELONY}[OK]${RESET}   $1"; }
log_info() { echo -e " ${NIEBIESKI}[INFO]${RESET} $1"; }
log_warn() { echo -e " ${ZOLTY}[WARN]${RESET} $1"; }
log_err()  { echo -e " ${CZERWONY}[BLAD]${RESET} $1"; }

PID_GANACHE=""
PID_BRIDGE=""
PID_PANEL=""

cleanup() {
    echo ""
    sep
    echo -e " ${ZOLTY}Zatrzymywanie serwisow...${RESET}"
    [ -n "$PID_PANEL"   ] && kill "$PID_PANEL"   2>/dev/null && log_ok "Panel zatrzymany"
    [ -n "$PID_BRIDGE"  ] && kill "$PID_BRIDGE"  2>/dev/null && log_ok "Bridge zatrzymany"
    [ -n "$PID_GANACHE" ] && kill "$PID_GANACHE" 2>/dev/null && log_ok "Ganache zatrzymany"
    sleep 1
    sep
    echo -e " ${ZOLTY}System zatrzymany.${RESET}"
    exit 0
}
trap cleanup INT TERM

clear
sep
echo -e " ${BOLD}IoT Security System — Panel startowy${RESET}"
echo -e " Skrypty: $BAZA"
echo -e " Logi:    $LOG_DIR"
sep
echo ""

# ── Weryfikacja plikow ────────────────────────────────────────────────────────
if [ ! -f "$BAZA/mqtt_to_influx.py" ]; then
    log_err "Nie znaleziono: $BAZA/mqtt_to_influx.py"
    exit 1
fi
if [ ! -f "$BAZA/app.py" ]; then
    log_err "Nie znaleziono: $BAZA/app.py"
    exit 1
fi

# ── Certyfikat TLS (self-signed) ──────────────────────────────────────────────
# app.py szuka cert.pem/key.pem obok siebie (w $BAZA); gen_cert.sh generuje je tam.
if [ -f "$BAZA/cert.pem" ] && [ -f "$BAZA/key.pem" ]; then
    log_ok "Certyfikat TLS juz istnieje"
elif [ -f "$BAZA/gen_cert.sh" ]; then
    log_info "Generowanie certyfikatu TLS (HTTPS)..."
    if bash "$BAZA/gen_cert.sh" > "$LOG_DIR/openssl.log" 2>&1; then
        log_ok "Certyfikat TLS wygenerowany (panel bedzie na HTTPS)"
    else
        log_warn "gen_cert.sh nie powiodl sie — panel wystartuje na HTTP (sprawdz $LOG_DIR/openssl.log)"
    fi
else
    log_warn "Brak gen_cert.sh — panel wystartuje na HTTP (bez TLS)"
fi

# ── 1. GANACHE ────────────────────────────────────────────────────────────────
GANACHE_BIN="$(which ganache-cli 2>/dev/null || which ganache 2>/dev/null)"

if [ -n "$GANACHE_BIN" ]; then
    log_info "Uruchamianie Ganache..."
    NODE_OPTIONS="--max-old-space-size=256" \
        "$GANACHE_BIN" \
            --port 8545 \
            --accounts 5 \
            --deterministic \
            --gasLimit 6000000 \
            > "$LOG_DIR/ganache.log" 2>&1 &
    PID_GANACHE=$!
    sleep 3

    if kill -0 "$PID_GANACHE" 2>/dev/null; then
        log_ok "Ganache dziala (PID=$PID_GANACHE, port 8545)"
    else
        log_warn "Ganache nie uruchomil sie — blockchain wylaczony"
        log_warn "Sprawdz: $LOG_DIR/ganache.log"
        PID_GANACHE=""
    fi
else
    log_warn "ganache-cli nie znaleziony — blockchain wylaczony"
fi

# ── 2. MQTT → INFLUXDB BRIDGE ─────────────────────────────────────────────────
log_info "Uruchamianie mqtt_to_influx.py..."
python3 "$BAZA/mqtt_to_influx.py" > "$LOG_DIR/bridge.log" 2>&1 &
PID_BRIDGE=$!
sleep 2

if kill -0 "$PID_BRIDGE" 2>/dev/null; then
    log_ok "Bridge dziala (PID=$PID_BRIDGE)"
else
    log_err "Bridge nie uruchomil sie — sprawdz $LOG_DIR/bridge.log"
    tail -10 "$LOG_DIR/bridge.log"
    cleanup
fi

# ── 3. FLASK PANEL ────────────────────────────────────────────────────────────
log_info "Uruchamianie app.py..."
python3 "$BAZA/app.py" > "$LOG_DIR/panel.log" 2>&1 &
PID_PANEL=$!
sleep 2

if kill -0 "$PID_PANEL" 2>/dev/null; then
    log_ok "Panel dziala (PID=$PID_PANEL)"
else
    log_err "Panel nie uruchomil sie — sprawdz $LOG_DIR/panel.log"
    tail -10 "$LOG_DIR/panel.log"
    cleanup
fi

# ── STATUS ────────────────────────────────────────────────────────────────────
echo ""
sep
echo -e " ${BOLD}${ZIELONY}System uruchomiony!${RESET}"
sep
IP=$(hostname -I | awk '{print $1}')
echo -e " Panel:   ${ZIELONY}http://${IP}:5000${RESET}"
echo -e " Bridge:  PID=$PID_BRIDGE  → $LOG_DIR/bridge.log"
[ -n "$PID_GANACHE" ] && \
echo -e " Ganache: PID=$PID_GANACHE → $LOG_DIR/ganache.log"
echo ""
echo -e " ${ZOLTY}Ctrl+C zatrzymuje wszystko${RESET}"
sep
echo ""

# Logi bridge na zywo
echo -e " ${NIEBIESKI}=== Logi bridge (na zywo) ===${RESET}"
tail -f "$LOG_DIR/bridge.log" &
PID_TAIL=$!

# Petla watchdog — restart jesli proces padnie
while true; do
    sleep 10

    if ! kill -0 "$PID_BRIDGE" 2>/dev/null; then
        log_warn "Bridge padl — restartuje..."
        python3 "$BAZA/mqtt_to_influx.py" >> "$LOG_DIR/bridge.log" 2>&1 &
        PID_BRIDGE=$!
        log_ok "Bridge zrestartowany (PID=$PID_BRIDGE)"
    fi

    if ! kill -0 "$PID_PANEL" 2>/dev/null; then
        log_warn "Panel padl — restartuje..."
        python3 "$BAZA/app.py" >> "$LOG_DIR/panel.log" 2>&1 &
        PID_PANEL=$!
        log_ok "Panel zrestartowany (PID=$PID_PANEL)"
    fi
done
