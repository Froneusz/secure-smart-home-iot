#!/bin/bash
# =============================================================================
# update.sh — Jednorazowa optymalizacja Raspberry Pi dla systemu IoT
# Uruchom jako root: sudo bash update.sh
# Wystarczy zrobic raz — ustawienia przetrwaja restarty
# =============================================================================

set -e

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
krok()     { echo ""; sep; echo -e " ${BOLD}KROK $1${RESET}"; sep; }

if [ "$EUID" -ne 0 ]; then
    log_err "Uruchom jako root: sudo bash update.sh"
    exit 1
fi

clear
sep
echo -e " ${BOLD}Optymalizacja Raspberry Pi — IoT Security System${RESET}"
sep


# =============================================================================
krok "1/6 — Aktualizacja pakietow"
# =============================================================================
log_info "apt update + upgrade..."
apt-get update -qq
apt-get upgrade -y -qq
log_ok "Pakiety zaktualizowane"


# =============================================================================
krok "2/6 — Plik SWAP (512 MB)"
# =============================================================================
if swapon --show | grep -q "/swapfile"; then
    log_warn "Swap /swapfile juz istnieje — pomijam"
else
    log_info "Tworze /swapfile 512 MB..."
    fallocate -l 512M /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=512 status=none
    chmod 600 /swapfile
    mkswap /swapfile -q
    swapon /swapfile

    if ! grep -q "/swapfile" /etc/fstab; then
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
    fi

    log_ok "Swap 512 MB aktywny"
fi

# Swappiness — agresywniejsze uzywanie swap zamiast OOM killera
SWAP_NOW=$(cat /proc/sys/vm/swappiness)
if [ "$SWAP_NOW" -ne 60 ]; then
    sysctl vm.swappiness=60 -q
    sed -i '/vm.swappiness/d' /etc/sysctl.conf
    echo 'vm.swappiness=60' >> /etc/sysctl.conf
fi
log_ok "vm.swappiness=60 (system bedzie korzystal ze swap zanim zacznie killowac procesy)"


# =============================================================================
krok "3/6 — Limity pamieci systemd (cgroups)"
# =============================================================================
# Wlacz cgroup memory — wymagane zeby MemoryMax dzialalo w systemd
CMDLINE="/boot/cmdline.txt"
[ -f "/boot/firmware/cmdline.txt" ] && CMDLINE="/boot/firmware/cmdline.txt"

if grep -q "cgroup_memory=1" "$CMDLINE"; then
    log_warn "cgroup_memory juz wlaczone w $CMDLINE"
else
    log_info "Wlaczam cgroup_memory w $CMDLINE..."
    sed -i 's/$/ cgroup_enable=memory cgroup_memory=1/' "$CMDLINE"
    log_ok "cgroup_memory wlaczone — wymagany restart po zakonczeniu skryptu"
fi


# =============================================================================
krok "4/6 — Optymalizacja InfluxDB"
# =============================================================================
INFLUX_CONF=""
for p in /etc/influxdb/config.toml /etc/influxdb/influxdb.conf /etc/influxdb2/config.yml; do
    [ -f "$p" ] && INFLUX_CONF="$p" && break
done

if [ -n "$INFLUX_CONF" ]; then
    log_ok "Znaleziono konfiguracje InfluxDB: $INFLUX_CONF"
    log_warn "Edytuj recznie jezeli potrzeba — InfluxDB 2.x zarzadza pamiecia automatycznie"
else
    log_warn "Nie znaleziono pliku konfiguracyjnego InfluxDB — pomijam"
fi

# InfluxDB — limit pamieci przez systemd override
mkdir -p /etc/systemd/system/influxdb.service.d
cat > /etc/systemd/system/influxdb.service.d/memory.conf << 'EOF'
[Service]
MemoryMax=400M
MemoryHigh=350M
EOF
log_ok "InfluxDB limit pamieci: 400 MB (przez systemd override)"


# =============================================================================
krok "5/6 — Optymalizacja Node.js / Ganache"
# =============================================================================
# Globalna zmienna NODE_OPTIONS ograniczajaca heap V8
NODE_CONF="/etc/environment"
if ! grep -q "NODE_OPTIONS" "$NODE_CONF" 2>/dev/null; then
    echo 'NODE_OPTIONS="--max-old-space-size=256"' >> "$NODE_CONF"
    log_ok "NODE_OPTIONS=--max-old-space-size=256 dodane do /etc/environment"
else
    log_warn "NODE_OPTIONS juz ustawione w /etc/environment"
fi

# Ganache — alias z flag ami pamieci
PROFILE_FILE="/etc/profile.d/ganache-opt.sh"
cat > "$PROFILE_FILE" << 'EOF'
# Ganache z ograniczonym heap V8
alias ganache-cli='NODE_OPTIONS="--max-old-space-size=256" ganache-cli --accounts 5 --deterministic --gasLimit 6000000'
alias ganache='NODE_OPTIONS="--max-old-space-size=256" ganache --accounts 5 --deterministic --gasLimit 6000000'
EOF
chmod +x "$PROFILE_FILE"
log_ok "Alias ganache-cli z flagami pamieci dodany"


# =============================================================================
krok "6/6 — Uprawnienia i weryfikacja"
# =============================================================================
log_info "Reload systemd..."
systemctl daemon-reload
log_ok "systemd przeladowany"

log_info "Aktualny stan RAM:"
free -h

log_info "Aktualny swap:"
swapon --show 2>/dev/null || echo "  brak aktywnego swap"

echo ""
sep
echo -e " ${BOLD}${ZIELONY}Optymalizacja zakonczona!${RESET}"
sep
echo ""
echo -e " Co zostalo zrobione:"
echo -e "  ${ZIELONY}✓${RESET} Swap 512 MB — system nie crashuje gdy braknie RAM"
echo -e "  ${ZIELONY}✓${RESET} vm.swappiness=60 — agresywne uzycie swap przed OOM"
echo -e "  ${ZIELONY}✓${RESET} cgroup_memory — limity RAM per serwis dzialaja"
echo -e "  ${ZIELONY}✓${RESET} InfluxDB limit 400 MB"
echo -e "  ${ZIELONY}✓${RESET} Node.js/Ganache limit 256 MB heap"
echo ""
echo -e " ${ZOLTY}WYMAGANY RESTART:${RESET}"
echo -e "   sudo reboot"
echo ""
echo -e " Po restarcie uruchom system:"
echo -e "   bash start.sh"
sep
