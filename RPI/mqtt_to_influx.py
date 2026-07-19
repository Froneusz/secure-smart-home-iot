#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mqtt_to_influx.py — Bridge MQTT → InfluxDB + Blockchain Ganache
Praca magisterska: Bezpieczenstwo IoT — porownanie algorytmow szyfrowania
na urzadzeniach wbudowanych ESP32.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import time
from datetime import datetime

import paho.mqtt.client as mqtt
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
from web3 import Web3

try:
    from Crypto.Cipher import AES, ARC4
except ImportError:
    from Cryptodome.Cipher import AES, ARC4  # type: ignore

# ═══════════════════════════════════════════════════════════════════════════════
# KONFIGURACJA
# ═══════════════════════════════════════════════════════════════════════════════
KLUCZ_AES           = b"1234567890123456"   # 16B klucz AES-128 (identyczny z firmware ESP32)
KLUCZ_XOR           = b"1234"              # klucz XOR — algorytm 3
KLUCZ_VIG           = "TAJNE"              # klucz Vigenere — algorytm 4
KLUCZ_RC4           = b"1234567890123456"  # klucz RC4 — algorytm 5
PRZESUNIECIE_CEZARA = 3                    # przesun. szyfru Cezara (+3 szyfrowanie, -3 deszyf.)

INFLUX_TOKEN  = "TWOJ_INFLUXDB_TOKEN"   # <-- token z InfluxDB UI: Data → API Tokens
INFLUX_ORG    = "MojaMagisterka"
INFLUX_BUCKET = "dane_esp"
INFLUX_URL    = "http://localhost:8086"

MQTT_BROKER = "127.0.0.1"
MQTT_PORT   = 1883

GANACHE_URL = "http://127.0.0.1:8545"   # lokalny testnet Ganache

# Topiki MQTT (literowka "srodowiskoa" celowa — zgodnosc z firmware ESP32)
TOPIK_SECURITY_DANE   = "/plytka_antywlamaniowa/zaszyfrowane"
TOPIK_SECURITY_ONLINE = "/plytka_antywlamaniowa/online"
TOPIK_ENV_DANE        = "/plytka_srodowiskoa/zaszyfrowane"
TOPIK_ENV_ONLINE      = "/plytka_srodowiskoa/online"

# Kazda wiadomosc jest haszowana i zapisywana na blockchain (bez rate limitingu).
# Jesli Ganache na RPi zacznie sie dlawic (sprawdz `free -h` / journalctl -u iot-ganache),
# mozna przywrocic limitowanie: TX tylko co N-ta wiadomosc per urzadzenie.

NAZWY_ALGORYTMOW: dict[int, str] = {
    0: "Czysty tekst",
    1: "Base64",
    2: "Cezar-3",
    3: "XOR-1234",
    4: "Vigenere-TAJNE",
    5: "RC4",
    6: "AES-128-ECB",
    7: "AES-128-CBC",
    8: "AES-128-GCM",
}


# ═══════════════════════════════════════════════════════════════════════════════
# KOLOROWY OUTPUT TERMINALA (kody ANSI)
# ═══════════════════════════════════════════════════════════════════════════════
class Kol:
    RESET     = "\033[0m"
    BOLD      = "\033[1m"
    CZERWONY  = "\033[91m"
    ZIELONY   = "\033[92m"
    ZOLTY     = "\033[93m"
    NIEBIESKI = "\033[94m"
    FIOLETOWY = "\033[95m"
    CYAN      = "\033[96m"
    SZARY     = "\033[90m"
    BIALY     = "\033[97m"


_STYLE_LOGU: dict[str, tuple[str, str]] = {
    "OK":         (Kol.ZIELONY,    "✔ OK        "),
    "BLAD":       (Kol.CZERWONY,   "✘ BLAD      "),
    "INFO":       (Kol.CYAN,       "ℹ INFO      "),
    "BLOCKCHAIN": (Kol.FIOLETOWY,  "⛓ CHAIN     "),
    "HEARTBEAT":  (Kol.SZARY,      "♥ HEARTBEAT "),
    "MQTT":       (Kol.NIEBIESKI,  "⇄ MQTT      "),
    "INFLUX":     (Kol.ZOLTY,      "⬆ INFLUX    "),
}


def log(poziom: str, tekst: str) -> None:
    """Kolorowy komunikat z timestampem do terminala."""
    czas = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    kolor, prefix = _STYLE_LOGU.get(poziom, (Kol.RESET, "  LOG       "))
    print(f"{Kol.SZARY}[{czas}]{Kol.RESET} {kolor}{prefix}{Kol.RESET}{tekst}")


# ═══════════════════════════════════════════════════════════════════════════════
# BLOCKCHAIN — GANACHE (graceful fallback gdy offline)
# ═══════════════════════════════════════════════════════════════════════════════
_w3:         Web3 | None = None
_konto_eth:  str  | None = None
_ganache_ok: bool        = False


def _inicjalizuj_blockchain() -> None:
    global _w3, _konto_eth, _ganache_ok
    try:
        polaczenie = Web3(Web3.HTTPProvider(GANACHE_URL, request_kwargs={"timeout": 3}))
        if polaczenie.is_connected():
            konta = polaczenie.eth.accounts
            if konta:
                _w3        = polaczenie
                _konto_eth = konta[0]
                _ganache_ok = True
                log("BLOCKCHAIN", f"Ganache online. Konto: {_konto_eth}")
            else:
                log("BLAD", "Ganache: brak kont — sprawdz konfiguracje")
        else:
            log("BLAD", "Ganache offline — hashi nie beda zapisywane na blockchain")
    except Exception as ex:
        log("BLAD", f"Blockchain init: {ex}")


def zapisz_na_blockchain(data_hash: str) -> str:
    """
    Wysyla hash SHA-256 jako dane transakcji ETH do Ganache.
    Zwraca hex tx_hash lub pusty string gdy blockchain niedostepny.
    """
    if not _ganache_ok or _w3 is None or _konto_eth is None:
        return ""
    try:
        tx = _w3.eth.send_transaction({
            "from":     _konto_eth,
            "to":       _konto_eth,
            "value":    0,
            "data":     "0x" + data_hash,   # hash jako dane transakcji
            "gas":      100_000,
            "gasPrice": _w3.to_wei("1", "gwei"),
        })
        tx_hex = tx.hex()
        log("BLOCKCHAIN", f"TX: {tx_hex[:32]}...")
        return tx_hex
    except Exception as ex:
        log("BLAD", f"Blockchain zapis: {ex}")
        return ""


# ═══════════════════════════════════════════════════════════════════════════════
# INFLUXDB
# ═══════════════════════════════════════════════════════════════════════════════
_klient_influx = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
_api_zapisu    = _klient_influx.write_api(write_options=SYNCHRONOUS)


def _zapisz_punkt(punkt: Point) -> None:
    try:
        _api_zapisu.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=punkt)
    except Exception as ex:
        log("BLAD", f"InfluxDB write: {ex}")


def zapisz_security(dane: dict, raw_enc: str, algo: int,
                    data_hash: str, tx_hash: str) -> None:
    """Zapis pomiaru plytki antywlamaniowej do InfluxDB."""
    acc = dane.get("akcelerometr", {})
    punkt = (
        Point("pomiary")
        .tag("urzadzenie", "security")
        .field("status",      str(dane.get("status", "OFFLINE")))
        .field("pir",         int(dane.get("pir",    0)))
        .field("drzwi",       int(dane.get("drzwi",  0)))
        .field("acc_x",       float(dane.get("acc_x", acc.get("x", 0.0))))
        .field("acc_y",       float(dane.get("acc_y", acc.get("y", 0.0))))
        .field("acc_z",       float(dane.get("acc_z", acc.get("z", 0.0))))
        .field("raw_enc",     raw_enc[:500])
        .field("uzyty_szyfr", NAZWY_ALGORYTMOW.get(algo, f"algo_{algo}"))
        .field("data_hash",   data_hash)
        .field("tx_hash",     tx_hash)
    )
    _zapisz_punkt(punkt)
    log("INFLUX", f"security zapisano (algo={algo}, status={dane.get('status', '?')})")


def zapisz_environment(dane: dict, raw_enc: str, algo: int,
                       data_hash: str, tx_hash: str) -> None:
    """Zapis pomiaru plytki srodowiskowej do InfluxDB."""
    punkt = (
        Point("pomiary")
        .tag("urzadzenie", "environment")
        .field("temperatura", float(dane.get("temperatura", dane.get("temp",  0.0))))
        .field("wilgotnosc",  float(dane.get("wilgotnosc",  dane.get("wilg",  0.0))))
        .field("cisnienie",   float(dane.get("cisnienie",   dane.get("pres",  0.0))))
        .field("gazy",        float(dane.get("gazy",        dane.get("mq135", 0.0))))
        .field("swiatlo",     float(dane.get("swiatlo",     dane.get("lux",   0.0))))
        .field("dzwiek",      int(  dane.get("dzwiek",      dane.get("sound", 0))))
        .field("raw_enc",     raw_enc[:500])
        .field("uzyty_szyfr", NAZWY_ALGORYTMOW.get(algo, f"algo_{algo}"))
        .field("data_hash",   data_hash)
        .field("tx_hash",     tx_hash)
    )
    _zapisz_punkt(punkt)
    log("INFLUX", f"environment zapisano (T={dane.get('temperatura', '?')}C, "
                  f"H={dane.get('wilgotnosc', '?')}%)")


def zapisz_heartbeat(urzadzenie: str) -> None:
    """Zapis sygnalu heartbeat (do wykrywania online/offline w panelu)."""
    punkt = (
        Point("pomiary")
        .tag("urzadzenie", urzadzenie)
        .field("heartbeat", 1)
    )
    _zapisz_punkt(punkt)


# ═══════════════════════════════════════════════════════════════════════════════
# SILNIK DESZYFROWANIA — algorytmy 0–8
# ═══════════════════════════════════════════════════════════════════════════════

def _usun_pkcs7(dane: bytes) -> bytes:
    """Usuwa padding PKCS7 z odszyfrowanych bajtow AES (bloki 128-bit)."""
    if not dane:
        raise ValueError("Puste dane — nie mozna usunac paddingu PKCS7")
    pad = dane[-1]
    if not (1 <= pad <= 16):
        raise ValueError(f"Nieprawidlowy rozmiar paddingu PKCS7: {pad}")
    if dane[-pad:] != bytes([pad] * pad):
        raise ValueError("Niezgodne bajty paddingu PKCS7")
    return dane[:-pad]


def _cezar_odszyfruj(tekst: str) -> str:
    """Deszyfrowanie Cezara: przesuniecie -3 w przestrzeni ASCII 32–126 (95 znakow)."""
    wynik = []
    for znak in tekst:
        k = ord(znak)
        if 32 <= k <= 126:
            k = 32 + (k - 32 - PRZESUNIECIE_CEZARA) % 95
        wynik.append(chr(k))
    return "".join(wynik)


def _xor_odszyfruj(dane: bytes) -> bytes:
    """XOR z cyklicznym kluczem (operacja symetryczna: encrypt == decrypt)."""
    dl = len(KLUCZ_XOR)
    return bytes(b ^ KLUCZ_XOR[i % dl] for i, b in enumerate(dane))


def _vigenere_odszyfruj(tekst: str) -> str:
    """Deszyfrowanie Vigenere: odwrotne przesuniecia kluczem w przestrzeni ASCII 32–126."""
    wynik = []
    j = 0
    for znak in tekst:
        k = ord(znak)
        if 32 <= k <= 126:
            shift = ord(KLUCZ_VIG[j % len(KLUCZ_VIG)]) - 32
            k = 32 + (k - 32 - shift) % 95
            j += 1
        wynik.append(chr(k))
    return "".join(wynik)


def deszyfruj(numer: int, payload: str) -> bytes | None:
    """
    Glowna funkcja deszyfrowania.

    Parametry:
        numer   — numer algorytmu (0–8) z prefiksu MQTT
        payload — czesc po ':' (tekst lub hex w zaleznosci od algorytmu)

    Zwraca bajty odszyfrowanego JSON lub None przy bledzie.
    """
    try:
        if numer == 0:
            # Czysty tekst — payload to surowy JSON
            return payload.encode("utf-8")

        if numer == 1:
            # Base64 — payload to ciag Base64 kodujacy JSON
            return base64.b64decode(payload)

        if numer == 2:
            # Cezar — payload to tekst po szyfrowaniu (nie hex)
            return _cezar_odszyfruj(payload).encode("utf-8")

        if numer == 3:
            # XOR — payload to hex zaszyfrowanych bajtow
            return _xor_odszyfruj(bytes.fromhex(payload))

        if numer == 4:
            # Vigenere — payload to tekst po szyfrowaniu (nie hex)
            return _vigenere_odszyfruj(payload).encode("utf-8")

        if numer == 5:
            # RC4 — payload to hex, klucz identyczny z KLUCZ_AES
            szyfr = ARC4.new(KLUCZ_RC4)
            return szyfr.decrypt(bytes.fromhex(payload))

        if numer == 6:
            # AES-128-ECB + PKCS7 — payload to hex
            szyfr = AES.new(KLUCZ_AES, AES.MODE_ECB)
            return _usun_pkcs7(szyfr.decrypt(binascii.unhexlify(payload)))

        if numer == 7:
            # AES-128-CBC, IV = 16 × 0x00 — payload to hex
            iv    = bytes(16)
            szyfr = AES.new(KLUCZ_AES, AES.MODE_CBC, iv=iv)
            return _usun_pkcs7(szyfr.decrypt(binascii.unhexlify(payload)))

        if numer == 8:
            # AES-128-GCM, staly nonce bytes([1..12]) — payload to hex
            # Format: szyfrogram || tag (ostatnie 16B)
            nonce    = bytes(range(1, 13))
            surowe   = binascii.unhexlify(payload)
            szyfrogram, tag = surowe[:-16], surowe[-16:]
            szyfr    = AES.new(KLUCZ_AES, AES.MODE_GCM, nonce=nonce)
            return szyfr.decrypt_and_verify(szyfrogram, tag)

        log("BLAD", f"Nieznany numer algorytmu: {numer}")
        return None

    except Exception as ex:
        log("BLAD", f"Deszyfrowanie [algo={numer}]: {ex}")
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# CALLBACKI MQTT
# ═══════════════════════════════════════════════════════════════════════════════

def przy_polaczeniu(klient, _ud, _flagi, kod, _wlasciw=None) -> None:
    """Callback MQTT: polaczenie nawiazane — subskrybuje 4 topiki."""
    if not getattr(kod, "is_failure", kod != 0):
        log("MQTT", "Polaczono z brokerem MQTT")
        klient.subscribe([
            (TOPIK_SECURITY_DANE,   0),
            (TOPIK_SECURITY_ONLINE, 0),
            (TOPIK_ENV_DANE,        0),
            (TOPIK_ENV_ONLINE,      0),
        ])
        log("OK", "Zasubskrybowano 4 topiki (2x dane zaszyfrowane + 2x heartbeat)")
    else:
        log("BLAD", f"MQTT blad polaczenia: {kod}")


def przy_rozlaczeniu(klient, _ud, _flagi, kod=0, _wlasciw=None) -> None:
    log("BLAD", f"MQTT rozlaczono (kod={kod})")


def przy_wiadomosci(klient, _ud, wiadomosc) -> None:
    """
    Glowny callback MQTT.
    Parsuje format <nr>:<payload>, deszyfruje, hashuje SHA-256,
    zapisuje do blockchain Ganache i InfluxDB.
    """
    try:
        temat  = wiadomosc.topic
        surowy = wiadomosc.payload.decode("utf-8", errors="replace").strip()

        # ── HEARTBEAT ──────────────────────────────────────────────────────────
        if temat == TOPIK_SECURITY_ONLINE:
            log("HEARTBEAT", f"security → '{surowy}'")
            zapisz_heartbeat("security")
            return

        if temat == TOPIK_ENV_ONLINE:
            log("HEARTBEAT", f"environment → '{surowy}'")
            zapisz_heartbeat("environment")
            return

        # ── DANE ZASZYFROWANE ──────────────────────────────────────────────────
        urzadzenie = "security" if "antywlamaniowa" in temat else "environment"

        if ":" not in surowy:
            log("BLAD", f"Brak separatora ':' w [{temat}]: '{surowy[:60]}'")
            return

        idx           = surowy.index(":")
        czesc_algo    = surowy[:idx].strip()
        czesc_payload = surowy[idx + 1:].strip()

        try:
            numer_algo = int(czesc_algo)
        except ValueError:
            log("BLAD", f"Nieprawidlowy nr algorytmu: '{czesc_algo}'")
            return

        nazwa_algo = NAZWY_ALGORYTMOW.get(numer_algo, f"algo_{numer_algo}")

        # Deszyfrowanie
        odszyfrowane = deszyfruj(numer_algo, czesc_payload)
        if odszyfrowane is None:
            return

        tekst_json = odszyfrowane.decode("utf-8", errors="replace").strip()

        # SHA-256 odszyfrowanych danych
        data_hash = hashlib.sha256(odszyfrowane).hexdigest()

        # Kazda wiadomosc trafia na blockchain (Ganache) — pelne pokrycie dla integralnosci danych
        tx_hash = zapisz_na_blockchain(data_hash)

        # Arduino String(NaN) emituje literał "nan" — nieprawidlowy JSON; zamieniamy na 0
        tekst_json_clean = re.sub(r':\s*nan\b', ':0', tekst_json)

        # Parsowanie JSON
        try:
            dane_json = json.loads(tekst_json_clean)
        except json.JSONDecodeError as je:
            log("BLAD", f"JSON parse ({je}): '{tekst_json[:100]}'")
            return

        # Zapis do InfluxDB
        if urzadzenie == "security":
            zapisz_security(dane_json, surowy, numer_algo, data_hash, tx_hash)
        else:
            zapisz_environment(dane_json, surowy, numer_algo, data_hash, tx_hash)

        # ── KOLOROWY OUTPUT TERMINALA ──────────────────────────────────────────
        sep   = f"{Kol.SZARY}{'━' * 64}{Kol.RESET}"
        kolor = Kol.ZOLTY if urzadzenie == "security" else Kol.NIEBIESKI
        print(f"\n{sep}")
        print(f"  {kolor}{Kol.BOLD}{urzadzenie.upper():15}{Kol.RESET}  "
              f"Algo: {Kol.ZOLTY}{nazwa_algo}{Kol.RESET}")
        print(f"  Hash:  {Kol.FIOLETOWY}{data_hash[:48]}...{Kol.RESET}")
        if tx_hash:
            print(f"  TX:    {Kol.ZIELONY}{tx_hash[:48]}...{Kol.RESET}")
        else:
            print(f"  TX:    {Kol.SZARY}Ganache offline — brak TX{Kol.RESET}")
        print(f"  JSON:  {Kol.SZARY}{tekst_json[:100]}{Kol.RESET}")
        print(f"{sep}\n")

    except Exception as ex:
        log("BLAD", f"przy_wiadomosci: {ex}")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN — petla MQTT z automatycznym wznawianiem polaczenia
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    _inicjalizuj_blockchain()

    print(f"\n{Kol.BOLD}{Kol.NIEBIESKI}{'═' * 64}{Kol.RESET}")
    print(f"{Kol.BOLD}  IoT KRYPTOGRAFICZNY MOST — MQTT → InfluxDB + Blockchain{Kol.RESET}")
    print(f"{Kol.BOLD}  Broker: {MQTT_BROKER}:{MQTT_PORT}{Kol.RESET}")
    print(f"{Kol.BOLD}  Sub:    {TOPIK_SECURITY_DANE}{Kol.RESET}")
    print(f"{Kol.BOLD}           {TOPIK_ENV_DANE}{Kol.RESET}")
    print(f"{Kol.BOLD}{Kol.NIEBIESKI}{'═' * 64}{Kol.RESET}\n")

    klient = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    klient.on_connect    = przy_polaczeniu
    klient.on_disconnect = przy_rozlaczeniu
    klient.on_message    = przy_wiadomosci

    while True:
        try:
            log("MQTT", f"Laczenie z {MQTT_BROKER}:{MQTT_PORT}...")
            klient.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
            klient.loop_forever()
        except (ConnectionRefusedError, OSError):
            log("BLAD", "Broker MQTT niedostepny — ponowna proba za 5s")
            time.sleep(5)
        except KeyboardInterrupt:
            log("INFO", "Zatrzymano (CTRL+C)")
            klient.disconnect()
            break
        except Exception as ex:
            log("BLAD", f"Nieoczekiwany blad: {ex} — ponawiam za 5s")
            time.sleep(5)


if __name__ == "__main__":
    main()
