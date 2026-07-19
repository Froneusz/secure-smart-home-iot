# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Project Overview

Magisterska praca badawcza dotycząca bezpieczeństwa IoT — porównanie algorytmów szyfrowania
na urządzeniach wbudowanych oraz analiza odporności systemu na ataki sieciowe i fizyczne.
System składa się z dwóch płytek ESP32, brokera MQTT, bazy InfluxDB, panelu webowego Flask
i integracji z blockchainem na Raspberry Pi.

**Autor:** Inżynier elektroniki i telekomunikacji, specjalizacja edge computing i IoT  
**Stack:** PlatformIO (ESP32 x2), Python, Flask, InfluxDB, Mosquitto, Blockchain

---

## Hardware — obie płytki to ESP32 DevKitC 32E v4

### Płytka antywłamaniowa (`plytka_antywlamaniowa/`)

| Peryferie | Interfejs | Piny |
|-----------|-----------|------|
| ADXL345 (akcelerometr) | I2C | SDA=GPIO21, SCL=GPIO22; CS→3.3V (tryb I2C), SDO→GND → adres 0x53 |
| MFRC522 (RFID) | SPI | SS=GPIO5, SCK=GPIO18, MOSI=GPIO23, MISO=GPIO19, RST=GPIO4; IRQ niepodłączony |
| PIR (czujnik ruchu) | Digital IN | GPIO34 — **input-only** |
| Reed switch (drzwi/okno) | Digital IN | GPIO35 — **input-only**, brak pullupa wewn.; zewnętrzny 10kΩ do 3.3V; `INPUT` nie `INPUT_PULLUP` |
| Buzzer | Digital OUT | GPIO15 |
| Klawiatura 4x4 — wiersze | Digital I/O | R1=GPIO32, R2=GPIO33, R3=GPIO25, R4=GPIO26 |
| Klawiatura 4x4 — kolumny | Digital I/O | C1=GPIO27, C2=GPIO14, C3=GPIO13, C4=GPIO12 |

**kartaWzorcowa (RFID):** `{0x4A, 0x81, 0x4D, 0x06}` — musi odpowiadać fizycznej karcie.  
**PIN alarmu (kodPin):** `"1234"` (hardcoded) — blokada po 3 błędnych próbach (30s).

### Płytka środowiskowa (`plytka_srodowiskowa/`)

| Peryferie | Interfejs | Piny |
|-----------|-----------|------|
| BME280 (temp/wilg/ciśn) | I2C0 (TwoWire 0) | SDA=GPIO4, SCL=GPIO5; adres 0x76 |
| BH1750 (natężenie światła) | I2C1 (TwoWire 1) | SDA=GPIO25, SCL=GPIO26; adres 0x23 |
| MQ135 (jakość powietrza) | ADC | GPIO36 (VP/ADC1_CH0) — **input-only**, max 3.3V; odczyt 0–4095 (12-bit) |
| Mikrofon (moduł dźwiękowy) | Digital IN | GPIO14; HIGH = wykryty dźwięk |

**Uwaga:** ESP32 ma dwa sprzętowe I2C — `TwoWire(0)` i `TwoWire(1)` inicjalizowane raz w `setup()`, bez reinicjalizacji w `loop()`.

---

## Architecture

```
[ESP32 - plytka_antywlamaniowa]        [ESP32 - plytka_srodowiskowa]
   PIR, Reed switch, ADXL345               BME280, BH1750, MQ135, Mikrofon
   RFID (MFRC522), Klawiatura 4x4          Silnik kryptograficzny (algo 0-8)
   Silnik kryptograficzny (algo 0-8)              |
   Maszyna stanów alarmowych                      |
          |                                        |
          └──────────── MQTT (port 1883) ──────────┘
                                  |
                        [Raspberry Pi]
                   mqtt_to_influx.py  ←→  Mosquitto broker
                        |     |
                   InfluxDB   app.py (Flask + TLS, port 5000)
                                    |
                             Przeglądarka (Panel Live Monitor)
                                    |
                             Blockchain (logi / podpisy)
```

---

## MQTT Topics

### Płytka antywłamaniowa

| Topic | Kierunek | Opis |
|-------|----------|------|
| `/plytka_antywlamaniowa/zaszyfrowane` | PUB | Zaszyfrowany payload JSON — format `<nr>:<hex>` |
| `/plytka_antywlamaniowa/online` | PUB retained | Heartbeat co 10s; LWT = `"offline"` |
| `/plytka_antywlamaniowa/set_algorytm` | SUB | Zmiana algorytmu w locie — wyślij cyfrę `"0"`–`"8"` |

### Płytka środowiskowa

| Topic | Kierunek | Opis |
|-------|----------|------|
| `/plytka_srodowiskoa/zaszyfrowane` | PUB | Zaszyfrowany payload JSON — format `<nr>:<hex>` |
| `/plytka_srodowiskoa/online` | PUB retained | Heartbeat co 10s; LWT = `"offline"` |
| `/plytka_srodowiskoa/set_algorytm` | SUB | Zmiana algorytmu w locie — wyślij cyfrę `"0"`–`"8"` |

> **Uwaga:** literówka `srodowiskoa` (brak `w`) — zachowana celowo dla kompatybilności z istniejącą subskrypcją brokera.

---

## Payload Protocol

Obie płytki wysyłają wiadomości MQTT w formacie `<numer_algorytmu>:<payload>`,
np. `6:3f8a...`. `mqtt_to_influx.py` parsuje prefix i wywołuje odpowiedni deszyfrator.

### Tabela algorytmów (obie płytki — identyczny silnik)

| Nr | Algorytm |
|----|----------|
| 0  | Czysty tekst |
| 1  | Base64 |
| 2  | Szyfr Cezara (przesunięcie 3, ASCII 32–126) |
| 3  | XOR (klucz: `"1234"`) |
| 4  | Vigenère (klucz: `"TAJNE"`) |
| 5  | RC4 (klucz: `"1234567890123456"`) |
| 6  | AES-128-ECB (mbedTLS, PKCS7) |
| 7  | AES-128-CBC (mbedTLS, PKCS7, IV=0) |
| 8  | AES-128-GCM (mbedTLS, nonce stały, tag 16B na końcu) |

**Zmiana algorytmu:**
- Przez MQTT: wyślij cyfrę `"0"`–`"8"` na topic `set_algorytm` (bez reflashowania)
- Przez kod: edytuj `volatile int wybranyAlgorytm = X;` w `src/main.cpp`

**Klucz AES:** `"1234567890123456"` (16B) — musi być identyczny z `kluczAes` w `main.cpp` i `KLUCZ_AES` w `mqtt_to_influx.py`.

---

## Build & Flash (PlatformIO)

```bash
# Płytka antywłamaniowa (ESP32)
cd plytka_antywlamaniowa
pio run                    # kompilacja
pio run --target upload    # wgranie
pio device monitor         # monitor szeregowy (115200 baud)

# Płytka środowiskowa (ESP32)
cd plytka_srodowiskowa
pio run
pio run --target upload
pio device monitor
```

---

## Run (Raspberry Pi)

```bash
# Broker MQTT musi być uruchomiony (Mosquitto, port 1883)
cd RPI
python mqtt_to_influx.py   # bridge MQTT → InfluxDB (uruchom w tle)
python app.py              # panel Flask (HTTPS, port 5000)

# Generowanie certyfikatu TLS:
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
# Wymaga: cert.pem i key.pem w katalogu RPI/
```

---

## Key Configuration

**Przed flashowaniem obu ESP32** uzupełnij w `src/main.cpp`:
- `ssid`, `hasloWifi`, `serwerMqtt`

**Przed uruchomieniem RPi** uzupełnij w plikach Python:
- `mqtt_to_influx.py`: `AES_KEY`, `token`, `org`, `bucket`, `url`
- `app.py`: `app.secret_key`, `INFLUX_TOKEN`, `INFLUX_ORG`, `INFLUX_BUCKET`, `INFLUX_URL`

---

## Profiling (Serial output)

Po każdym wysłaniu MQTT **obie płytki** drukują przez Serial (format identyczny):
```
==================================================
[PROFILOWANIE - ALGORYTM X]
-> Dane surowe JSON: {...}
-> Rozmiar surowy: N B
-> Szyfrogram: X:<hex>
-> Rozmiar po szyfrowaniu: N B
-> 1. CZAS SZYFROWANIA: N us
-> 2. NARZUT PRZESYLU: +N%
-> 3. WOLNY RAM (heap): N B
==================================================
```
Główny mechanizm zbierania danych porównawczych do pracy magisterskiej.

---

## RBAC Panel webowy

- `admin` / `admin` → pełny podgląd + eksport CSV
- `login` / `login` → tylko zaszyfrowany payload (bez deszyfrowania)

Panel odświeża się co 10 s, dane z ostatniej godziny z InfluxDB (pomiar `pomiary_srodowiskowe`).

---

## Plan realizacji

### Faza 1 — Hardware & Firmware ✓
- [x] Firmware — silnik kryptograficzny (algo 0–8), profiling przez Serial
- [x] MQTT LWT + heartbeat + WiFi watchdog na obu płytkach
- [x] Zmiana algorytmu przez MQTT (bez reflashowania)
- [x] Ochrona przed brute-force PIN (blokada 30s po 3 błędach)
- [ ] Montaż i uruchomienie prototypów sprzętowych

### Faza 2 — Serwer & Backend
- [ ] MQTT Broker na RPi (Mosquitto)
- [ ] mqtt_to_influx.py — odbiór, deszyfrowanie (algo 0–8), zapis do InfluxDB
- [ ] Flask frontend z RBAC

### Faza 3 — Blockchain
- [ ] Zapis logów / podpisów do blockchain
- [ ] Weryfikacja hashy i niezmienności danych

### Faza 4 — Testy bezpieczeństwa

#### 4.1 Analiza kryptograficzna
- [ ] Wydajność czasowa — czas szyfrowania per algorytm (µs, dane z Serial)
- [ ] Zasoby sprzętowe — RAM/Flash/CPU na ESP32 per algorytm
- [ ] Narzut na przesył — rozmiar payload przed/po szyfrowaniu

#### 4.2 Ataki sieciowe (Wireshark)
- [ ] Sniffing — przechwycenie niezaszyfrowanego MQTT (algo 0)
- [ ] Replay Attack — ponowne wysłanie przechwyconego pakietu
- [ ] Atak DoS — flood na broker MQTT

#### 4.3 Bezpieczeństwo sprzętowe
- [ ] Kradzież klucza z pamięci Flash (`esptool read_flash`)
- [ ] Fizyczny sabotaż — reakcja systemu na ingerencję

#### 4.4 Niezmienność danych (Blockchain)
- [ ] Zatrucie bazy danych — modyfikacja InfluxDB z pominięciem blockchain
- [ ] Weryfikacja hashy — detekcja manipulacji

#### 4.5 Ataki na interfejsy fizyczne
- [ ] Brute-force PIN-u (klawiatura 4x4) — zaimplementowana blokada jako punkt odniesienia
- [ ] Klonowanie RFID (Proxmark / smartphone NFC)

#### 4.6 Dodatkowe analizy (opcjonalne)
- [ ] Side-channel power analysis — pomiar prądu ESP32 podczas szyfrowania
      (oscyloskop lub INA219) — różne algorytmy zostawiają różny ślad energetyczny
- [ ] OTA security — test czy można wgrać niepodpisany firmware przez OTA update
- [ ] Anomaly detection — detektor anomalii w danych czujników (3-sigma rule)
      przed zapisem do blockchain

### Faza 5 — Frontend real-time
- [ ] Dashboard — stan czujników na żywo
- [ ] Potwierdzenia z blockchain
- [ ] RBAC (admin / read-only)

### Faza 6 — Analiza wyników i praca pisemna
- [ ] Tabele porównawcze algorytmów (czas, RAM, bezpieczeństwo)
- [ ] Wnioski z testów ataków
- [ ] Rekomendacje dla systemów IoT
