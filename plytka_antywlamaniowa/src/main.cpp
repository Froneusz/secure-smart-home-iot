#include <Arduino.h>
#include <SPI.h>
#include <MFRC522.h>
#include <Keypad.h>
#include <Wire.h>
#include <Adafruit_Sensor.h>
#include <Adafruit_ADXL345_U.h>
#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <base64.h>
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"

// =======================================================
// WYBOR ALGORYTMU SZYFROWANIA
// 0 = Czysty tekst     1 = Base64      2 = Szyfr Cezara
// 3 = XOR (klucz "1234")   4 = Vigenere ("TAJNE")
// 5 = RC4              6 = AES-128-ECB 7 = AES-128-CBC
// 8 = AES-128-GCM (uwierzytelnione, tag 16B na koncu)
// Mozna zmienic przez MQTT: wyslij cyfre 0-8 na topicSetAlgorytm
// =======================================================
int WYBRANY_ALGORYTM = 0;

// --- KONFIGURACJA SIECI ---
const char* ssid       = "TWOJE_SSID";          // <-- uzupelnij przed flashowaniem
const char* hasloWifi  = "TWOJE_HASLO_WIFI";    // <-- uzupelnij przed flashowaniem
const char* serwerMqtt = "IP_RASPBERRY_PI";     // <-- adres IP Raspberry Pi w sieci lokalnej
const char* topicAlarm      = "/plytka_antywlamaniowa/zaszyfrowane";
const char* topicOnline     = "/plytka_antywlamaniowa/online";
const char* topicSetAlgorytm = "/plytka_antywlamaniowa/set_algorytm";  // odbiór: "0"–"8"

WiFiClient   klientWifi;
PubSubClient klientMqtt(klientWifi);

// --- PINY ---
// GPIO34 i GPIO35 to piny tylko-wejsciowe (input-only) — nie mozna ich skonfigurowac jako wyjscie
#define PIR_PIN    34  // input-only
#define REED_PIN   35  // input-only; brak wewnetrznego pullupa — zewnetrzny 10kΩ do 3.3V; uzyj INPUT
#define BUZZER_PIN 15

// MFRC522 (SPI): SS=GPIO5, SCK=GPIO18, MOSI=GPIO23, MISO=GPIO19 (domyslne SPI ESP32), RST=GPIO4; IRQ niepodlaczony
#define RFID_SS   5
#define RFID_RST  4

// --- KLAWIATURA 4x4 ---
const byte WIERSZE = 4;
const byte KOLUMNY = 4;
char klawisze[WIERSZE][KOLUMNY] = {
  {'1','2','3','A'},
  {'4','5','6','B'},
  {'7','8','9','C'},
  {'*','0','#','D'}
};
byte pinyWierszy[WIERSZE] = {32, 33, 25, 26};  // R1=32, R2=33, R3=25, R4=26
byte pinyKolumn[KOLUMNY]  = {27, 14, 13, 12};  // C1=27, C2=14, C3=13, C4=12
Keypad klawiatura = Keypad(makeKeymap(klawisze), pinyWierszy, pinyKolumn, WIERSZE, KOLUMNY);

// ADXL345 (I2C): SDA=GPIO21, SCL=GPIO22; CS->3.3V (wymusza tryb I2C), SDO->GND (adres 0x53)
MFRC522 rfid(RFID_SS, RFID_RST);
byte masterUID[] = {0x4A, 0x81, 0x4D, 0x06};
Adafruit_ADXL345_Unified akcelerometr = Adafruit_ADXL345_Unified(12345);

// --- STANY SYSTEMU ALARMOWEGO ---
enum StanAlarmu { ROZBROJONY, UZBRAJANIE, CZUWA, OCZEKUJE, ALARM };
StanAlarmu aktualnyStanAlarmu = ROZBROJONY;
String kodWejsciowy = "";

// --- PARAMETRY CZASOWE [ms] ---
unsigned long timerStanu = 0;
const unsigned long CZAS_WYJSCIA             = 3000;
const unsigned long CZAS_WEJSCIA             = 5000;
const unsigned long INTERWAL_RAPORTU         = 15000;  // 15s — balans: dashboard zywy, RPi nie przeciazony
const unsigned long INTERWAL_HEARTBEAT       = 10000;
const unsigned long CZAS_POTWIERDZENIA_RUCHU = 1000;  // debounce PIR

// --- PROG CZULOCI AKCELEROMETRU ---
const float PROG_WSTRZASU = 3.0;  // [m/s²] na osi X; wyreguluj pod instalacje

// --- OCHRONA PRZED BRUTE-FORCE PIN ---
const byte          MAKS_BLEDNYCH_PROB = 3;
const unsigned long CZAS_BLOKADY      = 30000;  // 30s blokady klawiatury po N bledach
byte          licznikBledow = 0;
unsigned long czasBlokady   = 0;  // 0 = brak aktywnej blokady

// --- PARAMETRY POLACZEN ---
unsigned long ostatniRaport    = 0;
unsigned long ostatniHeartbeat = 0;
unsigned long czasRuchuPir     = 0;
unsigned long ostatniProbaWifi = 0;

// --- CACHE OSTATNIO WYSLANYCH WARTOSCI (wykrywanie zmian/zdarzen) ---
StanAlarmu ostatniWyslanyStan = ROZBROJONY;
int   ostatniStanPir  = -1;
int   ostatniStanReed = -1;
float ostatniAccX = 0.0, ostatniAccY = 0.0, ostatniAccZ = 0.0;

// Klucz AES-128 — musi byc identyczny z KLUCZ_AES w mqtt_to_influx.py
const unsigned char KLUCZ_AES[16] = {
  '1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6'
};

// --- DEKLARACJE ---
void konfigurujWifi();
void polaczMqtt();
String pobierzNazwStanu(StanAlarmu stan);
inline void dodajHex(String &s, unsigned char bajt);
void zaszyfruj(const char* dane, int dlugosc, int algorytm, String &wynik);
void wyslijMqtt(int pir, int reed, float ax, float ay, float az);
void obsluzKlawiature();
void obsluzRfid();

// Odbiera numer algorytmu przez MQTT — zmiana bez reflashowania urzadzenia
void wywolanieMqtt(char* topic, byte* payload, unsigned int dlugosc) {
  String wiadomosc = "";
  for (unsigned int i = 0; i < dlugosc; i++) wiadomosc += (char)payload[i];
  int nowyAlgorytm = wiadomosc.toInt();
  if (nowyAlgorytm >= 0 && nowyAlgorytm <= 8) {
    WYBRANY_ALGORYTM = nowyAlgorytm;
    Serial.print("[MQTT] Zmieniono algorytm na: "); Serial.println(WYBRANY_ALGORYTM);
  }
}

void setup() {
  Serial.begin(115200);

  pinMode(PIR_PIN,    INPUT);
  pinMode(REED_PIN,   INPUT);   // INPUT — GPIO35 nie ma wewnetrznego pullupa
  pinMode(BUZZER_PIN, OUTPUT);

  SPI.begin();
  rfid.PCD_Init();
  Wire.begin(21, 22);  // SDA=GPIO21, SCL=GPIO22 dla ADXL345

  if (!akcelerometr.begin()) Serial.println("Blad: Nie znaleziono ADXL345!");

  kodWejsciowy.reserve(5);

  konfigurujWifi();
  klientMqtt.setServer(serwerMqtt, 1883);
  klientMqtt.setBufferSize(1024);
  klientMqtt.setCallback(wywolanieMqtt);

  Serial.println("System uruchomiony.");
}

void konfigurujWifi() {
  delay(10);
  Serial.print("Lacze z WiFi...");
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, hasloWifi);
  while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
  Serial.println(" OK");
  Serial.println(WiFi.localIP());
}

void polaczMqtt() {
  if (!klientMqtt.connected()) {
    String idKlienta = "ESP32-Alarm-" + String(random(0xffff), HEX);
    // LWT: broker sam opublikuje "offline" gdy urzadzenie zniknie bez rozlaczenia (reset, zanik zasil.)
    if (klientMqtt.connect(idKlienta.c_str(), NULL, NULL, topicOnline, 0, true, "offline")) {
      klientMqtt.publish(topicOnline, "online", true);  // retained — widoczne dla nowych subskrybentow
      klientMqtt.subscribe(topicSetAlgorytm);
      Serial.println("Polaczono z MQTT.");
    }
  }
}

String pobierzNazwStanu(StanAlarmu stan) {
  switch (stan) {
    case ROZBROJONY: return "rozbrojony";
    case UZBRAJANIE: return "uzbrajanie";
    case CZUWA:      return "czuwa";
    case OCZEKUJE:   return "oczekuje_na_rfid";
    case ALARM:      return "ALARM";
    default:         return "nieznany";
  }
}

// Szybszy od sprintf("%02x") — unika parsowania stringa formatu przy kazdym bajcie
inline void dodajHex(String &s, unsigned char bajt) {
  static const char ZNAKI_HEX[] = "0123456789abcdef";
  s += ZNAKI_HEX[(bajt >> 4) & 0x0F];
  s += ZNAKI_HEX[bajt & 0x0F];
}

// =================================================================
// SILNIK KRYPTOGRAFICZNY
// Szyfruje dane wybranym algorytmem, wynik zapisuje do `wynik`
// przez referencje (unika kopiowania Stringa)
// =================================================================
void zaszyfruj(const char* dane, int dlugosc, int algorytm, String &wynik) {
  wynik = "";
  wynik.reserve(dlugosc * 2 + 32);

  int dlugoscZPaddingiem = dlugosc + (16 - (dlugosc % 16));
  unsigned char buforDanych[256]      = {0};
  unsigned char buforSzyfrogramu[256] = {0};

  switch (algorytm) {

    case 0:
      wynik = dane;
      return;

    case 1:
      wynik = base64::encode((const uint8_t*)dane, dlugosc);
      return;

    case 2:  // rotacja w przestrzeni drukowalnych ASCII (32–126)
      for (int i = 0; i < dlugosc; ++i) {
        char c = dane[i];
        wynik += (c >= 32 && c <= 126) ? (char)((c - 32 + 3) % 95 + 32) : c;
      }
      return;

    case 3:
      {
        const char kluczXor[] = "1234";
        for (int i = 0; i < dlugosc; ++i)
          dodajHex(wynik, (unsigned char)(dane[i] ^ kluczXor[i & 3]));
      }
      return;

    case 4:
      {
        const char kluczVig[] = "TAJNE";
        for (int i = 0; i < dlugosc; ++i) {
          char c = dane[i];
          int przesuniecie = kluczVig[i % 5] - 32;
          wynik += (c >= 32 && c <= 126) ? (char)((c - 32 + przesuniecie) % 95 + 32) : c;
        }
      }
      return;

    case 5:
      {
        const char kluczRc4[] = "1234567890123456";
        unsigned char S[256];
        for (int i = 0; i < 256; ++i) S[i] = i;

        // KSA (Key Scheduling Algorithm)
        int j = 0;
        for (int i = 0; i < 256; ++i) {
          j = (j + S[i] + kluczRc4[i & 15]) % 256;
          std::swap(S[i], S[j]);
        }

        // PRGA (Pseudo-Random Generation Algorithm)
        int iRc = 0, jRc = 0;
        for (int n = 0; n < dlugosc; ++n) {
          iRc = (iRc + 1) % 256;
          jRc = (jRc + S[iRc]) % 256;
          std::swap(S[iRc], S[jRc]);
          unsigned char K = S[(S[iRc] + S[jRc]) % 256];
          dodajHex(wynik, (unsigned char)(dane[n] ^ K));
        }
      }
      return;

    case 6:  // ECB: identyczne bloki plaintext → identyczne bloki szyfrogramu — slaba dyfuzja
      {
        mbedtls_aes_context kontekstAes;
        mbedtls_aes_init(&kontekstAes);
        mbedtls_aes_setkey_enc(&kontekstAes, KLUCZ_AES, 128);
        memcpy(buforDanych, dane, dlugosc);
        unsigned char wartoscPaddingu = dlugoscZPaddingiem - dlugosc;
        memset(buforDanych + dlugosc, wartoscPaddingu, wartoscPaddingu);
        for (int i = 0; i < dlugoscZPaddingiem; i += 16)
          mbedtls_aes_crypt_ecb(&kontekstAes, MBEDTLS_AES_ENCRYPT,
                                buforDanych + i, buforSzyfrogramu + i);
        for (int i = 0; i < dlugoscZPaddingiem; ++i) dodajHex(wynik, buforSzyfrogramu[i]);
        mbedtls_aes_free(&kontekstAes);
      }
      return;

    case 7:  // CBC: zerowy IV — uproszczenie badawcze; w produkcji IV musi byc losowy
      {
        mbedtls_aes_context kontekstAesCbc;
        mbedtls_aes_init(&kontekstAesCbc);
        mbedtls_aes_setkey_enc(&kontekstAesCbc, KLUCZ_AES, 128);
        unsigned char wektorIV[16] = {0};
        memcpy(buforDanych, dane, dlugosc);
        unsigned char wartoscPaddingu = dlugoscZPaddingiem - dlugosc;
        memset(buforDanych + dlugosc, wartoscPaddingu, wartoscPaddingu);
        mbedtls_aes_crypt_cbc(&kontekstAesCbc, MBEDTLS_AES_ENCRYPT,
                              dlugoscZPaddingiem, wektorIV, buforDanych, buforSzyfrogramu);
        for (int i = 0; i < dlugoscZPaddingiem; ++i) dodajHex(wynik, buforSzyfrogramu[i]);
        mbedtls_aes_free(&kontekstAesCbc);
      }
      return;

    case 8:  // GCM: tag 16B na koncu HEX; staly nonce — w produkcji unikalny per wiadomosc
      {
        mbedtls_gcm_context kontekstGcm;
        mbedtls_gcm_init(&kontekstGcm);
        mbedtls_gcm_setkey(&kontekstGcm, MBEDTLS_CIPHER_ID_AES, KLUCZ_AES, 128);
        unsigned char nonce[12]          = {1,2,3,4,5,6,7,8,9,10,11,12};
        unsigned char tagAutentykacji[16];
        mbedtls_gcm_crypt_and_tag(&kontekstGcm, MBEDTLS_GCM_ENCRYPT, dlugosc,
                                  nonce, sizeof(nonce), NULL, 0,
                                  (const unsigned char*)dane, buforSzyfrogramu,
                                  16, tagAutentykacji);
        for (int i = 0; i < dlugosc; ++i) dodajHex(wynik, buforSzyfrogramu[i]);
        for (int i = 0; i < 16; ++i)      dodajHex(wynik, tagAutentykacji[i]);
        mbedtls_gcm_free(&kontekstGcm);
      }
      return;
  }
}

// Mierzy czas szyfrowania [us], narzut rozmiaru [%] i wolny heap [B]
// Dane zbierane przez Serial do tabel porowawczych w pracy magisterskiej
void wyslijMqtt(int pir, int reed, float ax, float ay, float az) {
  if (!klientMqtt.connected()) return;

  JsonDocument doc;
  doc["status"] = pobierzNazwStanu(aktualnyStanAlarmu);
  doc["pir"]    = pir;
  doc["drzwi"]  = reed;
  JsonObject acc = doc["akcelerometr"].to<JsonObject>();
  acc["x"] = round(ax * 100.0) / 100.0;
  acc["y"] = round(ay * 100.0) / 100.0;
  acc["z"] = round(az * 100.0) / 100.0;

  char buforJson[256];
  int dlugoscJson = serializeJson(doc, buforJson, sizeof(buforJson));

  Serial.println("\n==================================================");
  Serial.print("[PROFILOWANIE - ALGORYTM "); Serial.print(WYBRANY_ALGORYTM); Serial.println("]");
  Serial.print("-> Dane surowe JSON: "); Serial.println(buforJson);
  Serial.print("-> Rozmiar surowy: ");  Serial.print(dlugoscJson); Serial.println(" B");

  String daneSzyfr = "";
  unsigned long czasStart    = micros();
  zaszyfruj(buforJson, dlugoscJson, WYBRANY_ALGORYTM, daneSzyfr);
  unsigned long czasWykonania = micros() - czasStart;

  size_t wolnyRam = ESP.getFreeHeap();

  // Format: "<nr_algorytmu>:<szyfrogram>" — serwer parsuje prefiks i wywoluje odpowiedni deszyfrator
  String finalnyPayload  = String(WYBRANY_ALGORYTM) + ":" + daneSzyfr;
  size_t rozmiarFinalny  = finalnyPayload.length();
  float procentowyNarzut = ((float)(rozmiarFinalny - dlugoscJson) / dlugoscJson) * 100.0;

  Serial.print("-> Szyfrogram: ");              Serial.println(finalnyPayload);
  Serial.print("-> Rozmiar po szyfrowaniu: ");  Serial.print(rozmiarFinalny); Serial.println(" B");
  Serial.print("-> 1. CZAS SZYFROWANIA: ");     Serial.print(czasWykonania); Serial.println(" us");
  Serial.print("-> 2. NARZUT PRZESYLU: +");     Serial.print(procentowyNarzut, 2); Serial.println("%");
  Serial.print("-> 3. WOLNY RAM (heap): ");     Serial.print(wolnyRam); Serial.println(" B");
  Serial.println("==================================================");

  klientMqtt.publish(topicAlarm, finalnyPayload.c_str());
}

// '*' kasuje bufor kodu; klawiatura aktywna tylko w stanie ROZBROJONY
void obsluzKlawiature() {
  char klawisz = klawiatura.getKey();
  if (!klawisz || aktualnyStanAlarmu != ROZBROJONY) return;

  // Blokada po MAKS_BLEDNYCH_PROB blednych probach — obrona przed brute-force
  if (czasBlokady) {
    if (millis() - czasBlokady < CZAS_BLOKADY) {
      Serial.println("[PIN] ZABLOKOWANE. Poczekaj przed kolejna proba.");
      return;
    }
    czasBlokady   = 0;
    licznikBledow = 0;
    Serial.println("[PIN] Odblokowano.");
  }

  if (klawisz == '*') {
    kodWejsciowy = "";
    Serial.println("\n[PIN] Wyczyszczono.");
    digitalWrite(BUZZER_PIN, HIGH); delay(50); digitalWrite(BUZZER_PIN, LOW);
    return;
  }

  digitalWrite(BUZZER_PIN, HIGH); delay(20); digitalWrite(BUZZER_PIN, LOW);
  kodWejsciowy += klawisz;
  Serial.print("*");

  if (kodWejsciowy.length() >= 4) {
    if (kodWejsciowy == "1234") {
      aktualnyStanAlarmu = UZBRAJANIE;
      timerStanu         = millis();
      licznikBledow      = 0;
      czasBlokady        = 0;
      digitalWrite(BUZZER_PIN, HIGH); delay(500); digitalWrite(BUZZER_PIN, LOW);
      Serial.println("\n[PIN] Poprawny! Masz 3s na wyjscie.");
    } else {
      licznikBledow++;
      Serial.print("\n[PIN] Bledny kod! Proba ");
      Serial.print(licznikBledow); Serial.print("/"); Serial.println(MAKS_BLEDNYCH_PROB);
      digitalWrite(BUZZER_PIN, HIGH); delay(100); digitalWrite(BUZZER_PIN, LOW);
      delay(50);
      digitalWrite(BUZZER_PIN, HIGH); delay(100); digitalWrite(BUZZER_PIN, LOW);

      if (licznikBledow >= MAKS_BLEDNYCH_PROB) {
        czasBlokady = millis();
        Serial.println("[PIN] KLAWIATURA ZABLOKOWANA na 30s!");
        delay(50);
        digitalWrite(BUZZER_PIN, HIGH); delay(100); digitalWrite(BUZZER_PIN, LOW);
      }
    }
    kodWejsciowy = "";
  }
}

// Porownuje 4 bajty UID z masterUID; rozbrajanie dziala z kazdego stanu (takze ALARM)
void obsluzRfid() {
  if (!rfid.PICC_IsNewCardPresent() || !rfid.PICC_ReadCardSerial()) return;

  bool zgodnosc = true;
  for (byte i = 0; i < 4; i++) {
    if (rfid.uid.uidByte[i] != masterUID[i]) { zgodnosc = false; break; }
  }

  if (zgodnosc) {
    aktualnyStanAlarmu = ROZBROJONY;
    licznikBledow      = 0;
    czasBlokady        = 0;
    digitalWrite(BUZZER_PIN, LOW);  // wyciszenie — buzzer mógl byc aktywny w trybie ALARM
    Serial.println("\n[RFID] Autoryzacja OK. System rozbrojony.");
  } else {
    Serial.println("\n[RFID] Zla karta - odmowa dostepu.");
  }

  rfid.PICC_HaltA();
}

void loop() {
  // WiFi watchdog — throttlowany co 5s, zeby nie floodowac stosu TCP
  if (WiFi.status() != WL_CONNECTED && millis() - ostatniProbaWifi >= 5000) {
    Serial.println("[WiFi] Brak polaczenia. Ponawiam...");
    WiFi.reconnect();
    ostatniProbaWifi = millis();
  }

  if (!klientMqtt.connected()) polaczMqtt();
  klientMqtt.loop();

  if (millis() - ostatniHeartbeat >= INTERWAL_HEARTBEAT) {
    if (klientMqtt.connected()) klientMqtt.publish(topicOnline, "online", true);
    ostatniHeartbeat = millis();
  }

  obsluzKlawiature();
  obsluzRfid();

  int aktualnyPir  = digitalRead(PIR_PIN);
  int aktualnyReed = digitalRead(REED_PIN);
  sensors_event_t zdarzenie;
  akcelerometr.getEvent(&zdarzenie);
  float akX = zdarzenie.acceleration.x;
  float akY = zdarzenie.acceleration.y;
  float akZ = zdarzenie.acceleration.z;

  bool wymusPublikacje = false;

  if (aktualnyStanAlarmu != ostatniWyslanyStan) wymusPublikacje = true;

  if (aktualnyStanAlarmu == CZUWA ||
      aktualnyStanAlarmu == OCZEKUJE ||
      aktualnyStanAlarmu == ALARM) {
    if (aktualnyPir  != ostatniStanPir)  wymusPublikacje = true;
    if (aktualnyReed != ostatniStanReed) wymusPublikacje = true;
    if (abs(akX - ostatniAccX) > 1.5 ||
        abs(akY - ostatniAccY) > 1.5 ||
        abs(akZ - ostatniAccZ) > 1.5)   wymusPublikacje = true;
  }

  switch (aktualnyStanAlarmu) {

    case ROZBROJONY:
      break;

    case UZBRAJANIE:
      if (millis() - timerStanu >= CZAS_WYJSCIA) {
        aktualnyStanAlarmu = CZUWA;
        Serial.println("[STAN] System uzbrojony - czuwa.");
        digitalWrite(BUZZER_PIN, HIGH); delay(200); digitalWrite(BUZZER_PIN, LOW);
      }
      break;

    case CZUWA:
      {
        // Debounce PIR: sygnal musi byc ciagly przez CZAS_POTWIERDZENIA_RUCHU
        // Eliminuje falszywe alarmy od krotkich zaklocen EMI na przewodzie PIR
        bool prawdziwyRuch = false;
        if (digitalRead(PIR_PIN) == HIGH) {
          if (czasRuchuPir == 0) czasRuchuPir = millis();
          if (millis() - czasRuchuPir >= CZAS_POTWIERDZENIA_RUCHU) prawdziwyRuch = true;
        } else {
          czasRuchuPir = 0;
        }

        if (prawdziwyRuch || digitalRead(REED_PIN) == HIGH || abs(akX) > PROG_WSTRZASU) {
          aktualnyStanAlarmu = OCZEKUJE;
          timerStanu         = millis();
          Serial.println("[STAN] Intruz wykryty! 5s na autoryzacje karta RFID.");
          digitalWrite(BUZZER_PIN, HIGH); delay(50); digitalWrite(BUZZER_PIN, LOW);
        }
      }
      break;

    case OCZEKUJE:
      if (millis() - timerStanu >= CZAS_WEJSCIA) {
        aktualnyStanAlarmu = ALARM;
        Serial.println("[STAN] ALARM WYZWOLONY!");
      }
      break;

    case ALARM:
      // Oscylator na millis — nieblokujacy, nie zatrzymuje petli
      digitalWrite(BUZZER_PIN, (millis() / 500) % 2);
      break;
  }

  // Drugi sprawdzenie — stan mogl sie zmienic w switch powyzej
  if (aktualnyStanAlarmu != ostatniWyslanyStan) wymusPublikacje = true;

  if (wymusPublikacje || (millis() - ostatniRaport >= INTERWAL_RAPORTU)) {
    wyslijMqtt(aktualnyPir, aktualnyReed, akX, akY, akZ);
    ostatniRaport      = millis();
    ostatniWyslanyStan = aktualnyStanAlarmu;
    ostatniStanPir     = aktualnyPir;
    ostatniStanReed    = aktualnyReed;
    ostatniAccX        = akX;
    ostatniAccY        = akY;
    ostatniAccZ        = akZ;
  }
}
