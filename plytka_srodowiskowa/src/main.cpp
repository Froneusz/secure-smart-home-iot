#include <Arduino.h>
#include <WiFi.h>
#include <PubSubClient.h>
#include <Wire.h>
#include <Adafruit_Sensor.h>
#include <Adafruit_BME280.h>
#include <BH1750.h>
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

// Literowka "srodowiskoa" w topiku — zachowana celowo dla kompatybilnosci z subskrypcja brokera
const char* topicAlarm       = "/plytka_srodowiskoa/zaszyfrowane";
const char* topicOnline      = "/plytka_srodowiskoa/online";
const char* topicSetAlgorytm = "/plytka_srodowiskoa/set_algorytm";  // odbiór: "0"–"8"

// Klucz AES-128 — musi byc identyczny z KLUCZ_AES w mqtt_to_influx.py
const unsigned char KLUCZ_AES[16] = {
  '1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6'
};

// --- PINY ---
// GPIO36 (VP) = ADC1_CH0; input-only, max 3.3V — nie podlaczac wyzszego napiecia
#define MQ135_PIN 36  // czujnik gazow; odczyt 0–4095 (12-bit ADC ESP32)
#define SOUND_PIN 14  // modul mikrofonu; HIGH = wykryty dzwiek

// BME280: I2C0 — SDA=GPIO4, SCL=GPIO5 (zweryfikowane kodem diagnostycznym)
#define I2C1_SDA  4
#define I2C1_SCL  5

// BH1750: I2C1 — SDA=GPIO25, SCL=GPIO26
// ESP32 ma dwa sprzetowe peryferial I2C — uzywamy TwoWire(0) i TwoWire(1) bez reinicjalizacji Wire
#define I2C2_SDA 25
#define I2C2_SCL 26

TwoWire magistrala1(0);  // I2C0: BME280
TwoWire magistrala2(1);  // I2C1: BH1750

Adafruit_BME280 czujnikBme;
BH1750          miernikSwiatla;

WiFiClient   klientWifi;
PubSubClient klientMqtt(klientWifi);

unsigned long ostatniaPublikacja = 0;
unsigned long ostatniHeartbeat   = 0;
unsigned long ostatniProbaWifi   = 0;

const unsigned long INTERWAL_NORMALNY  = 15000;   // 15s — balans: dashboard zywy, RPi nie przeciazony
const unsigned long INTERWAL_ANTISPAM  =  3000;
const unsigned long INTERWAL_HEARTBEAT = 10000;

// --- DEKLARACJE ---
void konfigurujWifi();
void polaczMqtt();
inline void dodajHex(String &s, unsigned char bajt);
void zaszyfruj(const char* dane, int dlugosc, int algorytm, String &wynik);
void wyslijMqtt(const String &payload);

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

// Szybszy od sprintf("%02x") — unika parsowania stringa formatu przy kazdym bajcie
inline void dodajHex(String &s, unsigned char bajt) {
  static const char ZNAKI_HEX[] = "0123456789abcdef";
  s += ZNAKI_HEX[(bajt >> 4) & 0x0F];
  s += ZNAKI_HEX[bajt & 0x0F];
}

// =================================================================
// SILNIK KRYPTOGRAFICZNY — identyczny z plytka_antywlamaniowa
// Algorytmy 0–8, ten sam format payloadu "<nr>:<szyfrogram>"
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

void konfigurujWifi() {
  delay(10);
  Serial.print("\nLacze z WiFi: "); Serial.println(ssid);
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, hasloWifi);
  while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
  Serial.println("\nPolaczono z WiFi.");
  Serial.println(WiFi.localIP());
}

void polaczMqtt() {
  while (!klientMqtt.connected()) {
    Serial.print("Lacze z MQTT... ");
    String idKlienta = "ESP32-Env-" + String(random(0xffff), HEX);
    // LWT: broker opublikuje "offline" gdy urzadzenie zniknie bez rozlaczenia
    if (klientMqtt.connect(idKlienta.c_str(), NULL, NULL, topicOnline, 0, true, "offline")) {
      klientMqtt.publish(topicOnline, "online", true);  // retained
      klientMqtt.subscribe(topicSetAlgorytm);
      Serial.println("OK");
    } else {
      Serial.print("Blad (kod "); Serial.print(klientMqtt.state());
      Serial.println(") - ponowna proba za 5s.");
      delay(5000);
    }
  }
}

// Mierzy czas szyfrowania [us], narzut rozmiaru [%] i wolny heap [B]
// Format identyczny z plytka_antywlamaniowa — te same tabele w pracy magisterskiej
void wyslijMqtt(const String &payload) {
  if (!klientMqtt.connected()) return;

  int dlugoscJson = payload.length();

  Serial.println("\n==================================================");
  Serial.print("[PROFILOWANIE - ALGORYTM "); Serial.print(WYBRANY_ALGORYTM); Serial.println("]");
  Serial.print("-> Dane surowe JSON: "); Serial.println(payload);
  Serial.print("-> Rozmiar surowy: ");  Serial.print(dlugoscJson); Serial.println(" B");

  String daneSzyfr = "";
  unsigned long czasStart    = micros();
  zaszyfruj(payload.c_str(), dlugoscJson, WYBRANY_ALGORYTM, daneSzyfr);
  unsigned long czasWykonania = micros() - czasStart;

  size_t wolnyRam = ESP.getFreeHeap();

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

void setup() {
  Serial.begin(115200);
  Serial.println("\nStart systemu (silnik kryptograficzny algo 0-8)");

  pinMode(SOUND_PIN, INPUT);

  konfigurujWifi();
  klientMqtt.setServer(serwerMqtt, 1883);
  klientMqtt.setBufferSize(1024);
  klientMqtt.setCallback(wywolanieMqtt);

  // Kazda magistrala inicjalizowana raz — sensor przechowuje wskaznik do swojego Wire
  magistrala1.begin(I2C1_SDA, I2C1_SCL);
  if (!czujnikBme.begin(0x76, &magistrala1)) Serial.println("Blad: nie znaleziono BME280!");

  magistrala2.begin(I2C2_SDA, I2C2_SCL);
  if (!miernikSwiatla.begin(BH1750::CONTINUOUS_HIGH_RES_MODE, 0x23, &magistrala2))
    Serial.println("Blad: nie znaleziono BH1750!");
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

  unsigned long teraz = millis();

  if (teraz - ostatniHeartbeat >= INTERWAL_HEARTBEAT) {
    if (klientMqtt.connected()) klientMqtt.publish(topicOnline, "online", true);
    ostatniHeartbeat = teraz;
  }

  int stanDzwieku    = digitalRead(SOUND_PIN);
  bool czyPublikowac = false;

  if (teraz - ostatniaPublikacja >= INTERWAL_NORMALNY) {
    czyPublikowac = true;
  } else if (stanDzwieku == HIGH && (teraz - ostatniaPublikacja >= INTERWAL_ANTISPAM)) {
    czyPublikowac = true;
    Serial.println("Wykryto dzwiek!");
  }

  if (czyPublikowac) {
    ostatniaPublikacja = teraz;

    int wartoscGazu   = analogRead(MQ135_PIN);  // 0–4095 (12-bit ADC)
    float temperatura = czujnikBme.readTemperature();
    float wilgotnosc  = czujnikBme.readHumidity();
    float cisnienie   = czujnikBme.readPressure() / 100.0F;  // Pa → hPa
    float swiatlo     = miernikSwiatla.readLightLevel();       // luxy [lx]

    // Arduino String(NaN) == "nan" — nieprawidlowy JSON; zabezpieczenie gdy BME280 nie odpowiada
    auto fJson = [](float v) -> String { return isnan(v) ? "0.00" : String(v, 2); };

    // Reczne budowanie JSON — szybsze i przewidywalne co do rozmiaru bufora
    String payload = "{";
    payload += "\"temperatura\":" + fJson(temperatura) + ",";
    payload += "\"wilgotnosc\":"  + fJson(wilgotnosc)  + ",";
    payload += "\"cisnienie\":"   + fJson(cisnienie)   + ",";
    payload += "\"gazy\":"        + String(wartoscGazu)  + ",";
    payload += "\"swiatlo\":"     + fJson(swiatlo >= 0 ? swiatlo : 0.0f) + ",";
    payload += "\"dzwiek\":"      + String(stanDzwieku);
    payload += "}";

    wyslijMqtt(payload);
  }
}
