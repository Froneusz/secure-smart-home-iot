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
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"

volatile int wybranyAlgorytm = 0;

const char* ssid       = "TWOJE_SSID";
const char* hasloWifi  = "TWOJE_HASLO_WIFI";
const char* serwerMqtt = "IP_RASPBERRY_PI";

const char* topicAlarm       = "/plytka_antywlamaniowa/zaszyfrowane";
const char* topicOnline      = "/plytka_antywlamaniowa/online";
const char* topicSetAlgorytm = "/plytka_antywlamaniowa/set_algorytm";

const unsigned char kluczAes[16] = {
    '1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6'
};

#define PIN_PIR      34
#define PIN_REED     35
#define PIN_BUZZER   15
#define PIN_RFID_SS   5
#define PIN_RFID_RST  4

static const byte LICZBA_WIERSZY = 4;
static const byte LICZBA_KOLUMN  = 4;
static char mapaKlawiszy[LICZBA_WIERSZY][LICZBA_KOLUMN] = {
    {'1','2','3','A'},
    {'4','5','6','B'},
    {'7','8','9','C'},
    {'*','0','#','D'}
};
static byte pinyWierszy[LICZBA_WIERSZY] = {32, 33, 25, 26};
static byte pinyKolumn[LICZBA_KOLUMN]   = {27, 14, 13, 12};

enum StanAlarmu : uint8_t { ROZBROJONY, UZBRAJANIE, CZUWA, OCZEKUJE, ALARM };

static const uint32_t CZAS_WYJSCIA             =  3000;
static const uint32_t CZAS_WEJSCIA             =  5000;
static const uint32_t INTERWAL_RAPORTU         = 60000;
static const uint32_t INTERWAL_HEARTBEAT       = 10000;
static const uint32_t CZAS_POTWIERDZENIA_RUCHU =   300;
static const uint32_t INTERWAL_PETLI_MQTT      =    10;
static const uint32_t ANTYSPAM_ANOMALII        =  5000;

static const float PROG_WSTRZASU_UZBROJONY = 2.0f;
static const float PROG_WSTRZASU_SABOTAZ   = 3.5f;
static const byte  MAKSYMALNA_LICZBA_PROB  = 3;
static const uint32_t CZAS_BLOKADY         = 30000;

static byte kartaWzorcowa[] = {0x4A, 0x81, 0x4D, 0x06};
static const char kodPin[] = "1234";

enum RodzajZdarzenia : uint8_t {
    ZD_KLAWISZ,
    ZD_RFID_OK,
    ZD_RFID_BLAD,
    ZD_WYZWALACZ,
};

struct Zdarzenie {
    RodzajZdarzenia rodzaj;
    char dane[8];
};

struct WiadomoscMqtt {
    char temat[64];
    char payload[1200];
    bool zachowaj;
};

struct StanSystemu {
    StanAlarmu stan;
    int   pir;
    int   reed;
    float przyspX, przyspY, przyspZ;
};

Keypad                   klawiatura = Keypad(makeKeymap(mapaKlawiszy),
                                             pinyWierszy, pinyKolumn,
                                             LICZBA_WIERSZY, LICZBA_KOLUMN);
MFRC522                  czytnikRfid(PIN_RFID_SS, PIN_RFID_RST);
Adafruit_ADXL345_Unified akcelerometr(12345);
WiFiClient                klientWifi;
PubSubClient              klientMqtt(klientWifi);

static SemaphoreHandle_t mutexStanu;
static QueueHandle_t     kolejkaZdarzen;
static QueueHandle_t     kolejkaMqtt;
static StanSystemu       stanSystemu;

inline void dodajHex(String& s, unsigned char bajt) {
    static const char znakiHex[] = "0123456789abcdef";
    s += znakiHex[bajt >> 4];
    s += znakiHex[bajt & 0x0F];
}

void zaszyfruj(const char* dane, int dlugosc, int algorytm, String& wynik) {
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

        case 2:
            for (int i = 0; i < dlugosc; ++i) {
                char znak = dane[i];
                wynik += (znak >= 32 && znak <= 126) ? (char)((znak - 32 + 3) % 95 + 32) : znak;
            }
            return;

        case 3: {
            const char kluczXor[] = "1234";
            for (int i = 0; i < dlugosc; ++i)
                dodajHex(wynik, (unsigned char)(dane[i] ^ kluczXor[i & 3]));
            return;
        }

        case 4: {
            const char kluczVigenere[] = "TAJNE";
            for (int i = 0; i < dlugosc; ++i) {
                char znak = dane[i];
                int przesuniecie = kluczVigenere[i % 5] - 32;
                wynik += (znak >= 32 && znak <= 126) ? (char)((znak - 32 + przesuniecie) % 95 + 32) : znak;
            }
            return;
        }

        case 5: {
            const char kluczRc4[] = "1234567890123456";
            unsigned char tablicaS[256];
            for (int i = 0; i < 256; ++i) tablicaS[i] = i;
            int j = 0;
            for (int i = 0; i < 256; ++i) {
                j = (j + tablicaS[i] + kluczRc4[i & 15]) % 256;
                std::swap(tablicaS[i], tablicaS[j]);
            }
            int iR = 0, jR = 0;
            for (int n = 0; n < dlugosc; ++n) {
                iR = (iR + 1) % 256;
                jR = (jR + tablicaS[iR]) % 256;
                std::swap(tablicaS[iR], tablicaS[jR]);
                dodajHex(wynik, (unsigned char)(dane[n] ^ tablicaS[(tablicaS[iR] + tablicaS[jR]) % 256]));
            }
            return;
        }

        case 6: {
            mbedtls_aes_context kontekst;
            mbedtls_aes_init(&kontekst);
            mbedtls_aes_setkey_enc(&kontekst, kluczAes, 128);
            memcpy(buforDanych, dane, dlugosc);
            unsigned char dopelnienie = dlugoscZPaddingiem - dlugosc;
            memset(buforDanych + dlugosc, dopelnienie, dopelnienie);
            for (int i = 0; i < dlugoscZPaddingiem; i += 16)
                mbedtls_aes_crypt_ecb(&kontekst, MBEDTLS_AES_ENCRYPT,
                                      buforDanych + i, buforSzyfrogramu + i);
            for (int i = 0; i < dlugoscZPaddingiem; ++i) dodajHex(wynik, buforSzyfrogramu[i]);
            mbedtls_aes_free(&kontekst);
            return;
        }

        case 7: {
            mbedtls_aes_context kontekst;
            mbedtls_aes_init(&kontekst);
            mbedtls_aes_setkey_enc(&kontekst, kluczAes, 128);
            unsigned char wektorIv[16] = {0};
            memcpy(buforDanych, dane, dlugosc);
            unsigned char dopelnienie = dlugoscZPaddingiem - dlugosc;
            memset(buforDanych + dlugosc, dopelnienie, dopelnienie);
            mbedtls_aes_crypt_cbc(&kontekst, MBEDTLS_AES_ENCRYPT,
                                  dlugoscZPaddingiem, wektorIv, buforDanych, buforSzyfrogramu);
            for (int i = 0; i < dlugoscZPaddingiem; ++i) dodajHex(wynik, buforSzyfrogramu[i]);
            mbedtls_aes_free(&kontekst);
            return;
        }

        case 8: {
            mbedtls_gcm_context kontekst;
            mbedtls_gcm_init(&kontekst);
            mbedtls_gcm_setkey(&kontekst, MBEDTLS_CIPHER_ID_AES, kluczAes, 128);
            unsigned char nonce[12] = {1,2,3,4,5,6,7,8,9,10,11,12};
            unsigned char tag[16];
            mbedtls_gcm_crypt_and_tag(&kontekst, MBEDTLS_GCM_ENCRYPT, dlugosc,
                                      nonce, 12, nullptr, 0,
                                      (const unsigned char*)dane, buforSzyfrogramu, 16, tag);
            for (int i = 0; i < dlugosc; ++i) dodajHex(wynik, buforSzyfrogramu[i]);
            for (int i = 0; i < 16; ++i)      dodajHex(wynik, tag[i]);
            mbedtls_gcm_free(&kontekst);
            return;
        }

        default:
            wynik = dane;
    }
}

static void sygnalBuzzer(uint32_t czasMs) {
    digitalWrite(PIN_BUZZER, HIGH);
    vTaskDelay(pdMS_TO_TICKS(czasMs));
    digitalWrite(PIN_BUZZER, LOW);
}

static String nazwaStanu(StanAlarmu stan) {
    switch (stan) {
        case ROZBROJONY: return "rozbrojony";
        case UZBRAJANIE: return "uzbrajanie";
        case CZUWA:      return "czuwa";
        case OCZEKUJE:   return "oczekuje_na_rfid";
        case ALARM:      return "ALARM";
        default:         return "nieznany";
    }
}

static void wyslijDoKolejkiMqtt(StanAlarmu stan, int pir, int reed,
                                 float przyspX, float przyspY, float przyspZ,
                                 const String& zrodloRaportu) {
    JsonDocument dokument;
    dokument["status"]    = nazwaStanu(stan);
    dokument["pir"]       = pir;
    dokument["drzwi"]     = reed;
    dokument["zdarzenie"] = zrodloRaportu;
    JsonObject przyspieszenie = dokument["akcelerometr"].to<JsonObject>();
    przyspieszenie["x"] = round(przyspX * 100.0f) / 100.0f;
    przyspieszenie["y"] = round(przyspY * 100.0f) / 100.0f;
    przyspieszenie["z"] = round(przyspZ * 100.0f) / 100.0f;

    char buforJson[256];
    int dlugoscJson = serializeJson(dokument, buforJson, sizeof(buforJson));

    int algorytm = wybranyAlgorytm;

    Serial.println("\n==================================================");
    Serial.printf("[PROFILOWANIE - ALGORYTM %d]\n", algorytm);
    Serial.printf("-> Dane surowe JSON: %s\n", buforJson);
    Serial.printf("-> Rozmiar surowy: %d B\n", dlugoscJson);

    String zaszyfrowane = "";
    unsigned long poczatek = micros();
    zaszyfruj(buforJson, dlugoscJson, algorytm, zaszyfrowane);
    unsigned long czasSzyfrowania = micros() - poczatek;

    String finalnaWiadomosc = String(algorytm) + ":" + zaszyfrowane;
    float narzut = ((float)((int)finalnaWiadomosc.length() - dlugoscJson) / dlugoscJson) * 100.0f;

    Serial.printf("-> Szyfrogram: %s\n",              finalnaWiadomosc.c_str());
    Serial.printf("-> Rozmiar po szyfrowaniu: %d B\n", finalnaWiadomosc.length());
    Serial.printf("-> 1. CZAS SZYFROWANIA: %lu us\n",  czasSzyfrowania);
    Serial.printf("-> 2. NARZUT PRZESYLU: +%.2f%%\n",  narzut);
    Serial.printf("-> 3. WOLNY RAM (heap): %u B\n",    ESP.getFreeHeap());
    Serial.println("==================================================");

    WiadomoscMqtt wiadomosc;
    strncpy(wiadomosc.temat,   topicAlarm,               sizeof(wiadomosc.temat)   - 1);
    strncpy(wiadomosc.payload, finalnaWiadomosc.c_str(), sizeof(wiadomosc.payload) - 1);
    wiadomosc.zachowaj = false;

    if (xQueueSend(kolejkaMqtt, &wiadomosc, pdMS_TO_TICKS(50)) != pdTRUE) {
        Serial.println("[WARN] kolejkaMqtt pelna");
    }
}

void wywolanieMqtt(char* temat, byte* payload, unsigned int dlugosc) {
    if (strcmp(temat, topicSetAlgorytm) != 0 || dlugosc < 1) return;
    int nowyAlgorytm = payload[0] - '0';
    if (nowyAlgorytm >= 0 && nowyAlgorytm <= 8) {
        wybranyAlgorytm = nowyAlgorytm;
        Serial.printf("[MQTT] Algorytm -> %d\n", nowyAlgorytm);
    }
}

void polaczZBrokeremMqtt() {
    char identyfikator[32];
    snprintf(identyfikator, sizeof(identyfikator), "esp32-alarm-%lu", millis());
    if (klientMqtt.connect(identyfikator, nullptr, nullptr, topicOnline, 0, true, "offline")) {
        klientMqtt.publish(topicOnline, "online", true);
        klientMqtt.subscribe(topicSetAlgorytm);
        Serial.println("[MQTT] Polaczono");
    } else {
        Serial.printf("[MQTT] Blad: %d\n", klientMqtt.state());
    }
}

static void taskKomunikacja(void* parametry) {
    WiFi.mode(WIFI_STA);
    WiFi.begin(ssid, hasloWifi);
    Serial.print("[WiFi] Lacze");
    while (WiFi.status() != WL_CONNECTED) {
        vTaskDelay(pdMS_TO_TICKS(500));
        Serial.print(".");
    }
    Serial.printf("\n[WiFi] OK  IP: %s\n", WiFi.localIP().toString().c_str());

    klientMqtt.setServer(serwerMqtt, 1883);
    klientMqtt.setBufferSize(2048);
    klientMqtt.setCallback(wywolanieMqtt);
    polaczZBrokeremMqtt();

    TickType_t ostatniHeartbeat  = xTaskGetTickCount();
    TickType_t ostatniaProbaWifi = 0;

    while (true) {
        if (WiFi.status() != WL_CONNECTED) {
            TickType_t teraz = xTaskGetTickCount();
            if (teraz - ostatniaProbaWifi >= pdMS_TO_TICKS(5000)) {
                WiFi.reconnect();
                ostatniaProbaWifi = teraz;
            }
            vTaskDelay(pdMS_TO_TICKS(500));
            continue;
        }

        if (!klientMqtt.connected()) {
            polaczZBrokeremMqtt();
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        klientMqtt.loop();

        TickType_t teraz = xTaskGetTickCount();
        if (teraz - ostatniHeartbeat >= pdMS_TO_TICKS(INTERWAL_HEARTBEAT)) {
            klientMqtt.publish(topicOnline, "online", true);
            ostatniHeartbeat = teraz;
        }

        WiadomoscMqtt wiadomosc;
        if (xQueueReceive(kolejkaMqtt, &wiadomosc, 0) == pdTRUE) {
            klientMqtt.publish(wiadomosc.temat,
                               (const uint8_t*)wiadomosc.payload,
                               strlen(wiadomosc.payload),
                               wiadomosc.zachowaj);
        }

        vTaskDelay(pdMS_TO_TICKS(INTERWAL_PETLI_MQTT));
    }
}

static void taskKlawiatura(void* parametry) {
    while (true) {
        char klawisz = klawiatura.getKey();
        if (klawisz) {
            Zdarzenie zdarzenie;
            zdarzenie.rodzaj  = ZD_KLAWISZ;
            zdarzenie.dane[0] = klawisz;
            zdarzenie.dane[1] = 0;
            xQueueSend(kolejkaZdarzen, &zdarzenie, pdMS_TO_TICKS(20));
        }
        vTaskDelay(pdMS_TO_TICKS(20));
    }
}

static void taskSensory(void* parametry) {
    TickType_t czasPotwierdzeniaPir   = 0;
    TickType_t czasOstatniejAnomalii  = 0;

    while (true) {
        vTaskDelay(pdMS_TO_TICKS(50));

        int pir  = digitalRead(PIN_PIR);
        int reed = digitalRead(PIN_REED);
        sensors_event_t zdarzenieCzujnika;
        akcelerometr.getEvent(&zdarzenieCzujnika);
        float przyspX = zdarzenieCzujnika.acceleration.x;
        float przyspY = zdarzenieCzujnika.acceleration.y;
        float przyspZ = zdarzenieCzujnika.acceleration.z;
        float modulPrzyspieszenia = sqrtf(przyspX * przyspX + przyspY * przyspY + przyspZ * przyspZ);

        if (xSemaphoreTake(mutexStanu, pdMS_TO_TICKS(10)) == pdTRUE) {
            stanSystemu.pir     = pir;
            stanSystemu.reed    = reed;
            stanSystemu.przyspX = przyspX;
            stanSystemu.przyspY = przyspY;
            stanSystemu.przyspZ = przyspZ;
            xSemaphoreGive(mutexStanu);
        }

        if (czytnikRfid.PICC_IsNewCardPresent() && czytnikRfid.PICC_ReadCardSerial()) {
            bool zgodnaKarta = true;
            for (byte i = 0; i < 4; i++) {
                if (czytnikRfid.uid.uidByte[i] != kartaWzorcowa[i]) { zgodnaKarta = false; break; }
            }
            czytnikRfid.PICC_HaltA();

            Zdarzenie zdarzenie;
            zdarzenie.rodzaj  = zgodnaKarta ? ZD_RFID_OK : ZD_RFID_BLAD;
            zdarzenie.dane[0] = 0;
            xQueueSend(kolejkaZdarzen, &zdarzenie, pdMS_TO_TICKS(20));

            Serial.printf("[RFID] %s\n", zgodnaKarta ? "Autoryzacja OK" : "Odmowa dostepu");
        }

        if (xSemaphoreTake(mutexStanu, pdMS_TO_TICKS(5)) == pdTRUE) {
            StanAlarmu stanAktualny = stanSystemu.stan;
            xSemaphoreGive(mutexStanu);

            if (stanAktualny == CZUWA) {
                if (pir == HIGH) {
                    if (czasPotwierdzeniaPir == 0) czasPotwierdzeniaPir = xTaskGetTickCount();
                    bool ruchPotwierdzony = (xTaskGetTickCount() - czasPotwierdzeniaPir >=
                                             pdMS_TO_TICKS(CZAS_POTWIERDZENIA_RUCHU));
                    if (ruchPotwierdzony) {
                        Zdarzenie zdarzenie = {ZD_WYZWALACZ, {'P', 0}};
                        xQueueSend(kolejkaZdarzen, &zdarzenie, 0);
                    }
                } else {
                    czasPotwierdzeniaPir = 0;
                }

                if (reed == HIGH) {
                    Zdarzenie zdarzenie = {ZD_WYZWALACZ, {'R', 0}};
                    xQueueSend(kolejkaZdarzen, &zdarzenie, 0);
                }

                if (fabsf(modulPrzyspieszenia - 9.8f) > PROG_WSTRZASU_UZBROJONY) {
                    Zdarzenie zdarzenie = {ZD_WYZWALACZ, {'W', 0}};
                    xQueueSend(kolejkaZdarzen, &zdarzenie, 0);
                }
            } else {
                bool sabotaz = fabsf(modulPrzyspieszenia - 9.8f) > PROG_WSTRZASU_SABOTAZ;
                if (sabotaz && (xTaskGetTickCount() - czasOstatniejAnomalii >=
                                pdMS_TO_TICKS(ANTYSPAM_ANOMALII))) {
                    czasOstatniejAnomalii = xTaskGetTickCount();
                    Serial.println("[SABOTAZ] Wykryto ingerencje fizyczna");
                    wyslijDoKolejkiMqtt(stanAktualny, pir, reed, przyspX, przyspY, przyspZ, "sabotaz");
                }
            }
        }
    }
}

static void ustawStan(StanAlarmu nowyStan) {
    if (xSemaphoreTake(mutexStanu, pdMS_TO_TICKS(20)) == pdTRUE) {
        stanSystemu.stan = nowyStan;
        xSemaphoreGive(mutexStanu);
    }
    Serial.printf("[STAN] -> %s\n", nazwaStanu(nowyStan).c_str());
}

static StanAlarmu pobierzStan() {
    StanAlarmu stan = ROZBROJONY;
    if (xSemaphoreTake(mutexStanu, pdMS_TO_TICKS(10)) == pdTRUE) {
        stan = stanSystemu.stan;
        xSemaphoreGive(mutexStanu);
    }
    return stan;
}

static void taskMaszynaStanow(void* parametry) {
    char       buforKodu[5]          = {0};
    int        indeksKodu            = 0;
    int        liczbaBlednychProb    = 0;
    TickType_t czasBlokady           = 0;

    TickType_t ostatniRaport       = xTaskGetTickCount();
    StanAlarmu ostatnioWyslanyStan = ROZBROJONY;

    while (true) {
        StanAlarmu stan = pobierzStan();

        TickType_t teraz   = xTaskGetTickCount();
        bool zmianaStanu   = (stan != ostatnioWyslanyStan);
        bool minalInterwal = (teraz - ostatniRaport >= pdMS_TO_TICKS(INTERWAL_RAPORTU));

        if (zmianaStanu || minalInterwal) {
            int pir = 0, reed = 0; float przyspX = 0, przyspY = 0, przyspZ = 0;
            if (xSemaphoreTake(mutexStanu, pdMS_TO_TICKS(20)) == pdTRUE) {
                pir     = stanSystemu.pir;
                reed    = stanSystemu.reed;
                przyspX = stanSystemu.przyspX;
                przyspY = stanSystemu.przyspY;
                przyspZ = stanSystemu.przyspZ;
                xSemaphoreGive(mutexStanu);
            }
            wyslijDoKolejkiMqtt(stan, pir, reed, przyspX, przyspY, przyspZ,
                                zmianaStanu ? "zmiana_stanu" : "okresowy");
            ostatniRaport       = teraz;
            ostatnioWyslanyStan = stan;
        }

        Zdarzenie zdarzenie;

        switch (stan) {

            case ROZBROJONY: {
                if (xQueueReceive(kolejkaZdarzen, &zdarzenie, pdMS_TO_TICKS(200)) != pdTRUE) break;

                if (zdarzenie.rodzaj == ZD_RFID_OK) {
                    sygnalBuzzer(50);
                    break;
                }

                if (zdarzenie.rodzaj != ZD_KLAWISZ) break;

                if (czasBlokady) {
                    if (xTaskGetTickCount() - czasBlokady < pdMS_TO_TICKS(CZAS_BLOKADY)) {
                        Serial.println("[PIN] ZABLOKOWANE - poczekaj 30s.");
                        break;
                    }
                    czasBlokady = 0; liczbaBlednychProb = 0;
                    Serial.println("[PIN] Odblokowano.");
                }

                char klawisz = zdarzenie.dane[0];
                if (klawisz == '*') {
                    memset(buforKodu, 0, 5); indeksKodu = 0;
                    sygnalBuzzer(50);
                    Serial.println("[PIN] Wyczyszczono.");
                    break;
                }

                sygnalBuzzer(20);
                buforKodu[indeksKodu++] = klawisz;
                Serial.print("*");

                if (indeksKodu >= 4) {
                    if (strcmp(buforKodu, kodPin) == 0) {
                        liczbaBlednychProb = 0; czasBlokady = 0;
                        Serial.println("\n[PIN] Poprawny! Masz 3s na wyjscie.");
                        sygnalBuzzer(500);
                        ustawStan(UZBRAJANIE);
                    } else {
                        liczbaBlednychProb++;
                        Serial.printf("\n[PIN] Bledny! Proba %d/%d\n",
                                      liczbaBlednychProb, MAKSYMALNA_LICZBA_PROB);
                        sygnalBuzzer(100); vTaskDelay(pdMS_TO_TICKS(50)); sygnalBuzzer(100);
                        if (liczbaBlednychProb >= MAKSYMALNA_LICZBA_PROB) {
                            czasBlokady = xTaskGetTickCount();
                            Serial.println("[PIN] KLAWIATURA ZABLOKOWANA na 30s!");
                            vTaskDelay(pdMS_TO_TICKS(50)); sygnalBuzzer(100);
                        }
                    }
                    memset(buforKodu, 0, 5); indeksKodu = 0;
                }
                break;
            }

            case UZBRAJANIE: {
                for (uint32_t ms = 0; ms < CZAS_WYJSCIA; ms += 1000) {
                    sygnalBuzzer(200);
                    if (xQueueReceive(kolejkaZdarzen, &zdarzenie, pdMS_TO_TICKS(800)) == pdTRUE) {
                        if ((zdarzenie.rodzaj == ZD_KLAWISZ && zdarzenie.dane[0] == '#') ||
                             zdarzenie.rodzaj == ZD_RFID_OK) {
                            ustawStan(ROZBROJONY);
                            goto koniecUzbrajania;
                        }
                    }
                }
                ustawStan(CZUWA);
                Serial.println("[STAN] System uzbrojony - czuwa.");
                sygnalBuzzer(200);
                koniecUzbrajania:;
                break;
            }

            case CZUWA: {
                if (xQueueReceive(kolejkaZdarzen, &zdarzenie, pdMS_TO_TICKS(100)) != pdTRUE) break;

                if (zdarzenie.rodzaj == ZD_RFID_OK) {
                    ustawStan(ROZBROJONY);
                    sygnalBuzzer(500);
                    break;
                }

                if (zdarzenie.rodzaj == ZD_WYZWALACZ) {
                    Serial.printf("[CZUWA] Wyzwalacz: %c - 5s na autoryzacje!\n",
                                  zdarzenie.dane[0]);
                    sygnalBuzzer(50);
                    ustawStan(OCZEKUJE);
                }
                break;
            }

            case OCZEKUJE: {
                TickType_t koniecOkna = xTaskGetTickCount() + pdMS_TO_TICKS(CZAS_WEJSCIA);

                while (xTaskGetTickCount() < koniecOkna) {
                    TickType_t pozostaloCzasu = koniecOkna - xTaskGetTickCount();
                    if (xQueueReceive(kolejkaZdarzen, &zdarzenie, pozostaloCzasu) == pdTRUE) {
                        if (zdarzenie.rodzaj == ZD_RFID_OK) {
                            ustawStan(ROZBROJONY);
                            digitalWrite(PIN_BUZZER, LOW);
                            sygnalBuzzer(500);
                            goto koniecOczekiwania;
                        }
                    }
                }
                ustawStan(ALARM);
                Serial.println("[STAN] ALARM WYZWOLONY!");
                koniecOczekiwania:;
                break;
            }

            case ALARM: {
                if (xQueueReceive(kolejkaZdarzen, &zdarzenie, pdMS_TO_TICKS(500)) == pdTRUE) {
                    if (zdarzenie.rodzaj == ZD_RFID_OK) {
                        digitalWrite(PIN_BUZZER, LOW);
                        liczbaBlednychProb = 0; czasBlokady = 0;
                        ustawStan(ROZBROJONY);
                        Serial.println("[RFID] Autoryzacja - system rozbrojony.");
                    }
                } else {
                    digitalWrite(PIN_BUZZER, !digitalRead(PIN_BUZZER));
                }
                break;
            }
        }
    }
}

void setup() {
    Serial.begin(115200);
    delay(300);
    Serial.println("\n[BOOT] Plytka antywlamaniowa");

    pinMode(PIN_PIR,    INPUT);
    pinMode(PIN_REED,   INPUT);
    pinMode(PIN_BUZZER, OUTPUT);
    digitalWrite(PIN_BUZZER, LOW);

    SPI.begin();
    czytnikRfid.PCD_Init();

    Wire.begin(21, 22);
    if (!akcelerometr.begin()) Serial.println("[WARN] ADXL345 nie odpowiada!");

    stanSystemu.stan = ROZBROJONY;

    mutexStanu     = xSemaphoreCreateMutex();
    kolejkaZdarzen = xQueueCreate(10, sizeof(Zdarzenie));
    kolejkaMqtt    = xQueueCreate(5,  sizeof(WiadomoscMqtt));
    configASSERT(mutexStanu);
    configASSERT(kolejkaZdarzen);
    configASSERT(kolejkaMqtt);

    xTaskCreatePinnedToCore(taskKomunikacja,   "Komunikacja",   6144,  nullptr, 5, nullptr, 0);
    xTaskCreatePinnedToCore(taskKlawiatura,    "Klawiatura",    3072,  nullptr, 6, nullptr, 1);
    xTaskCreatePinnedToCore(taskSensory,       "Sensory",       4096,  nullptr, 5, nullptr, 1);
    xTaskCreatePinnedToCore(taskMaszynaStanow, "MaszynaStanow", 10240, nullptr, 4, nullptr, 1);

    Serial.println("[RTOS] Taski uruchomione");
    Serial.println("[RTOS] Wpisz PIN (1234) aby uzbrojic system.");
}

void loop() {
    vTaskDelay(portMAX_DELAY);
}
