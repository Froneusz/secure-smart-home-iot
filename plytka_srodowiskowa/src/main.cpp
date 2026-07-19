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
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"

volatile int wybranyAlgorytm = 0;

const char* ssid       = "TWOJE_SSID";
const char* hasloWifi  = "TWOJE_HASLO_WIFI";
const char* serwerMqtt = "IP_RASPBERRY_PI";

const char* topicDane        = "/plytka_srodowiskoa/zaszyfrowane";
const char* topicOnline      = "/plytka_srodowiskoa/online";
const char* topicSetAlgorytm = "/plytka_srodowiskoa/set_algorytm";

const unsigned char kluczAes[16] = {
    '1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6'
};

#define PIN_MQ135  36
#define PIN_DZWIEK 14

#define PIN_BME_SDA 4
#define PIN_BME_SCL 5

#define PIN_BH_SDA 25
#define PIN_BH_SCL 26

static const uint32_t INTERWAL_RAPORTU         = 60000;
static const uint32_t INTERWAL_PROBKI_ANOMALII =  5000;
static const uint32_t ANTYSPAM_ZDARZEN         =  3000;
static const uint32_t INTERWAL_HEARTBEAT       = 10000;
static const uint32_t INTERWAL_PETLI_MQTT      =    10;

static const float PROG_SKOK_TEMPERATURY = 1.5f;
static const float PROG_SKOK_WILGOTNOSCI = 10.0f;
static const float PROG_SKOK_CISNIENIA   = 1.5f;
static const float PROG_SKOK_SWIATLA     = 0.6f;
static const int   PROG_SKOK_GAZOW       = 600;

struct DaneSrodowiskowe {
    float temperatura;
    float wilgotnosc;
    float cisnienie;
    float swiatlo;
    int   gazy;
    int   dzwiek;
};

struct WiadomoscMqtt {
    char temat[64];
    char payload[1200];
    bool zachowaj;
};

TwoWire         magistralaBme(0);
TwoWire         magistralaBh(1);
Adafruit_BME280 czujnikBme;
BH1750          miernikSwiatla;
WiFiClient      klientWifi;
PubSubClient    klientMqtt(klientWifi);

static SemaphoreHandle_t mutexDanych;
static QueueHandle_t     kolejkaMqtt;
static DaneSrodowiskowe  daneBiezace;

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
            int iRc = 0, jRc = 0;
            for (int n = 0; n < dlugosc; ++n) {
                iRc = (iRc + 1) % 256;
                jRc = (jRc + tablicaS[iRc]) % 256;
                std::swap(tablicaS[iRc], tablicaS[jRc]);
                dodajHex(wynik, (unsigned char)(dane[n] ^ tablicaS[(tablicaS[iRc] + tablicaS[jRc]) % 256]));
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
    snprintf(identyfikator, sizeof(identyfikator), "esp32-srod-%lu", millis());
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

static void taskSensory(void* parametry) {
    TickType_t ostatniaPublikacja     = xTaskGetTickCount();
    TickType_t ostatniaProbkaAnomalii = 0;

    float ostatniaTemperatura = NAN;
    float ostatniaWilgotnosc  = NAN;
    float ostatnieCisnienie   = NAN;
    float ostatnieSwiatlo     = -1.0f;
    int   ostatnieGazy        = -1;

    while (true) {
        vTaskDelay(pdMS_TO_TICKS(100));

        TickType_t teraz       = xTaskGetTickCount();
        int        stanDzwieku = digitalRead(PIN_DZWIEK);

        bool minalInterwal = (teraz - ostatniaPublikacja) >= pdMS_TO_TICKS(INTERWAL_RAPORTU);
        bool wykrytoDzwiek = (stanDzwieku == HIGH) &&
                             (teraz - ostatniaPublikacja) >= pdMS_TO_TICKS(ANTYSPAM_ZDARZEN);

        bool   wykrytoAnomalie = false;
        String zrodloAnomalii  = "";

        if ((teraz - ostatniaProbkaAnomalii) >= pdMS_TO_TICKS(INTERWAL_PROBKI_ANOMALII)) {
            ostatniaProbkaAnomalii = teraz;
            bool mozeRaportowac = (teraz - ostatniaPublikacja) >= pdMS_TO_TICKS(ANTYSPAM_ZDARZEN);

            float temperaturaTeraz = czujnikBme.readTemperature();
            float wilgotnoscTeraz  = czujnikBme.readHumidity();
            float cisnienieTeraz   = czujnikBme.readPressure() / 100.0f;
            float swiatloTeraz     = miernikSwiatla.readLightLevel();
            int   gazyTeraz        = analogRead(PIN_MQ135);

            if (!isnan(temperaturaTeraz) && !isnan(ostatniaTemperatura) && mozeRaportowac &&
                fabsf(temperaturaTeraz - ostatniaTemperatura) >= PROG_SKOK_TEMPERATURY) {
                wykrytoAnomalie = true; zrodloAnomalii = "temperatura";
            }
            if (!isnan(wilgotnoscTeraz) && !isnan(ostatniaWilgotnosc) && mozeRaportowac &&
                fabsf(wilgotnoscTeraz - ostatniaWilgotnosc) >= PROG_SKOK_WILGOTNOSCI) {
                wykrytoAnomalie = true; zrodloAnomalii = "wilgotnosc";
            }
            if (!isnan(cisnienieTeraz) && !isnan(ostatnieCisnienie) && mozeRaportowac &&
                fabsf(cisnienieTeraz - ostatnieCisnienie) >= PROG_SKOK_CISNIENIA) {
                wykrytoAnomalie = true; zrodloAnomalii = "cisnienie";
            }
            if (swiatloTeraz >= 0 && ostatnieSwiatlo >= 0 && mozeRaportowac) {
                float baza = fmaxf(ostatnieSwiatlo, 1.0f);
                if (fabsf(swiatloTeraz - ostatnieSwiatlo) / baza >= PROG_SKOK_SWIATLA) {
                    wykrytoAnomalie = true; zrodloAnomalii = "swiatlo";
                }
            }
            if (ostatnieGazy >= 0 && mozeRaportowac &&
                abs(gazyTeraz - ostatnieGazy) >= PROG_SKOK_GAZOW) {
                wykrytoAnomalie = true; zrodloAnomalii = "gazy";
            }

            if (wykrytoAnomalie) {
                Serial.printf("[ANOMALIA] Zrodlo: %s\n", zrodloAnomalii.c_str());
            }

            if (!isnan(temperaturaTeraz)) ostatniaTemperatura = temperaturaTeraz;
            if (!isnan(wilgotnoscTeraz))  ostatniaWilgotnosc  = wilgotnoscTeraz;
            if (!isnan(cisnienieTeraz))   ostatnieCisnienie   = cisnienieTeraz;
            if (swiatloTeraz >= 0)        ostatnieSwiatlo     = swiatloTeraz;
            ostatnieGazy = gazyTeraz;
        }

        if (!minalInterwal && !wykrytoDzwiek && !wykrytoAnomalie) continue;
        ostatniaPublikacja = teraz;

        float temperatura = czujnikBme.readTemperature();
        float wilgotnosc  = czujnikBme.readHumidity();
        float cisnienie   = czujnikBme.readPressure() / 100.0F;
        float swiatlo     = miernikSwiatla.readLightLevel();
        int   gazy        = analogRead(PIN_MQ135);

        auto sformatujLiczbe = [](float wartosc) -> String {
            return isnan(wartosc) ? "0.00" : String(wartosc, 2);
        };

        if (xSemaphoreTake(mutexDanych, pdMS_TO_TICKS(20)) == pdTRUE) {
            daneBiezace = {temperatura, wilgotnosc, cisnienie, swiatlo, gazy, stanDzwieku};
            xSemaphoreGive(mutexDanych);
        }

        String zrodloRaportu;
        if (minalInterwal)      zrodloRaportu = "okresowy";
        else if (wykrytoDzwiek) zrodloRaportu = "dzwiek";
        else                    zrodloRaportu = zrodloAnomalii;

        String payload = "{";
        payload += "\"temperatura\":" + sformatujLiczbe(temperatura)                   + ",";
        payload += "\"wilgotnosc\":"  + sformatujLiczbe(wilgotnosc)                    + ",";
        payload += "\"cisnienie\":"   + sformatujLiczbe(cisnienie)                     + ",";
        payload += "\"gazy\":"        + String(gazy)                                    + ",";
        payload += "\"swiatlo\":"     + sformatujLiczbe(swiatlo >= 0 ? swiatlo : 0.0f) + ",";
        payload += "\"dzwiek\":"      + String(stanDzwieku)                             + ",";
        payload += "\"zdarzenie\":\"" + zrodloRaportu                                   + "\"";
        payload += "}";

        int algorytm    = wybranyAlgorytm;
        int dlugoscJson = payload.length();

        Serial.println("\n==================================================");
        Serial.printf("[PROFILOWANIE - ALGORYTM %d]\n", algorytm);
        Serial.printf("-> Dane surowe JSON: %s\n",  payload.c_str());
        Serial.printf("-> Rozmiar surowy: %d B\n",  dlugoscJson);

        String zaszyfrowane = "";
        unsigned long poczatek = micros();
        zaszyfruj(payload.c_str(), dlugoscJson, algorytm, zaszyfrowane);
        unsigned long czasSzyfrowania = micros() - poczatek;

        String finalnaWiadomosc = String(algorytm) + ":" + zaszyfrowane;
        float narzut = ((float)((int)finalnaWiadomosc.length() - dlugoscJson) / dlugoscJson) * 100.0f;

        Serial.printf("-> Szyfrogram: %s\n",           finalnaWiadomosc.c_str());
        Serial.printf("-> Rozmiar po szyfrowaniu: %d B\n", finalnaWiadomosc.length());
        Serial.printf("-> 1. CZAS SZYFROWANIA: %lu us\n", czasSzyfrowania);
        Serial.printf("-> 2. NARZUT PRZESYLU: +%.2f%%\n",  narzut);
        Serial.printf("-> 3. WOLNY RAM (heap): %u B\n",    ESP.getFreeHeap());
        Serial.println("==================================================");

        WiadomoscMqtt wiadomosc;
        strncpy(wiadomosc.temat,   topicDane,               sizeof(wiadomosc.temat)   - 1);
        strncpy(wiadomosc.payload, finalnaWiadomosc.c_str(), sizeof(wiadomosc.payload) - 1);
        wiadomosc.zachowaj = false;

        if (xQueueSend(kolejkaMqtt, &wiadomosc, pdMS_TO_TICKS(50)) != pdTRUE) {
            Serial.println("[WARN] kolejkaMqtt pelna");
        }
    }
}

void setup() {
    Serial.begin(115200);
    delay(300);
    Serial.println("\n[BOOT] Plytka srodowiskowa");

    pinMode(PIN_DZWIEK, INPUT);

    magistralaBme.begin(PIN_BME_SDA, PIN_BME_SCL);
    if (!czujnikBme.begin(0x76, &magistralaBme))
        Serial.println("[WARN] BME280 nie odpowiada na 0x76");

    magistralaBh.begin(PIN_BH_SDA, PIN_BH_SCL);
    if (!miernikSwiatla.begin(BH1750::CONTINUOUS_HIGH_RES_MODE, 0x23, &magistralaBh))
        Serial.println("[WARN] BH1750 nie odpowiada");

    mutexDanych = xSemaphoreCreateMutex();
    kolejkaMqtt = xQueueCreate(5, sizeof(WiadomoscMqtt));
    configASSERT(mutexDanych);
    configASSERT(kolejkaMqtt);

    xTaskCreatePinnedToCore(taskKomunikacja, "Komunikacja", 6144,  nullptr, 5, nullptr, 0);
    xTaskCreatePinnedToCore(taskSensory,     "Sensory",     10240, nullptr, 4, nullptr, 1);

    Serial.println("[RTOS] Taski uruchomione");
}

void loop() {
    vTaskDelay(portMAX_DELAY);
}
