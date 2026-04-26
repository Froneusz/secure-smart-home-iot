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
#include "mbedtls/aes.h"

const char* ssid = "";
const char* password = "";
const char* mqtt_server = "";
const char* mqtt_topic = "/plytka_antywlamaniowa/zaszyfrowane";

WiFiClient espClient;
PubSubClient client(espClient);

#define PIR_PIN 34 
#define REED_PIN 14 
#define BUZZER_PIN 15 
#define RFID_SS 5
#define RFID_RST 4

const byte ROWS = 4; 
const byte COLS = 4; 
char keys[ROWS][COLS] = {
  {'1','2','3','A'}, 
  {'4','5','6','B'}, 
  {'7','8','9','C'}, 
  {'*','0','#','D'}
};
byte rowPins[ROWS] = {32, 33, 25, 26}; 
byte colPins[COLS] = {27, 13, 16, 17}; 
Keypad keypad = Keypad(makeKeymap(keys), rowPins, colPins, ROWS, COLS);

MFRC522 rfid(RFID_SS, RFID_RST);
byte masterUID[] = {0x5A, 0x60, 0xFF, 0x06}; //uid karty przypisanej do admina
Adafruit_ADXL345_Unified accel = Adafruit_ADXL345_Unified(12345);

enum SystemState { DISARMED, ARMING, ARMED, PENDING_ALARM, ALARM };
SystemState currentState = DISARMED; 
String inputCode = "";

unsigned long stateTimer = 0;
const unsigned long EXIT_DELAY = 5000; //czas na opuszczenie strefy po uzbrojeniu
const unsigned long ENTRY_DELAY = 5000; //czas na podanie kodu po wejsciu

unsigned long ostatniRaport = 0;
const unsigned long INTERWAL_RAPORTU = 30000; //okresowy raport statusu co 30s

SystemState lastReportedState = DISARMED;
int lastPirState = -1;
int lastReedState = -1;
float lastAccX = 0.0, lastAccY = 0.0, lastAccZ = 0.0;

void setupWiFi();
void reconnectMQTT();
void publishMQTT(int pir, int reed, float ax, float ay, float az);
String getStateString(SystemState state);

void setup() {
  Serial.begin(115200);
  
  pinMode(PIR_PIN, INPUT);
  pinMode(REED_PIN, INPUT_PULLUP);
  pinMode(BUZZER_PIN, OUTPUT);
  
  SPI.begin();
  rfid.PCD_Init();
  Wire.begin(21, 22);
  
  if(!accel.begin()) {
    Serial.println("Blad: Nie znaleziono ADXL345!");
  }

  setupWiFi();
  client.setServer(mqtt_server, 1883);
  client.setBufferSize(512); //powiekszenie bufora pod dlugie pakiety aes
  
  Serial.println("Start systemu...");
}

void setupWiFi() {
  delay(10);
  Serial.print("Lacznie z WiFi: ");
  Serial.println(ssid);

  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("\nPolaczono z WiFi");
  Serial.println(WiFi.localIP());
}

void reconnectMQTT() {
  if (!client.connected()) {
    Serial.print("Laczenie z MQTT...");
    String clientId = "ESP32-Alarm-" + String(random(0xffff), HEX);
    
    if (client.connect(clientId.c_str())) {
      Serial.println(" OK");
    } else {
      Serial.print(" Blad: ");
      Serial.println(client.state());
    }
  }
}

String getStateString(SystemState state) {
  switch(state) {
    case DISARMED: return "rozbrojony";
    case ARMING: return "uzbrajanie";
    case ARMED: return "czuwa";
    case PENDING_ALARM: return "oczekuje_na_rfid";
    case ALARM: return "ALARM";
    default: return "nieznany";
  }
}

void publishMQTT(int pir, int reed, float ax, float ay, float az) {
  if (!client.connected()) return; 

  JsonDocument doc;
  doc["status"] = getStateString(currentState);
  doc["pir"] = pir;
  doc["drzwi"] = reed;
  
  JsonObject acc = doc["akcelerometr"].to<JsonObject>();
  acc["x"] = round(ax * 100.0) / 100.0; //zaokraglanie by zmniejszyc wage jsona
  acc["y"] = round(ay * 100.0) / 100.0;
  acc["z"] = round(az * 100.0) / 100.0;

  char buffer[256];
  serializeJson(doc, buffer);
  String plainText = String(buffer);
  
  Serial.print("\n[JSON]: ");
  Serial.println(plainText);

  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  const unsigned char key[16] = {'1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6'};
  mbedtls_aes_setkey_enc(&aes, key, 128);

  int originalLen = plainText.length();
  int paddedLen = originalLen + (16 - (originalLen % 16));
  
  //uzycie buforow statycznych zamiast new/delete zapobiega fragmentacji sterty
  unsigned char paddedData[288] = {0}; 
  unsigned char encryptedData[288] = {0};

  memcpy(paddedData, plainText.c_str(), originalLen);
  unsigned char padByte = paddedLen - originalLen;
  for (int i = originalLen; i < paddedLen; i++) {
    paddedData[i] = padByte; //dopelnianie pkcs7
  }

  for (int i = 0; i < paddedLen; i += 16) {
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, paddedData + i, encryptedData + i);
  }

  String hexOutput = "";
  for (int i = 0; i < paddedLen; i++) {
    char hex[3];
    sprintf(hex, "%02x", encryptedData[i]);
    hexOutput += hex;
  }

  mbedtls_aes_free(&aes);

  Serial.print("[AES]: ");
  Serial.println(hexOutput);
  client.publish(mqtt_topic, hexOutput.c_str());
}

void handleKeypad() {
  char key = keypad.getKey();
  
  if (key && currentState == DISARMED) {
    inputCode += key;
    Serial.print("*");
    
    if (inputCode.length() == 4) {
      if (inputCode == "1234") { //hardkodowany pin autoryzacji
        currentState = ARMING;
        stateTimer = millis();
        digitalWrite(BUZZER_PIN, HIGH); delay(100); digitalWrite(BUZZER_PIN, LOW);
        Serial.println("\nKod poprawny. Masz 5s na wyjscie");
      } else {
        Serial.println("\nZly kod");
      }
      inputCode = "";
    }
  }
}

void handleRFID() {
  if (rfid.PICC_IsNewCardPresent() && rfid.PICC_ReadCardSerial()) {
    bool match = true;
    for (byte i = 0; i < 4; i++) {
      if (rfid.uid.uidByte[i] != masterUID[i]) match = false;
    }

    if (match) {
      currentState = DISARMED;
      digitalWrite(BUZZER_PIN, LOW);
      Serial.println("Zautoryzowano. Rozbrojono alarm");
    } else {
      Serial.println("Zla karta");
    }
    rfid.PICC_HaltA();
  }
}

void loop() {
  if (!client.connected()) reconnectMQTT();
  client.loop();

  handleKeypad();
  handleRFID();

  int currentPir = digitalRead(PIR_PIN);
  int currentReed = digitalRead(REED_PIN);
  sensors_event_t event;
  accel.getEvent(&event);
  float cAx = event.acceleration.x;
  float cAy = event.acceleration.y;
  float cAz = event.acceleration.z;

  bool forcePublish = false;

  if (currentState == DISARMED || currentState == ARMING) {
      currentPir = 0; //maskowanie ruchu dla autoryzowanych akcji
  }

  if (currentState != lastReportedState) forcePublish = true;

  if (currentState == ARMED || currentState == PENDING_ALARM || currentState == ALARM) {
      if (currentPir != lastPirState) forcePublish = true;
      if (currentReed != lastReedState) forcePublish = true;
      if (abs(cAx - lastAccX) > 1.5 || abs(cAy - lastAccY) > 1.5 || abs(cAz - lastAccZ) > 1.5) {
          forcePublish = true; //wykrycie drgan
      }
  }

  switch (currentState) {
    case DISARMED:
      break;
    case ARMING:
      if (millis() - stateTimer >= EXIT_DELAY) {
        currentState = ARMED;
        Serial.println("System Uzbrojony");
        digitalWrite(BUZZER_PIN, HIGH); delay(200); digitalWrite(BUZZER_PIN, LOW);
      }
      break;
    case ARMED:
      if (digitalRead(PIR_PIN) == HIGH || digitalRead(REED_PIN) == HIGH || abs(cAx) > 3.0) {
        currentState = PENDING_ALARM;
        stateTimer = millis();
        Serial.println("Intruz. 5s na autoryzacje");
        digitalWrite(BUZZER_PIN, HIGH); delay(50); digitalWrite(BUZZER_PIN, LOW); 
      }
      break;
    case PENDING_ALARM:
      if (millis() - stateTimer >= ENTRY_DELAY) {
        currentState = ALARM;
        Serial.println("ALARM WYZWOLONY");
      }
      break;
    case ALARM:
      digitalWrite(BUZZER_PIN, (millis() / 500) % 2); //pulsowanie buzzera
      break;
  }

  if (currentState != lastReportedState) forcePublish = true;

  if (forcePublish || (millis() - ostatniRaport >= INTERWAL_RAPORTU)) {
    publishMQTT(currentPir, currentReed, cAx, cAy, cAz);
    
    ostatniRaport = millis();
    lastReportedState = currentState;
    lastPirState = currentPir;
    lastReedState = currentReed;
    lastAccX = cAx;
    lastAccY = cAy;
    lastAccZ = cAz;
  }
}