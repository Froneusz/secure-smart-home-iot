#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <PubSubClient.h>
#include <Wire.h>
#include <Adafruit_Sensor.h>
#include <Adafruit_BME280.h>
#include <BH1750.h>
#include <bearssl/bearssl.h> //natywny silnik dla esp

const char* ssid = "";
const char* password = "";
const char* mqtt_server = "";

const char* aes_key = ""; //klucz musi miec 16 znakow

String szyfrujDane(String payload) {
  br_aes_ct_cbcenc_keys ctx;
  br_aes_ct_cbcenc_init(&ctx, aes_key, 16);

  unsigned char iv[16] = {0}; //wektor same zera

  int len = payload.length();
  int padded_len = len + (16 - (len % 16));
  unsigned char buffer[padded_len];

  uint8_t pad_val = padded_len - len;
  payload.getBytes(buffer, len + 1); 
  
  for (int i = len; i < padded_len; i++) { //wypelnianie paddingiem
    buffer[i] = pad_val;
  }

  br_aes_ct_cbcenc_run(&ctx, iv, buffer, padded_len); //szyfrowanie

  String encryptedHex = "";
  for (int i = 0; i < padded_len; i++) { //zamiana na hex
    char hex[3];
    sprintf(hex, "%02x", buffer[i]);
    encryptedHex += hex;
  }

  return encryptedHex;
}

#define MQ135_PIN A0
#define SOUND_PIN D5
#define I2C1_SDA D2
#define I2C1_SCL D1
#define I2C2_SDA D6
#define I2C2_SCL D7

Adafruit_BME280 bme;
BH1750 lightMeter;
WiFiClient espClient;
PubSubClient client(espClient);

unsigned long lastPublishTime = 0; 
const unsigned long normalInterval = 60000;  //co 60 sekund
const unsigned long antiSpamInterval = 3000; //blokada spamu co 3s 

void setup_wifi() {
  delay(10);
  Serial.print("\nlacze z wifi: ");
  Serial.println(ssid);

  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("\npolaczono z wifi");
  Serial.println(WiFi.localIP());
}

void reconnect() {
  while (!client.connected()) {
    Serial.print("laczenie z mqtt... ");
    String clientId = "ESP8266Client-";
    clientId += String(random(0xffff), HEX);
    
    if (client.connect(clientId.c_str())) {
      Serial.println("ok");
    } else {
      Serial.print("blad ");
      Serial.print(client.state());
      Serial.println(" proba za 5s");
      delay(5000);
    }
  }
}

void setup() {
  Serial.begin(115200);
  Serial.println("\nstart systemu (aes)");

  pinMode(MQ135_PIN, INPUT);
  pinMode(SOUND_PIN, INPUT);

  setup_wifi();
  client.setServer(mqtt_server, 1883);
  client.setBufferSize(512);

  Wire.begin(I2C1_SDA, I2C1_SCL); 
  if (!bme.begin(0x76, &Wire)) Serial.println("blad bme280");
  
  Wire.begin(I2C2_SDA, I2C2_SCL); 
  if (!lightMeter.begin(BH1750::CONTINUOUS_HIGH_RES_MODE, 0x23, &Wire)) Serial.println("blad bh1750");
}

void loop() {
  if (!client.connected()) {
    reconnect();
  }
  client.loop(); 

  unsigned long currentMillis = millis();
  int soundStatus = digitalRead(SOUND_PIN);
  bool shouldPublish = false;

  if (currentMillis - lastPublishTime >= normalInterval) {
    shouldPublish = true;
  } 
  else if (soundStatus == HIGH && (currentMillis - lastPublishTime >= antiSpamInterval)) {
    shouldPublish = true;
    Serial.println("wykryto dzwiek!");
  }

  if (shouldPublish) {
    lastPublishTime = currentMillis;

    int gasValue = analogRead(MQ135_PIN); 
    Wire.begin(I2C1_SDA, I2C1_SCL);
    float temp = bme.readTemperature();
    float hum = bme.readHumidity();
    float pres = bme.readPressure() / 100.0F;
    
    Wire.begin(I2C2_SDA, I2C2_SCL);
    float lux = lightMeter.readLightLevel();

    String payload = "{"; //sklejanie jsona
    payload += "\"temperatura\":" + String(temp) + ",";
    payload += "\"wilgotnosc\":" + String(hum) + ",";
    payload += "\"cisnienie\":" + String(pres) + ",";
    payload += "\"gazy\":" + String(gasValue) + ",";
    payload += "\"swiatlo\":" + (lux >= 0 ? String(lux) : "0") + ",";
    payload += "\"dzwiek\":" + String(soundStatus);
    payload += "}";

    String encryptedPayload = szyfrujDane(payload);

    bool sukces = client.publish("/plytka_srodowiskoa/zaszyfrowane", encryptedPayload.c_str());

    Serial.println("txt: " + payload);
    Serial.println("hex: " + encryptedPayload);
    
    if (sukces) {
      Serial.println("wyslano mqtt");
    } else {
      Serial.println("blad wysylki mqtt");
    }
  }
}