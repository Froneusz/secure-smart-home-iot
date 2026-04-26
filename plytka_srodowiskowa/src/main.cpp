#include <Arduino.h>
#include <Wire.h>
#include <Adafruit_Sensor.h>
#include <Adafruit_BME280.h>

#define SOUND_PIN D5

// Magistrala I2C
#define I2C_SDA D6
#define I2C_SCL D5

Adafruit_BME280 bme;

unsigned long lastPrintTime = 0;
unsigned long lastSoundTime = 0;
const unsigned long normalInterval = 10000;  // rzut co 10 sekund
const unsigned long antiSpamInterval = 2000; // 2 sekundy przerwy po dźwięku

// Funkcja wypisująca TYLKO temperaturę
void odczytajIWypisz(String powod) {
  Serial.println("\n--- NOWY ODCZYT (" + powod + ") ---");

  float temp = bme.readTemperature();
  
  Serial.print("Temperatura:  "); 
  Serial.print(temp); 
  Serial.println(" °C");
  
  Serial.println("---------------------------------");
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("\n\n--- START SYSTEMU (TYLKO TEMPERATURA) ---");

  pinMode(SOUND_PIN, INPUT);

  // Inicjalizacja I2C
  Wire.begin(I2C_SDA, I2C_SCL);

  // Odpalamy BME280
  if (!bme.begin(0x76, &Wire)) {
    Serial.println("BME280: BLAD! Sprawdz kabelki na D1/D2");
  } else {
    Serial.println("BME280: Zalogowano poprawnie.");
  }
}

void loop() {
  unsigned long currentMillis = millis();
  int soundStatus = digitalRead(SOUND_PIN);

  bool periodicTrigger = (currentMillis - lastPrintTime >= normalInterval);
  bool soundTrigger = (soundStatus == HIGH && (currentMillis - lastSoundTime >= antiSpamInterval));

  if (periodicTrigger || soundTrigger) {
    if (soundTrigger) {
      lastSoundTime = currentMillis;
      odczytajIWypisz("WYKRYTO DZWIEK!");
    } else {
      lastPrintTime = currentMillis;
      odczytajIWypisz("Zegar 10s");
    }
  }
}