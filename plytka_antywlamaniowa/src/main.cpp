#include <Arduino.h>
#include <SPI.h>
#include <MFRC522.h>
#include <Keypad.h>
#include <Wire.h>
#include <Adafruit_Sensor.h>
#include <Adafruit_ADXL345_U.h>

#define PIR_PIN 34 //pin od czujnika ruchu
#define REED_PIN 14 //pin kontaktronu
#define BUZZER_PIN 15 //pin buzzera
#define RFID_SS 5
#define RFID_RST 4

const byte ROWS = 4; 
const byte COLS = 4; 
char keys[ROWS][COLS] = {
  {'1','2','3','A'}, {'4','5','6','B'}, {'7','8','9','C'}, {'*','0','#','D'}
};
byte rowPins[ROWS] = {32, 33, 25, 26}; //wiersze klawiatury
byte colPins[COLS] = {27, 13, 16, 17}; //kolumny klawiatury
Keypad keypad = Keypad(makeKeymap(keys), rowPins, colPins, ROWS, COLS);

MFRC522 rfid(RFID_SS, RFID_RST);
byte masterUID[] = {0x5A, 0x60, 0xFF, 0x06}; //moje uid z karty

Adafruit_ADXL345_Unified accel = Adafruit_ADXL345_Unified(12345);

enum SystemState { DISARMED, ARMED, ALARM };
SystemState currentState = DISARMED; //na start alarm wylaczony
String inputCode = "";

unsigned long ostatniRaport = 0;
const unsigned long INTERWAL_RAPORTU = 10000; //czas miedzy raportami 10s

void setup() {
  Serial.begin(115200);
  pinMode(PIR_PIN, INPUT);
  pinMode(REED_PIN, INPUT_PULLUP); //wewnetrzny pullup dla drzwi
  pinMode(BUZZER_PIN, OUTPUT);
  
  SPI.begin();
  rfid.PCD_Init();
  Wire.begin(21, 22);
  accel.begin();
  
  Serial.println("start... wpisz 1234 zeby uzbroic");
}

void loop() {
  char key = keypad.getKey();
  
  if (key) { //czytanie pinu z klawiatury
    inputCode += key;
    Serial.print("*");
    if (inputCode.length() == 4) {
      if (inputCode == "1234") {
        currentState = ARMED;
        digitalWrite(BUZZER_PIN, HIGH); delay(100); digitalWrite(BUZZER_PIN, LOW); //krotkie pikniecie
        Serial.println("\nuzbrojono system");
      } else {
        Serial.println("\nzly kod");
      }
      inputCode = "";
    }
  }

  if (rfid.PICC_IsNewCardPresent() && rfid.PICC_ReadCardSerial()) { //obsluga karty rfid
    bool match = true;
    Serial.print("uid karty: ");
    for (byte i = 0; i < 4; i++) {
      Serial.print(rfid.uid.uidByte[i], HEX); Serial.print(" ");
      if (rfid.uid.uidByte[i] != masterUID[i]) match = false;
    }
    Serial.println();

    if (match) {
      currentState = DISARMED;
      digitalWrite(BUZZER_PIN, LOW); //wylaczenie syreny
      Serial.println("rozbrojono alarm");
    } else {
      Serial.println("zla karta!");
    }
    rfid.PICC_HaltA(); //zatrzymanie czytania zeby nie spamowalo
  }

  if (currentState == ARMED) { //sprawdzanie czujnikow tylko jak uzbrojony
    bool trigger = false;
    
    if (digitalRead(PIR_PIN) == HIGH) trigger = true; //ruch
    if (digitalRead(REED_PIN) == HIGH) trigger = true; //otwarcie drzwi
    
    sensors_event_t event;
    accel.getEvent(&event);
    if (abs(event.acceleration.x) > 3.0) trigger = true; //duze drgania

    if (trigger) {
      currentState = ALARM;
      Serial.println("ALARM! wykryto intruza");
    }
  }

  if (currentState == ALARM) {
    digitalWrite(BUZZER_PIN, (millis() / 500) % 2); //przerywany dzwiek buzzera
  }

  if (millis() - ostatniRaport >= INTERWAL_RAPORTU) { //raport co 10 sekund
    ostatniRaport = millis(); 

    sensors_event_t event;
    accel.getEvent(&event);

    Serial.println("\n--- stany czujnikow ---");
    
    Serial.print("status: ");
    if (currentState == DISARMED) Serial.println("rozbrojony");
    else if (currentState == ARMED) Serial.println("czuwa");
    else Serial.println("alarm wyje");

    Serial.print("pir: ");
    Serial.println(digitalRead(PIR_PIN) == HIGH ? "1" : "0");

    Serial.print("drzwi: ");
    Serial.println(digitalRead(REED_PIN) == HIGH ? "1" : "0");

    Serial.print("akcelerometr: ");
    Serial.print("x:"); Serial.print(event.acceleration.x);
    Serial.print(" y:"); Serial.print(event.acceleration.y);
    Serial.print(" z:"); Serial.println(event.acceleration.z);
  }
}