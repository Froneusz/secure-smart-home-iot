import sys
import paho.mqtt.client as mqtt
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
from web3 import Web3
import hashlib, time, json, binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

AES_KEY = b""
token = ""
org = ""
bucket = "dane_esp"
url = "http://localhost:8086"

bufor_systemu = {
    "security": {"status": "OFFLINE", "pir": 0, "drzwi": 0, "acc_x": 0.0, "acc_y": 0.0, "acc_z": 0.0},
    "environment": {"temperatura": "OFFLINE", "wilgotnosc": "OFFLINE"}
}
czas_ostatniej_wiadomosci = {"security": time.time(), "environment": time.time()}

influx_client = InfluxDBClient(url=url, token=token, org=org)
write_api = influx_client.write_api(write_options=SYNCHRONOUS)

def deszyfruj_aes(hex_payload):
    try:
        encrypted_bytes = binascii.unhexlify(hex_payload) 
        cipher = Cipher(algorithms.AES(AES_KEY), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_bytes) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()
    except: return None

def on_message(client, userdata, message):
    try:
        raw_payload = message.payload.decode("utf-8")
        dev = "security" if "antywlamaniowa" in message.topic else "environment"
        czas_ostatniej_wiadomosci[dev] = time.time()
        
        ts = time.time_ns()
        dane_plaskie = {"raw_enc": raw_payload} # Zawsze zapisujemy surowy HEX

        czysty_bin = deszyfruj_aes(raw_payload)
        if czysty_bin:
            dane = json.loads(czysty_bin.decode('utf-8'))
            if dev == "security":
                acc = dane.get("akcelerometr", {})
                dane_plaskie.update({
                    "acc_x": acc.get("x", 0.0), "acc_y": acc.get("y", 0.0), "acc_z": acc.get("z", 0.0),
                    "status": dane.get("status", "OFFLINE"), "pir": dane.get("pir", 0), "drzwi": dane.get("drzwi", 0)
                })
            bufor_systemu[dev].update(dane_plaskie)
            print(f"[OK] Odszyfrowano {dev}. Status: {dane_plaskie.get('status')}")

        for sensor, val in dane_plaskie.items():
            point = Point("pomiary_srodowiskowe").tag("urzadzenie", dev).tag("sensor", sensor).time(ts)
            point.field("value", float(val) if isinstance(val, (int, float)) else str(val))
            write_api.write(bucket=bucket, org=org, record=point)
            
    except Exception as e: print(f"Błąd MQTT: {e}")

mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
mqtt_client.on_message = on_message
mqtt_client.connect("localhost", 1883)
mqtt_client.subscribe([("/plytka_antywlamaniowa/zaszyfrowane", 0)])
mqtt_client.loop_start()

print("--- SYSTEM KRYPTOGRAFICZNY URUCHOMIONY ---")
while True: time.sleep(1)