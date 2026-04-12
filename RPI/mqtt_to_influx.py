import paho.mqtt.client as mqtt
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
from web3 import Web3
import hashlib
import time
import json
import binascii

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# klucz musi byc taki sam jak na esp (16 znakow)
AES_KEY = b"" 
IV = bytes([0] * 16) 

# ustawienia bazy influx
token = ""
org = ""
bucket = "dane_esp"
url = "http://localhost:8086"

influx_client = InfluxDBClient(url=url, token=token, org=org)
write_api = influx_client.write_api(write_options=SYNCHRONOUS)

# ustawienia lokalnego blockchaina
w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))
w3.eth.default_account = w3.eth.accounts[0]

bufor_czujnikow = {}
OSTATNI_ANCHOR = time.time()
INTERWAL_SEKUNDY = 10 # wysylka co 10s

def deszyfruj_aes(hex_payload):
    try:
        encrypted_bytes = binascii.unhexlify(hex_payload) # zamiana hex na bajty
        
        cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(IV), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # deszyfrowanie i wywalenie paddingu
        padded_data = decryptor.update(encrypted_bytes) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        clean_data = unpadder.update(padded_data) + unpadder.finalize()
        
        return clean_data.decode('utf-8')
    except Exception as e:
        print(f"blad deszyfrowania: {e}")
        return None

def wyslij_zbiorczy_hash():
    global OSTATNI_ANCHOR, bufor_czujnikow
    
    if not bufor_czujnikow:
        return

    # sklejanie stringa tak jak na froncie
    t = bufor_czujnikow.get('temperatura', 0)
    w = bufor_czujnikow.get('wilgotnosc', 0)
    c = bufor_czujnikow.get('cisnienie', 0)
    g = bufor_czujnikow.get('gazy', 0)
    s = bufor_czujnikow.get('swiatlo', 0)
    d = bufor_czujnikow.get('dzwiek', 0)

    data_string = f"T:{t}|W:{w}|C:{c}|G:{g}|S:{s}|D:{d}"
    data_hash = hashlib.sha256(data_string.encode()).hexdigest()

    try:
        tx_data = Web3.to_bytes(hexstr=data_hash)
        tx = {
            'to': w3.eth.accounts[0], 
            'from': w3.eth.accounts[0],
            'value': 0,
            'gas': 100000,
            'gasPrice': w3.eth.gas_price,
            'data': tx_data
        }
        tx_hash = w3.eth.send_transaction(tx)
        
        print("\n--- zapis do blockchaina ---")
        print(f"dane: {data_string}")
        print(f"hash: {data_hash}")
        print(f"tx: {tx_hash.hex()[:10]}...")
        
    except Exception as e:
        print(f"blad blockchain: {e}")

    OSTATNI_ANCHOR = time.time()

def on_message(client, userdata, message):
    global OSTATNI_ANCHOR
    
    try:
        hex_payload = message.payload.decode("utf-8")
        print("\nodbior paczki mqtt (zaszyfrowana)")
        
        czysty_json = deszyfruj_aes(hex_payload)
        
        if czysty_json:
            dane = json.loads(czysty_json)
            print(f"odszyfrowano: {czysty_json}")
            
            # zapis do influxa i aktualizacja bufora
            for sensor, val in dane.items():
                point = Point("pomiary_srodowiskowe").tag("sensor", sensor).field("value", float(val))
                write_api.write(bucket=bucket, org=org, record=point)
                bufor_czujnikow[sensor] = float(val)

            # jak wykryje dzwiek to od razu kotwiczy
            if dane.get('dzwiek') == 1:
                print("wykryto halas! natychmiastowy zapis na blockchain")
                wyslij_zbiorczy_hash()
            elif time.time() - OSTATNI_ANCHOR >= INTERWAL_SEKUNDY:
                wyslij_zbiorczy_hash()
                
    except Exception as e:
        print(f"blad przetwarzania: {e}")

mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
mqtt_client.on_message = on_message
mqtt_client.connect("localhost", 1883)

mqtt_client.subscribe("/plytka_srodowiskoa/zaszyfrowane") # slucha tylko zaszyfrowanego kanalu

print("serwer python ruszyl")
print("tryb: aes-128 + blockchain")
mqtt_client.loop_forever()