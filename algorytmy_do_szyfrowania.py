import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# base64 tylko kodowanie
def test_base64(payload):
    zakodowane = base64.b64encode(payload.encode('utf-8')).decode('utf-8')
    print(f"base64: {zakodowane}")

# szyfr cezara
def test_cezar(payload):
    shift = 3
    output = ""
    for c in payload:
        if 32 <= ord(c) <= 126:
            output += chr((ord(c) - 32 + shift) % 95 + 32)
        else:
            output += c
    print(f"cezar: {output}")

# prosty xor
def test_xor(payload):
    klucz = "1234"
    output = bytearray()
    for i, c in enumerate(payload.encode('utf-8')):
        output.append(c ^ ord(klucz[i % len(klucz)]))
    print(f"xor hex: {output.hex()}")

# vigenere
def test_vigenere(payload):
    klucz = "TAJNE"
    output = ""
    for i, c in enumerate(payload):
        k = klucz[i % len(klucz)]
        shift = ord(k) - 32
        if 32 <= ord(c) <= 126:
            output += chr((ord(c) - 32 + shift) % 95 + 32)
        else:
            output += c
    print(f"vigenere: {output}")

# rc4
def test_rc4(payload):
    klucz = b"1234567890123456"
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + klucz[i % len(klucz)]) % 256
        S[i], S[j] = S[j], S[i]

    i = 0
    j = 0
    output = bytearray()
    for char in payload.encode('utf-8'):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        output.append(char ^ K)
    print(f"rc4 hex: {output.hex()}")

# aes ecb
def test_aes_ecb(payload):
    klucz = b"1234567890123456"
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(payload.encode('utf-8')) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(klucz), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    output = encryptor.update(padded_data) + encryptor.finalize()
    print(f"aes-ecb hex: {output.hex()}")

# aes cbc
def test_aes_cbc(payload):
    klucz = b"1234567890123456"
    iv = bytes([0] * 16)
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(payload.encode('utf-8')) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(klucz), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    output = encryptor.update(padded_data) + encryptor.finalize()
    print(f"aes-cbc hex: {output.hex()}")

# aes gcm
def test_aes_gcm(payload):
    klucz = b"1234567890123456"
    nonce = bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
    
    cipher = Cipher(algorithms.AES(klucz), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    output = encryptor.update(payload.encode('utf-8')) + encryptor.finalize()
    
    print(f"aes-gcm szyfr hex: {output.hex()}")
    print(f"aes-gcm tag hex: {encryptor.tag.hex()}")