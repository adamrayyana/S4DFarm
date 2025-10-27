#!/usr/bin/env python3
from requests import get
from sotong import decrypt_hex as sotong
from bengsky import decrypt_blob as beng
import sys
from pwn import xor
ip = sys.argv[1] 

a = get("http://" + ip + ":14000/flag")
b = get("http://" + ip + ":14000/key")


import binascii

def decrypt(encrypted_hex, key_hex):
    encrypted = bytearray(binascii.unhexlify(encrypted_hex))
    key = bytearray(binascii.unhexlify(key_hex))
    out = bytearray()
    for i, b in enumerate(encrypted):
        out.append(b ^ key[(i + 2) % len(key)])
    return out.decode(errors="ignore")



def decrypt2(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("empty key")

    derived = key
    out = bytearray(len(data))

    for i in range(len(data)):
        idx = (7 * i) % len(key)
        mask = (31 * i + (i >> 2)) % 256
        out[i] = derived[idx] ^ data[i] ^ mask

    return bytes(out)
try: 
    print(decrypt2(bytes.fromhex(a.text), bytes.fromhex(b.text) ), flush=True)
except:
    pass
try:
    print(decrypt(a.text,b.text), flush=True)
except:
    pass

# steven
print(xor(bytes.fromhex(a.text), b'different_secret_key_12345678'), flush=True)
# normal
print(xor(bytes.fromhex(a.text), bytes.fromhex(b.text)), flush=True)
# oyf
print(xor(xor(bytes.fromhex(a.text), bytes.fromhex(b.text)),2 ), flush=True)

try:
    print(beng(a.text, '6d616e676f5f7e65637265745f6b6579'), flush=True)
except:
    pass
# sotong
try:
    print(sotong(a.text, b.text), flush=True)
except:
    pass