# decrypt_cbc.py
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import sys, binascii, base64

# 1) derive key
secret_hex = "6d616e676f5f7e65637265745f6b6579"
secret_bytes = binascii.unhexlify(secret_hex)        # b"mango_~ecret_key"
key = sha256(secret_bytes).digest()                   # 32 bytes (AES-256)

def decrypt_blob(blob: bytes, key) -> bytes:
    blob = bytes.fromhex(blob)
    key = bytes.fromhex(key)
    if len(blob) < 16:
        raise ValueError("ciphertext too short (needs 16-byte IV + data)")
    if ((len(blob) - 16) & 0xF) != 0:
        raise ValueError("ciphertext length-16 must be a multiple of 16")
    iv, ct = blob[:16], blob[16:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    pt_padded = aes.decrypt(ct)
    # PKCS#7 unpad
    return unpad(pt_padded, 16)

if __name__ == "__main__":
    data = b'b68de7a78cc09616628ca7cbf38becb49c93d7e89d611a62237cb1fc1f0485b47469f744103aeaf08d49b4056ed0daf4a59572c0b3e81105860d3ccef31103e5353e76babcda451b332a1d859223ac44c5fa845d401c80953ae8ce8a152bc800'

    # convenience: accept raw, hex, or base64
    try:
        if all(c in b"0123456789abcdefABCDEF" for c in data) and len(data) % 2 == 0:
            blob = binascii.unhexlify(data)
        else:
            # try base64, otherwise treat as raw bytes
            try:
                blob = base64.b64decode(data, validate=True)
            except Exception:
                blob = data
    except Exception as e:
        raise SystemExit(f"Input decoding error: {e}")

    try:
        pt = decrypt_blob(blob)
        sys.stdout.buffer.write(pt)
    except Exception as e:
        raise SystemExit(f"Decrypt error: {e}")
