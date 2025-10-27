from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import binascii
import sys

def decrypt_hex(encrypted_hex: str, key_hex: str) -> bytes:
    data = binascii.unhexlify(encrypted_hex.strip())
    key_bytes = binascii.unhexlify(key_hex.strip())
    aes_key = SHA256.new(key_bytes).digest()  # 32-byte AES-256 key

    NONCE_SIZE = 12   # from newGCMWithNonceAndTagSize(..., 12, 16)
    TAG_SIZE   = 16

    if len(data) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("ciphertext too short")

    nonce = data[:NONCE_SIZE]
    ct_and_tag = data[NONCE_SIZE:]
    if len(ct_and_tag) < TAG_SIZE:
        raise ValueError("missing tag")

    ct = ct_and_tag[:-TAG_SIZE]
    tag = ct_and_tag[-TAG_SIZE:]

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ct, tag)
    return plaintext