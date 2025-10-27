import hashlib
from typing import Union

def derive_key(key: bytes, rounds: int = 3) -> bytes:
    """
    Port of main_deriveKey:
      h0 = SHA256(key)
      for i in 0..rounds-1:
          h_{i+1} = SHA256(h_i || single_byte(i))
    Returns the final 32-byte hash (used cyclically by decrypt).
    """
    if not key:
        raise ValueError("empty key")

    h = hashlib.sha256(key).digest()
    for i in range(rounds):
        h = hashlib.sha256(h + bytes([i & 0xFF])).digest()
    return h  # 32 bytes


def decrypt_bytes(data: bytes, key: bytes) -> bytes:
    """
    Port of main_decrypt:
      out[i] = DKEY[idx] ^ data[i] ^ ((31*i + (i >> 2)) & 0xFF)
      where idx = (7*i + (i % 13)) % len(DKEY)
      and DKEY = derive_key(key, 3)
    """
    if not key:
        raise ValueError("key must be non-empty")

    dkey = derive_key(key, rounds=3)  # 32 bytes
    n = len(dkey)
    out = bytearray(len(data))

    for i, b in enumerate(data):
        idx = (7 * i + (i % 13)) % n
        tweak = (31 * i + (i >> 2)) & 0xFF
        out[i] = dkey[idx] ^ b ^ tweak

    return bytes(out)


# --- Helpers mirroring the HTTP handler’s hex I/O ---
def decrypt_hex(encrypted_hex: Union[str, bytes], key_hex: Union[str, bytes]) -> bytes:
    if isinstance(encrypted_hex, bytes):
        encrypted_hex = encrypted_hex.decode("ascii")
    if isinstance(key_hex, bytes):
        key_hex = key_hex.decode("ascii")

    try:
        data = bytes.fromhex(encrypted_hex)
    except ValueError:
        raise ValueError("Invalid hex string for 'encrypted'")

    try:
        key = bytes.fromhex(key_hex)
    except ValueError:
        raise ValueError("Invalid hex string for 'key'")

    return decrypt_bytes(data, key)


# --- Example usage (fill in your real values) ---
if __name__ == "__main__":
    # Replace with your actual ciphertext and key (both hex strings)
    encrypted_hex = "07de08bd66079c54d1a491a8dd3c3a1066e609be63538b07ee9a89c5db3d1d296ffcefb70d55bb4e868231c3c7c72237602997c2408fb46fdc1056e031cb3c4f4004b9bafbcfb643ce07"
    key_hex = "6d616e676f5f7365637265745f6b6579"

    pt = decrypt_hex(encrypted_hex, key_hex)
    # The handler prints "Decrypted: %s" (treats as text if possible)
    try:
        print(f"Decrypted: {pt.decode('utf-8')}")
    except UnicodeDecodeError:
        print(f"Decrypted bytes: {pt!r}")
