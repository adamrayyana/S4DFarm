import binascii

def decrypt(encrypted_hex, key_hex):
    encrypted = bytearray(binascii.unhexlify(encrypted_hex))
    key = bytearray(binascii.unhexlify(key_hex))
    out = bytearray()
    for i, b in enumerate(encrypted):
        out.append(b ^ key[(i + 2) % len(key)])
    return out.decode(errors="ignore")

# Example
encrypted_hex = "39352a1c382c37441e35080d57320f052120082f231c242123376d1b313a0936140d06082500312528466d07301d5f325e11271138305a2404321c5b124c1a3516255e6b11093b1c5d09"  # replace with actual
key_hex = "6d616e676f5f7365637265745f6b6579"            # replace with actual
print(decrypt(encrypted_hex, key_hex))
