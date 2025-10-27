# diagnostic_decrypt.py
import hashlib
from typing import Optional

def derive_key_single32(key: bytes, rounds: int = 3) -> bytes:
    """Previous simple variant: return final 32-byte SHA256 chain value."""
    if not key:
        raise ValueError("empty key")
    h = hashlib.sha256(key).digest()
    for i in range(rounds):
        h = hashlib.sha256(h + bytes([i & 0xFF])).digest()
    return h  # 32 bytes

def derive_key_concat_truncate(key: bytes, rounds: int = 3, out_len: Optional[int] = None) -> bytes:
    """
    Build h0 = SHA256(key), then hi = SHA256(h_{i-1} || byte(i-1)),
    form buffer = h0||h1||... and truncate to out_len.
    If out_len is None, use len(key).
    """
    if not key:
        raise ValueError("empty key")
    if out_len is None:
        out_len = len(key)
    chunks = []
    h = hashlib.sha256(key).digest()
    chunks.append(h)
    for i in range(rounds):
        h = hashlib.sha256(h + bytes([i & 0xFF])).digest()
        chunks.append(h)
    buf = b"".join(chunks)
    if len(buf) < out_len:
        # if still too short, repeat final hash until long enough (unlikely for typical rounds)
        while len(buf) < out_len:
            h = hashlib.sha256(h + b"\x00").digest()
            buf += h
    return buf[:out_len]

def decrypt_with_derived(data: bytes, dkey: bytes) -> bytes:
    n = len(dkey)
    out = bytearray(len(data))
    for i, b in enumerate(data):
        idx = (7 * i + (i % 13)) % n
        tweak = (31 * i + (i >> 2)) & 0xFF
        out[i] = dkey[idx] ^ b ^ tweak
    return bytes(out)

def try_variants(encrypted_hex: str, key_input: str):
    data = bytes.fromhex(encrypted_hex)

    variants = []

    # Interpret key_input as hex string -> raw bytes
    try:
        key_hex_bytes = bytes.fromhex(key_input)
        variants.append(("key_as_hex_decoded", key_hex_bytes))
    except Exception:
        pass

    # Interpret key_input as raw ASCII bytes (no hex decode)
    variants.append(("key_as_ascii", key_input.encode('utf-8')))

    # If key_input looks like hex maybe user included 0x prefix — try to strip it
    if key_input.startswith("0x") or key_input.startswith("0X"):
        try:
            variants.append(("key_hex_strip_0x", bytes.fromhex(key_input[2:])))
        except Exception:
            pass

    rounds_to_try = [1, 2, 3, 4, 5]  # try a few round counts in case of mismatch

    print(f"Trying {len(variants)} key interpretations and {len(rounds_to_try)} round counts.\n")

    for key_name, key_bytes in variants:
        for rounds in rounds_to_try:
            # Variant A: single-32 derived key (the earlier approach)
            d_single = derive_key_single32(key_bytes, rounds=rounds)
            pt_single = decrypt_with_derived(data, d_single)
            ok1 = pt_single.startswith(b"WRECKIT6")
            print(f"[{key_name}] rounds={rounds}  single32 -> startswith WRECKIT6? {ok1}")
            print("  first 48 bytes:", repr(pt_single[:48]))
            if ok1:
                print("  -> Found candidate (single32). Plaintext (utf8 attempt):")
                try:
                    print(pt_single.decode())
                except:
                    print(pt_single)

            # Variant B: concat/truncate to original key length
            d_ct = derive_key_concat_truncate(key_bytes, rounds=rounds, out_len=len(key_bytes))
            pt_ct = decrypt_with_derived(data, d_ct)
            ok2 = pt_ct.startswith(b"WRECKIT6")
            print(f"[{key_name}] rounds={rounds}  concat_trunc(len={len(key_bytes)}) -> startswith WRECKIT6? {ok2}")
            print("  first 48 bytes:", repr(pt_ct[:48]))
            if ok2:
                print("  -> Found candidate (concat_trunc). Plaintext (utf8 attempt):")
                try:
                    print(pt_ct.decode())
                except:
                    print(pt_ct)
            print("-" * 60)
    print("done")

if __name__ == "__main__":
    # Paste your ciphertext hex (exact) and key string you used when calling the handler.
    encrypted_hex = "07de08bd66079c54d1a491a8dd3c3a1066e609be63538b07ee9a89c5db3d1d296ffcefb70d55bb4e868231c3c7c72237602997c2408fb46fdc1056e031cb3c4f4004b9bafbcfb643ce07"
    key_input = "6d616e676f5f7365637265745f6b6579" # replace: either the hex string you used in the web form, or the raw key string
    try:
        try_variants(encrypted_hex, key_input)
    except Exception as e:
        print("error:", e)
