import binascii
import hashlib

def derive_key(key: bytes, rounds: int) -> bytes:
    """
    Replicates the key derivation logic from the main.deriveKey function.
    
    The algorithm is:
    1. Start with the SHA-256 hash of the original key.
    2. For the specified number of rounds, append the round number (as a byte)
       to the current hash and calculate the SHA-256 hash of that new data.
    """
    # 1. Start with derived_key = SHA256(original_key)
    derived = hashlib.sha256(key).digest()
    
    # 2. Loop `rounds` times (the disassembly shows this was called with rounds=3)
    for i in range(rounds):
        # Append the round number (0, 1, 2) as a single byte
        data_to_hash = derived + bytes([i])
        
        # Update the derived key with the new hash
        derived = hashlib.sha256(data_to_hash).digest()
        
    return derived

def decrypt(encrypted_data: bytes, key: bytes) -> bytes:
    """
    Replicates the decryption logic from the provided Go disassembly.
    """
    if not key:
        raise ValueError("Key cannot be empty")

    decrypted_bytes = bytearray()
    data_len = len(encrypted_data)
    key_len = len(key)

    for i in range(data_len):
        key_byte = key[(8 * i) % key_len]
        generated_byte = (31 * i + (i >> 2)) & 0xFF
        decrypted_byte = encrypted_data[i] ^ key_byte ^ generated_byte
        decrypted_bytes.append(decrypted_byte)

    return bytes(decrypted_bytes)

if __name__ == '__main__':
    # TODO: Replace these with your actual encrypted flag and key
    encrypted_flag_hex = "07de08bd66079c54d1a4f788da337f3259c836b1544eb643d8858682c20e1c3961e288d56626aa3fff9a38f2cdfd075c5a1e96f560d98877c31f09e56ec8227c6b0581ccd696a95eac07"
    key_hex = "6d616e676f5f7365637265745f6b6579"

    ROUNDS = 3 # From the call to main_deriveKey(key, 3, ...)

    try:
        # 1. Decode the hex strings into bytes
        encrypted_data = binascii.unhexlify(encrypted_flag_hex)
        initial_key = binascii.unhexlify(key_hex)

        # 2. Derive the final key using the newly discovered algorithm
        print(f"🔑 Deriving key with {ROUNDS} rounds...")
        final_key = derive_key(initial_key, ROUNDS)
        print("   Derived key (hex):", final_key.hex())

        # 3. Decrypt the data using the derived key
        decrypted_result = decrypt(encrypted_data, final_key)

        # 4. Print the result
        print(f"\n✅ Decrypted successfully!")
        try:
            print(f"   Result: {decrypted_result.decode('utf-8')}")
        except UnicodeDecodeError:
            print(f"   Result (raw bytes): {decrypted_result}")

    except binascii.Error as e:
        print(f"❌ Error: Invalid hex string provided. {e}")
    except ValueError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")