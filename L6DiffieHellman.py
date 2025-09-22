#Python Diffie-Hellman + Hash Integrity Demo# -------------------- Imports --------------------
import random
import hashlib

# -------------------- Diffie-Hellman Key Exchange --------------------
# Step 1: Agree on public parameters (prime p and generator g)
p = 23  # Small prime for demo; in real life use large prime (1024+ bits)
g = 5   # Primitive root modulo p

# Party A (Alice) private key
a_private = random.randint(1, p-2)
# Party B (Bob) private key
b_private = random.randint(1, p-2)

# Compute public keys
A_public = pow(g, a_private, p)  # Alice sends this to Bob
B_public = pow(g, b_private, p)  # Bob sends this to Alice

print(f"Alice Public Key: {A_public}")
print(f"Bob Public Key: {B_public}")

# -------------------- Generate Shared Secret --------------------
# Alice computes shared secret
shared_secret_alice = pow(B_public, a_private, p)
# Bob computes shared secret
shared_secret_bob = pow(A_public, b_private, p)

print(f"Shared Secret (Alice): {shared_secret_alice}")
print(f"Shared Secret (Bob): {shared_secret_bob}")

# Ensure both shared secrets are equal
assert shared_secret_alice == shared_secret_bob, "Key exchange failed!"

# Convert shared secret to bytes for XOR encryption
shared_key = shared_secret_alice.to_bytes((shared_secret_alice.bit_length() + 7) // 8, byteorder='big')

# -------------------- Simple XOR Encryption/Decryption --------------------
def xor_encrypt_decrypt(message, key):
    """Encrypt/decrypt message using XOR with key"""
    message_bytes = message.encode()
    key_len = len(key)
    result = bytes([b ^ key[i % key_len] for i, b in enumerate(message_bytes)])
    return result

# -------------------- Custom Hash Function --------------------
def custom_hash(input_bytes):
    """Compute a 32-bit hash using djb2 algorithm on bytes"""
    hash_value = 5381
    for b in input_bytes:
        hash_value = ((hash_value * 33) + b) & 0xFFFFFFFF
        hash_value = hash_value ^ (hash_value >> 16)
    return hash_value

# -------------------- Message Transmission --------------------
message = "ConfidentialData123"
print("\nOriginal Message:", message)

# Sender encrypts the message
encrypted_msg = xor_encrypt_decrypt(message, shared_key)
print("Encrypted Message (bytes):", encrypted_msg)

# Compute hash of original message
hash_original = custom_hash(message.encode())
print("Hash of Original Message:", hash_original)

# Simulate sending message over insecure channel
received_msg = encrypted_msg  # In real network, this could be intercepted

# Receiver decrypts the message
decrypted_msg = xor_encrypt_decrypt(received_msg, shared_key).decode()
print("Decrypted Message:", decrypted_msg)

# Receiver computes hash
hash_received = custom_hash(decrypted_msg.encode())
print("Hash of Decrypted Message:", hash_received)

# Verify integrity
if hash_original == hash_received:
    print("Data Integrity Verified ")
else:
    print("Data Integrity Failed ")
