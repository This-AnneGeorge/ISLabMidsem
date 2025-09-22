# -------------------- Imports --------------------
from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes, random
from Crypto.Util.number import GCD, inverse
import hashlib

# -------------------- Generate ElGamal Key Pair --------------------
key = ElGamal.generate(256, get_random_bytes)  # 256-bit ElGamal keys for demo

# Extract public key components
p = key.p
g = key.g
y = key.y  # public component
x = key.x  # private component

print("ElGamal Public Key: (p, g, y)")
print(f"p={p}, g={g}, y={y}")
print("ElGamal Private Key x=", x)

# -------------------- Encryption --------------------
def elgamal_encrypt(message, key):
    """
    Encrypt a plaintext string message using ElGamal.
    Returns a tuple (c1, c2)
    """
    m_int = int.from_bytes(message.encode(), byteorder='big')  # Convert string to int
    while True:
        k = random.StrongRandom().randint(1, key.p - 2)  # Random ephemeral key
        if GCD(k, key.p - 1) == 1:  # k must be coprime with p-1
            break
    c1 = pow(key.g, k, key.p)
    c2 = (m_int * pow(key.y, k, key.p)) % key.p
    return c1, c2

# -------------------- Decryption --------------------
def elgamal_decrypt(cipher_tuple, key):
    """
    Decrypt ElGamal ciphertext tuple (c1, c2) to retrieve original string
    """
    c1, c2 = cipher_tuple
    s = pow(c1, key.x, key.p)
    m_int = (c2 * inverse(s, key.p)) % key.p
    # Convert integer back to string
    message_length = (m_int.bit_length() + 7) // 8
    message = m_int.to_bytes(message_length, byteorder='big').decode()
    return message

# -------------------- Demo --------------------
plaintext = "SecureMessage123"
print("\nOriginal message:", plaintext)

# Encrypt
cipher = elgamal_encrypt(plaintext, key)
print("Ciphertext:", cipher)

# Decrypt
decrypted = elgamal_decrypt(cipher, key)
print("Decrypted message:", decrypted)

# Verify integrity using hash
hash_original = hashlib.sha256(plaintext.encode()).hexdigest()
hash_decrypted = hashlib.sha256(decrypted.encode()).hexdigest()
print("SHA-256 hash of original:", hash_original)
print("SHA-256 hash of decrypted:", hash_decrypted)

if hash_original == hash_decrypted:
    print("Data integrity verified ")
else:
    print("Data integrity failed ")
