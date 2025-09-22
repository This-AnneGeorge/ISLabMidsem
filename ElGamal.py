# Activate venv (Linux)
# source ~/py_venvs/global_venv/bin/activate

# ElGamal Encryption & Decryption (simplified demonstration)

import random

# -------------------- Define ElGamal parameters --------------------
# Small example prime p (in practice, use very large prime)
p = 467  # Prime modulus
g = 2    # Generator
x = 127  # Private key (1 < x < p)
h = pow(g, x, p)  # Public key component h = g^x mod p

# -------------------- Define plaintext --------------------
plaintext = "Confidential Data"

# Convert plaintext to integer representation (simple method)
# Remove spaces and convert to uppercase
plaintext = plaintext.replace(" ", "").upper()
message_ints = [ord(c) for c in plaintext]  # List of integers

# -------------------- Encrypt the message --------------------
ciphertext_pairs = []

for m in message_ints:
    k = random.randint(1, p-2)  # Random ephemeral key 1 <= k <= p-2
    c1 = pow(g, k, p)           # c1 = g^k mod p
    c2 = (m * pow(h, k, p)) % p # c2 = m * h^k mod p
    ciphertext_pairs.append((c1, c2))  # Store ciphertext pair

# Display ciphertext
print("Encrypted message (ElGamal):")
for c1, c2 in ciphertext_pairs:
    print(f"({c1}, {c2})", end=" ")
print("\n")

# -------------------- Decrypt the message --------------------
decrypted_ints = []

for c1, c2 in ciphertext_pairs:
    s = pow(c1, x, p)             # s = c1^x mod p
    s_inv = pow(s, -1, p)         # Modular inverse of s
    m = (c2 * s_inv) % p          # m = c2 * s^-1 mod p
    decrypted_ints.append(m)

# Convert integers back to characters
decrypted_text = ''.join([chr(m) for m in decrypted_ints])
print("Decrypted message:", decrypted_text)
