# Activate venv (Linux)
# source ~/py_venvs/global_venv/bin/activate

# RSA Encryption & Decryption using PyCryptodome

from Crypto.PublicKey import RSA  # To generate and use RSA keys
from Crypto.Cipher import PKCS1_OAEP  # For RSA encryption/decryption with padding

# -------------------- Generate or define RSA keys --------------------
# For demonstration, generate a small RSA key pair (2048-bit recommended)
key = RSA.generate(2048)

private_key = key  # RSA private key (n, d)
public_key = key.publickey()  # RSA public key (n, e)

# Create cipher objects using PKCS1_OAEP (padding scheme)
cipher_encrypt = PKCS1_OAEP.new(public_key)
cipher_decrypt = PKCS1_OAEP.new(private_key)

# -------------------- Define plaintext --------------------
plaintext = "Asymmetric Encryption"

# Convert plaintext to bytes
plaintext_bytes = plaintext.encode('utf-8')

# -------------------- Encrypt the plaintext --------------------
cipher_bytes = cipher_encrypt.encrypt(plaintext_bytes)

# Display ciphertext in hexadecimal
cipher_hex = cipher_bytes.hex()
print("Encrypted message (RSA):", cipher_hex)

# -------------------- Decrypt the ciphertext --------------------
decrypted_bytes = cipher_decrypt.decrypt(cipher_bytes)
decrypted_text = decrypted_bytes.decode('utf-8')

print("Decrypted message:", decrypted_text)
