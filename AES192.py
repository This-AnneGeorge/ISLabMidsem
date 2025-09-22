# Activate venv (Linux)
# source ~/py_venvs/global_venv/bin/activate

# AES-192 Encryption & Decryption using PyCryptodome

from Crypto.Cipher import AES  # AES cipher
from Crypto.Util.Padding import pad, unpad  # For block padding

# -------------------- Define plaintext --------------------
plaintext = "Top Secret Data"

# Remove spaces and convert to uppercase (optional)
plaintext = plaintext.replace(" ", "").upper()

# Convert plaintext to bytes
plaintext_bytes = plaintext.encode('utf-8')

# -------------------- Define AES-192 key --------------------
# AES-192 requires 24-byte (192-bit) keys
key_192 = b"FEDCBA9876543210FEDCBA98"  # 24-byte key

# -------------------- Create AES cipher --------------------
# Using ECB mode for simplicity
cipher_encrypt = AES.new(key_192, AES.MODE_ECB)

# -------------------- Pad plaintext to 16-byte blocks --------------------
padded_text = pad(plaintext_bytes, AES.block_size)

# -------------------- Encrypt the plaintext --------------------
cipher_bytes = cipher_encrypt.encrypt(padded_text)

# Display ciphertext in hexadecimal
cipher_hex = cipher_bytes.hex()
print("Encrypted message (AES-192):", cipher_hex)

# -------------------- Decrypt the ciphertext --------------------
cipher_decrypt = AES.new(key_192, AES.MODE_ECB)
decrypted_padded_bytes = cipher_decrypt.decrypt(cipher_bytes)
decrypted_bytes = unpad(decrypted_padded_bytes, AES.block_size)
decrypted_text = decrypted_bytes.decode('utf-8')

print("Decrypted message:", decrypted_text)
