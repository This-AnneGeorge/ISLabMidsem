# Activate venv (Linux)
# source ~/py_venvs/global_venv/bin/activate

# DES Encryption & Decryption using PyCryptodome

# Import DES and padding utilities
from Crypto.Cipher import DES  # DES cipher
from Crypto.Util.Padding import pad, unpad  # For block padding

# Define the plaintext
plaintext = "Confidential Data"

# Remove spaces and convert to uppercase (optional for DES)
plaintext = plaintext.replace(" ", "").upper()

# Define the key
key = b"A1B2C3D4"  # Must be 8 bytes for DES

# Create DES cipher in ECB mode for encryption
cipher_encrypt = DES.new(key, DES.MODE_ECB)

# DES operates on multiples of 8 bytes, so pad the plaintext
plaintext_bytes = plaintext.encode('utf-8')  # Convert to bytes
padded_text = pad(plaintext_bytes, DES.block_size)  # Pad to 8-byte blocks

# Encrypt the padded plaintext
cipher_bytes = cipher_encrypt.encrypt(padded_text)

# Display ciphertext in hexadecimal for readability
cipher_hex = cipher_bytes.hex()
print("Encrypted message (DES):", cipher_hex)

# Create DES cipher again for decryption (ECB mode)
cipher_decrypt = DES.new(key, DES.MODE_ECB)

# Decrypt the ciphertext
decrypted_padded_bytes = cipher_decrypt.decrypt(cipher_bytes)

# Remove padding to get original plaintext
decrypted_bytes = unpad(decrypted_padded_bytes, DES.block_size)
decrypted_text = decrypted_bytes.decode('utf-8')

print("Decrypted message:", decrypted_text)
