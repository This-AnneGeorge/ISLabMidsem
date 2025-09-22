# Activate venv (Linux)
# source ~/py_venvs/global_venv/bin/activate

# AES-128 Encryption & Decryption using PyCryptodome

# Import AES cipher and padding utilities
from Crypto.Cipher import AES  # AES cipher
from Crypto.Util.Padding import pad, unpad  # For block padding

# Define the plaintext
plaintext = "Sensitive Information"

# Remove spaces and convert to uppercase (optional)
plaintext = plaintext.replace(" ", "").upper()

# Define the AES-128 key (16 bytes)
full_key = "0123456789ABCDEF0123456789ABCDEF"
key = full_key[:16].encode('utf-8')  # Take first 16 bytes and encode

# Create AES cipher in ECB mode for encryption
cipher_encrypt = AES.new(key, AES.MODE_ECB)

# AES requires blocks of 16 bytes, so pad the plaintext
plaintext_bytes = plaintext.encode('utf-8')  # Convert string to bytes
padded_text = pad(plaintext_bytes, AES.block_size)  # Pad to 16-byte blocks

# Encrypt the padded plaintext
cipher_bytes = cipher_encrypt.encrypt(padded_text)

# Display ciphertext in hexadecimal
cipher_hex = cipher_bytes.hex()
print("Encrypted message (AES-128):", cipher_hex)

# Create AES cipher again for decryption
cipher_decrypt = AES.new(key, AES.MODE_ECB)

# Decrypt the ciphertext
decrypted_padded_bytes = cipher_decrypt.decrypt(cipher_bytes)

# Remove padding to get original plaintext
decrypted_bytes = unpad(decrypted_padded_bytes, AES.block_size)
decrypted_text = decrypted_bytes.decode('utf-8')

print("Decrypted message:", decrypted_text)
