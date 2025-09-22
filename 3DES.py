# Activate venv (Linux)
# source ~/py_venvs/global_venv/bin/activate

# Triple DES (3DES) Encryption & Decryption using PyCryptodome

from Crypto.Cipher import DES3  # 3DES cipher
from Crypto.Util.Padding import pad, unpad  # For block padding

# Define the plaintext
plaintext = "Classified Text"

# Remove spaces and convert to uppercase (optional)
plaintext = plaintext.replace(" ", "").upper()

# Convert plaintext to bytes
plaintext_bytes = plaintext.encode('utf-8')

# Define the 3DES key
# Triple DES keys can be 16 or 24 bytes; we have 24-byte key here
key_3des = b"1234567890ABCDEF12345678"  # Take first 24 bytes

# Create 3DES cipher in ECB mode for encryption
cipher_encrypt = DES3.new(key_3des, DES3.MODE_ECB)

# 3DES requires blocks of 8 bytes, so pad the plaintext
padded_text = pad(plaintext_bytes, DES3.block_size)

# Encrypt the padded plaintext
cipher_bytes = cipher_encrypt.encrypt(padded_text)

# Display ciphertext in hexadecimal
cipher_hex = cipher_bytes.hex()
print("Encrypted message (3DES):", cipher_hex)

# Create 3DES cipher again for decryption
cipher_decrypt = DES3.new(key_3des, DES3.MODE_ECB)

# Decrypt the ciphertext
decrypted_padded_bytes = cipher_decrypt.decrypt(cipher_bytes)

# Remove padding to get original plaintext
decrypted_bytes = unpad(decrypted_padded_bytes, DES3.block_size)
decrypted_text = decrypted_bytes.decode('utf-8')

print("Decrypted message:", decrypted_text)
