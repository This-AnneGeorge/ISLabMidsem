# Activate venv (Linux)
# source ~/py_venvs/global_venv/bin/activate

# Compare DES and AES-256 encryption/decryption times

import time  # To measure execution time
from Crypto.Cipher import DES, AES  # DES and AES ciphers
from Crypto.Util.Padding import pad, unpad  # For block padding

# Define the message
message = "Performance Testing of Encryption Algorithms"

# Remove spaces and convert to uppercase (optional)
message = message.replace(" ", "").upper()

# Convert message to bytes
message_bytes = message.encode('utf-8')

# -------------------- DES Setup --------------------

des_key = b"A1B2C3D4"  # 8-byte key for DES
des_cipher_encrypt = DES.new(des_key, DES.MODE_ECB)  # DES ECB encryption
des_cipher_decrypt = DES.new(des_key, DES.MODE_ECB)  # DES ECB decryption

# Pad message for DES (8-byte blocks)
des_padded = pad(message_bytes, DES.block_size)

# -------------------- AES-256 Setup --------------------

aes_key = b"0123456789ABCDEF0123456789ABCDEF"  # 32-byte key for AES-256
aes_cipher_encrypt = AES.new(aes_key, AES.MODE_ECB)  # AES-256 ECB encryption
aes_cipher_decrypt = AES.new(aes_key, AES.MODE_ECB)  # AES-256 ECB decryption

# Pad message for AES (16-byte blocks)
aes_padded = pad(message_bytes, AES.block_size)

# -------------------- Measure DES Performance --------------------

# Measure encryption time
start_time = time.time()
des_ciphertext = des_cipher_encrypt.encrypt(des_padded)
des_enc_time = time.time() - start_time

# Measure decryption time
start_time = time.time()
des_plaintext = unpad(des_cipher_decrypt.decrypt(des_ciphertext), DES.block_size)
des_dec_time = time.time() - start_time

# -------------------- Measure AES-256 Performance --------------------

# Measure encryption time
start_time = time.time()
aes_ciphertext = aes_cipher_encrypt.encrypt(aes_padded)
aes_enc_time = time.time() - start_time

# Measure decryption time
start_time = time.time()
aes_plaintext = unpad(aes_cipher_decrypt.decrypt(aes_ciphertext), AES.block_size)
aes_dec_time = time.time() - start_time

# -------------------- Report Results --------------------

print("DES Encryption Time: {:.6f} seconds".format(des_enc_time))
print("DES Decryption Time: {:.6f} seconds".format(des_dec_time))
print("AES-256 Encryption Time: {:.6f} seconds".format(aes_enc_time))
print("AES-256 Decryption Time: {:.6f} seconds".format(aes_dec_time))
