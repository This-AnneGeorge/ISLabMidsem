# -------------------- Import necessary libraries --------------------
from Crypto.PublicKey import ECC          # For ECC key generation
from Crypto.Cipher import AES             # AES for message encryption
from Crypto.Random import get_random_bytes # Random key generation
from Crypto.Util.Padding import pad, unpad # Padding for AES
from Crypto.Hash import SHA256             # Hash function for key derivation
from Crypto.Protocol.KDF import HKDF       # Key derivation from shared secret

# -------------------- Step 1: Generate ECC key pair --------------------
private_key = ECC.generate(curve='P-256')   # ECC private key
public_key = private_key.public_key()       # Corresponding public key

# -------------------- Step 2: Define plaintext --------------------
plaintext = "Secure Transactions"           # Message to encrypt
plaintext_bytes = plaintext.encode('utf-8') # Convert to bytes

# -------------------- Step 3: Encrypt the message with ECC public key --------------------
# ECC alone cannot encrypt long messages, so we use AES + ECC (ECIES style)

# 3a: Generate random ephemeral ECC key for this encryption
ephemeral_key = ECC.generate(curve='P-256')

# 3b: Compute shared secret: ephemeral private key * recipient public key
shared_secret_point = ephemeral_key.d * public_key.pointQ

# 3c: Derive AES key from shared secret (using SHA-256 or HKDF)
shared_secret_bytes = int(shared_secret_point.x).to_bytes(32, 'big')
aes_key = HKDF(master=shared_secret_bytes, key_len=16, salt=None, hashmod=SHA256)

# 3d: Encrypt the plaintext using AES
aes_cipher = AES.new(aes_key, AES.MODE_ECB)
ciphertext_bytes = aes_cipher.encrypt(pad(plaintext_bytes, AES.block_size))

# The "encrypted package" includes ephemeral public key and AES ciphertext
ephemeral_pub_bytes = ephemeral_key.public_key().export_key(format='DER')
encrypted_package = ephemeral_pub_bytes + ciphertext_bytes

# -------------------- Step 4: Decrypt the message with ECC private key --------------------
# Extract ephemeral public key from encrypted package
ephemeral_pub_len = len(ephemeral_pub_bytes)
ephemeral_pub_bytes_received = encrypted_package[:ephemeral_pub_len]
ciphertext_received = encrypted_package[ephemeral_pub_len:]

# Reconstruct ephemeral public key object
ephemeral_pub_key = ECC.import_key(ephemeral_pub_bytes_received)

# Compute shared secret: recipient private key * ephemeral public key
shared_secret_point_decrypt = private_key.d * ephemeral_pub_key.pointQ
shared_secret_bytes_decrypt = int(shared_secret_point_decrypt.x).to_bytes(32, 'big')
aes_key_decrypt = HKDF(master=shared_secret_bytes_decrypt, key_len=16, salt=None, hashmod=SHA256)

# Decrypt the AES ciphertext
aes_cipher_decrypt = AES.new(aes_key_decrypt, AES.MODE_ECB)
decrypted_padded = aes_cipher_decrypt.decrypt(ciphertext_received)
decrypted_text = unpad(decrypted_padded, AES.block_size).decode('utf-8')

# -------------------- Step 5: Display results --------------------
print("Original message:", plaintext)
print("Encrypted package (hex):", encrypted_package.hex())
print("Decrypted message:", decrypted_text)
