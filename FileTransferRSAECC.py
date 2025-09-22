# Activate venv (Linux)
# source ~/py_venvs/global_venv/bin/activate

import time
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# -------------------- Define a helper function to encrypt file using AES --------------------
def encrypt_file_aes(file_bytes, aes_key):
    cipher = AES.new(aes_key, AES.MODE_CBC)  # AES-CBC mode
    ciphertext = cipher.encrypt(pad(file_bytes, AES.block_size))
    return ciphertext, cipher.iv  # Return ciphertext and IV

# -------------------- Helper function to decrypt AES file --------------------
def decrypt_file_aes(ciphertext, aes_key, iv):
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

# -------------------- Generate or load file bytes --------------------
# For demonstration, create dummy data (1MB or 10MB)
file_sizes = [1*1024*1024, 10*1024*1024]  # 1MB, 10MB
files = [get_random_bytes(size) for size in file_sizes]  # Random files

# -------------------- RSA Setup --------------------
print("=== RSA-2048 Key Generation ===")
start_time = time.time()
rsa_key = RSA.generate(2048)  # Generate RSA 2048-bit key pair
rsa_public = rsa_key.publickey()
rsa_keygen_time = time.time() - start_time
print(f"RSA key generation time: {rsa_keygen_time:.4f} s")

# -------------------- ECC Setup (secp256r1) --------------------
print("\n=== ECC Key Generation (secp256r1) ===")
start_time = time.time()
ecc_key = ECC.generate(curve='P-256')  # ECC secp256r1
ecc_public = ecc_key.public_key()
ecc_keygen_time = time.time() - start_time
print(f"ECC key generation time: {ecc_keygen_time:.4f} s\n")

# -------------------- File encryption & performance measurement --------------------
for idx, file_bytes in enumerate(files):
    print(f"--- File {idx+1}: {len(file_bytes)//1024} KB ---")

    # -------------------- AES key generation --------------------
    aes_key = get_random_bytes(16)  # AES-128 key

    # -------------------- RSA Encryption --------------------
    rsa_cipher = PKCS1_OAEP.new(rsa_public)
    start_time = time.time()
    encrypted_aes_key_rsa = rsa_cipher.encrypt(aes_key)
    rsa_key_enc_time = time.time() - start_time

    start_time = time.time()
    file_ciphertext_rsa, iv_rsa = encrypt_file_aes(file_bytes, aes_key)
    rsa_file_enc_time = time.time() - start_time

    # RSA Decryption
    rsa_cipher_dec = PKCS1_OAEP.new(rsa_key)
    start_time = time.time()
    decrypted_aes_key_rsa = rsa_cipher_dec.decrypt(encrypted_aes_key_rsa)
    rsa_key_dec_time = time.time() - start_time

    start_time = time.time()
    decrypted_file_rsa = decrypt_file_aes(file_ciphertext_rsa, decrypted_aes_key_rsa, iv_rsa)
    rsa_file_dec_time = time.time() - start_time

    print(f"RSA AES key encrypt: {rsa_key_enc_time:.6f} s, decrypt: {rsa_key_dec_time:.6f} s")
    print(f"RSA file encrypt: {rsa_file_enc_time:.6f} s, decrypt: {rsa_file_dec_time:.6f} s")

    # -------------------- ECC Encryption --------------------
    # Use ECDH to derive shared secret for AES
    ecc_shared_secret = ecc_key.d * ecc_public.pointQ
    aes_key_ecc = int(ecc_shared_secret.x).to_bytes(32, 'big')[:16]  # Take 16 bytes for AES

    start_time = time.time()
    file_ciphertext_ecc, iv_ecc = encrypt_file_aes(file_bytes, aes_key_ecc)
    ecc_file_enc_time = time.time() - start_time

    start_time = time.time()
    decrypted_file_ecc = decrypt_file_aes(file_ciphertext_ecc, aes_key_ecc, iv_ecc)
    ecc_file_dec_time = time.time() - start_time

    print(f"ECC file encrypt: {ecc_file_enc_time:.6f} s, decrypt: {ecc_file_dec_time:.6f} s\n")

    # Verify correctness
    assert decrypted_file_rsa == file_bytes, "RSA decrypted file mismatch!"
    assert decrypted_file_ecc == file_bytes, "ECC decrypted file mismatch!"
