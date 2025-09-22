# Activate venv (Linux)
# source ~/py_venvs/global_venv/bin/activate

# Hill Cipher Encryption & Decryption (2x2 matrix)

import numpy as np  # For matrix operations

# Define the plaintext
plaintext = "We live in an insecure world"

# Remove spaces and convert to uppercase
plaintext = plaintext.replace(" ", "").upper()

# Define the 2x2 key matrix
# Key = [[3, 3], [2, 7]]
key_matrix = np.array([[3, 3],
                       [2, 7]])

# Function to process plaintext into 2-letter blocks
def create_blocks(text, block_size=2):
    blocks = []
    i = 0
    while i < len(text):
        block = text[i:i+block_size]
        if len(block) < block_size:
            block += 'X'  # Pad with 'X' if last block is short
        blocks.append(block)
        i += block_size
    return blocks

# Function to encrypt using Hill cipher
def hill_encrypt(plaintext, key_matrix):
    cipher_text = ""
    blocks = create_blocks(plaintext, 2)
    for block in blocks:
        # Convert letters to numbers (A=0, B=1, ..., Z=25)
        vector = [ord(char) - ord('A') for char in block]
        # Multiply key matrix with vector and take mod 26
        encrypted_vector = np.dot(key_matrix, vector) % 26
        # Convert numbers back to letters
        cipher_block = ''.join([chr(num + ord('A')) for num in encrypted_vector])
        cipher_text += cipher_block
    return cipher_text

# Function to compute modular inverse of a matrix modulo 26
def mod_matrix_inv(matrix, mod):
    det = int(np.round(np.linalg.det(matrix)))  # Determinant
    det_inv = pow(det, -1, mod)  # Modular inverse of determinant
    # Adjugate matrix
    adj = np.round(det * np.linalg.inv(matrix)).astype(int)
    # Multiply adjugate by det_inv modulo 26
    return (det_inv * adj) % mod

# Function to decrypt using Hill cipher
def hill_decrypt(cipher_text, key_matrix):
    decrypted_text = ""
    # Compute modular inverse of key matrix
    key_inv = mod_matrix_inv(key_matrix, 26)
    blocks = create_blocks(cipher_text, 2)
    for block in blocks:
        vector = [ord(char) - ord('A') for char in block]
        decrypted_vector = np.dot(key_inv, vector) % 26
        decrypted_block = ''.join([chr(int(num) + ord('A')) for num in decrypted_vector])
        decrypted_text += decrypted_block
    return decrypted_text

# Encrypt the plaintext
cipher_text = hill_encrypt(plaintext, key_matrix)
print("Encrypted message (Hill Cipher):", cipher_text)

# Decrypt the ciphertext
decrypted_text = hill_decrypt(cipher_text, key_matrix)
print("Decrypted message:", decrypted_text)
