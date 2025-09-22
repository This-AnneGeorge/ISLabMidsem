# Activate venv (Linux)
# source ~/py_venvs/global_venv/bin/activate

# Affine Cipher Encryption & Decryption

# Define the alphabet
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Affine cipher keys
a = 15  # Multiplicative part, must be coprime with 26
b = 20  # Additive part

# Define the plaintext
plaintext = "I am learning information security"

# Remove spaces and convert to uppercase
plaintext = plaintext.replace(" ", "").upper()

# Function to compute modular inverse (needed for decryption)
def mod_inverse(a, m):
    # Extended Euclidean Algorithm
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None

# Function to encrypt using affine cipher
def affine_encrypt(message, a, b):
    cipher_text = ""
    for char in message:
        if char in alphabet:
            index = alphabet.index(char)  # Original position
            new_index = (a * index + b) % 26  # Affine transformation
            cipher_text += alphabet[new_index]
        else:
            cipher_text += char
    return cipher_text

# Function to decrypt using affine cipher
def affine_decrypt(cipher_text, a, b):
    decrypted_text = ""
    a_inv = mod_inverse(a, 26)  # Modular inverse of a
    if a_inv is None:
        return "Cannot decrypt: a has no modular inverse"
    for char in cipher_text:
        if char in alphabet:
            index = alphabet.index(char)
            new_index = (a_inv * (index - b)) % 26  # Reverse affine transformation
            decrypted_text += alphabet[new_index]
        else:
            decrypted_text += char
    return decrypted_text

# Encrypt the plaintext
cipher_text = affine_encrypt(plaintext, a, b)
print("Encrypted message (Affine Cipher):", cipher_text)

# Decrypt the ciphertext
decrypted_text = affine_decrypt(cipher_text, a, b)
print("Decrypted message:", decrypted_text)
