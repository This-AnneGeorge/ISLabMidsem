# Activate venv (Linux)
# source ~/py_venvs/global_venv/bin/activate

# Multiplicative Cipher Encryption & Decryption

# Define the alphabet
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Define the key for multiplicative cipher
key = 15  # Must be coprime with 26 for decryption

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
    return None  # Return None if inverse doesn't exist

# Function to encrypt a message using multiplicative cipher
def multiplicative_encrypt(message, key):
    cipher_text = ""
    for char in message:
        if char in alphabet:
            index = alphabet.index(char)  # Original position
            new_index = (index * key) % 26  # Multiply position and mod 26
            cipher_text += alphabet[new_index]
        else:
            cipher_text += char
    return cipher_text

# Function to decrypt a message using multiplicative cipher
def multiplicative_decrypt(cipher_text, key):
    decrypted_text = ""
    inv_key = mod_inverse(key, 26)  # Compute modular inverse of key
    if inv_key is None:
        return "Cannot decrypt: key has no modular inverse"
    for char in cipher_text:
        if char in alphabet:
            index = alphabet.index(char)
            new_index = (index * inv_key) % 26
            decrypted_text += alphabet[new_index]
        else:
            decrypted_text += char
    return decrypted_text

# Encrypt the plaintext
cipher_text = multiplicative_encrypt(plaintext, key)
print("Encrypted message (Multiplicative Cipher):", cipher_text)

# Decrypt the ciphertext
decrypted_text = multiplicative_decrypt(cipher_text, key)
print("Decrypted message:", decrypted_text)
