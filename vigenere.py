# Activate venv (Linux)
# source ~/py_venvs/global_venv/bin/activate

# Vigenere Cipher Encryption & Decryption

# Define the plaintext
plaintext = "the house is being sold tonight"

# Remove spaces and convert to uppercase
plaintext = plaintext.replace(" ", "").upper()

# Define the Vigenere key
key = "dollars".upper()  # Convert key to uppercase

# Define the alphabet
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Function to encrypt using Vigenere cipher
def vigenere_encrypt(message, key):
    cipher_text = ""
    key_length = len(key)
    for i, char in enumerate(message):
        if char in alphabet:
            # Shift each letter by corresponding key letter
            key_index = alphabet.index(key[i % key_length])
            msg_index = alphabet.index(char)
            new_index = (msg_index + key_index) % 26
            cipher_text += alphabet[new_index]
        else:
            cipher_text += char
    return cipher_text

# Function to decrypt using Vigenere cipher
def vigenere_decrypt(cipher_text, key):
    decrypted_text = ""
    key_length = len(key)
    for i, char in enumerate(cipher_text):
        if char in alphabet:
            key_index = alphabet.index(key[i % key_length])
            cipher_index = alphabet.index(char)
            new_index = (cipher_index - key_index) % 26
            decrypted_text += alphabet[new_index]
        else:
            decrypted_text += char
    return decrypted_text

# Encrypt the plaintext
cipher_text = vigenere_encrypt(plaintext, key)
print("Encrypted message (Vigenere Cipher):", cipher_text)

# Decrypt the ciphertext
decrypted_text = vigenere_decrypt(cipher_text, key)
print("Decrypted message:", decrypted_text)
