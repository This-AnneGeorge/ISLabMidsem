# Activate venv (Linux)
# source ~/py_venvs/global_venv/bin/activate

# Autokey Cipher Encryption & Decryption

# Define the plaintext
plaintext = "the house is being sold tonight"

# Remove spaces and convert to uppercase
plaintext = plaintext.replace(" ", "").upper()

# Define the initial numerical key
key = 7  # Initial shift

# Define the alphabet
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Function to encrypt using Autokey cipher
def autokey_encrypt(message, key):
    cipher_text = ""
    # Initial key for the first letter
    keys = [key]  # List to store shifts: start with initial key
    for i, char in enumerate(message):
        if char in alphabet:
            # Shift using current key
            shift = keys[i]
            index = alphabet.index(char)
            new_index = (index + shift) % 26
            cipher_text += alphabet[new_index]
            # Add the current plaintext letter's index as next key
            keys.append(index)
        else:
            cipher_text += char
    return cipher_text

# Function to decrypt using Autokey cipher
def autokey_decrypt(cipher_text, key):
    decrypted_text = ""
    keys = [key]
    for i, char in enumerate(cipher_text):
        if char in alphabet:
            shift = keys[i]
            index = alphabet.index(char)
            new_index = (index - shift) % 26
            decrypted_text += alphabet[new_index]
            # Append decrypted letter index to keys
            keys.append(new_index)
        else:
            decrypted_text += char
    return decrypted_text

# Encrypt the plaintext
cipher_text = autokey_encrypt(plaintext, key)
print("Encrypted message (Autokey Cipher):", cipher_text)

# Decrypt the ciphertext
decrypted_text = autokey_decrypt(cipher_text, key)
print("Decrypted message:", decrypted_text)
