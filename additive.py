# Activate venv (Linux) 

# source ~/py_venvs/global_venv/bin/activate 

 

# Additive Cipher Encryption & Decryption 

 

# Define the alphabet 

alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"  # Only uppercase letters will be used 

 

# Define the key for additive cipher 

key = 20  # Shift amount for encryption 

 

# Define the plaintext message 

plaintext = "I am learning information security" 

 

# Remove spaces and convert to uppercase 

plaintext = plaintext.replace(" ", "").upper() 

 

# Function to encrypt a message using additive cipher 

def additive_encrypt(message, key): 

    cipher_text = ""  # Initialize empty string to store ciphertext 

    for char in message:  # Loop through each character in the message 

        if char in alphabet:  # Only encrypt alphabet letters 

            # Find original position in alphabet 

            index = alphabet.index(char) 

            # Shift the position by key (mod 26 to wrap around) 

            new_index = (index + key) % 26 

            # Append the new character to ciphertext 

            cipher_text += alphabet[new_index] 

        else: 

            cipher_text += char  # Non-alphabet characters remain unchanged 

    return cipher_text 

 

# Function to decrypt a message using additive cipher 

def additive_decrypt(cipher_text, key): 

    decrypted_text = ""  # Initialize empty string to store decrypted text 

    for char in cipher_text:  # Loop through each character in ciphertext 

        if char in alphabet:  # Only decrypt alphabet letters 

            index = alphabet.index(char)  # Original position 

            new_index = (index - key) % 26  # Reverse the shift 

            decrypted_text += alphabet[new_index]  # Append decrypted char 

        else: 

            decrypted_text += char  # Non-alphabet characters remain unchanged 

    return decrypted_text 

 

# Encrypt the plaintext 

cipher_text = additive_encrypt(plaintext, key) 

print("Encrypted message (Additive Cipher):", cipher_text) 

 

# Decrypt the ciphertext 

decrypted_text = additive_decrypt(cipher_text, key) 

print("Decrypted message:", decrypted_text) 