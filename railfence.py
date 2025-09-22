# Activate venv (Linux)
# source ~/py_venvs/global_venv/bin/activate

# Rail Fence Cipher Encryption & Decryption

# Define the plaintext
plaintext = "I am learning information security"

# Remove spaces and convert to uppercase
plaintext = plaintext.replace(" ", "").upper()

# Define the number of rails (key)
rails = 3  # Number of rows for the rail fence

# Function to encrypt using Rail Fence Cipher
def rail_fence_encrypt(message, rails):
    # Create a list of empty strings for each rail
    fence = ['' for _ in range(rails)]
    rail = 0  # Start at the first rail
    direction = 1  # 1 = moving down, -1 = moving up

    for char in message:  # Loop through each character
        fence[rail] += char  # Append char to the current rail
        rail += direction  # Move to next rail
        # Change direction if we hit top or bottom rail
        if rail == 0 or rail == rails - 1:
            direction *= -1

    # Combine all rails into one string (ciphertext)
    return ''.join(fence)

# Function to decrypt Rail Fence Cipher
def rail_fence_decrypt(cipher_text, rails):
    # Create a 2D array to mark positions
    pattern = [['' for _ in range(len(cipher_text))] for _ in range(rails)]
    rail = 0
    direction = 1

    # Mark the zig-zag pattern with placeholders
    for i in range(len(cipher_text)):
        pattern[rail][i] = '*'
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1

    # Fill the letters in the marked positions
    index = 0
    for r in range(rails):
        for c in range(len(cipher_text)):
            if pattern[r][c] == '*' and index < len(cipher_text):
                pattern[r][c] = cipher_text[index]
                index += 1

    # Read the message in zig-zag order
    result = ''
    rail = 0
    direction = 1
    for i in range(len(cipher_text)):
        result += pattern[rail][i]
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1

    return result

# Encrypt the plaintext
cipher_text = rail_fence_encrypt(plaintext, rails)
print("Encrypted message (Rail Fence Cipher):", cipher_text)

# Decrypt the ciphertext
decrypted_text = rail_fence_decrypt(cipher_text, rails)
print("Decrypted message:", decrypted_text)
