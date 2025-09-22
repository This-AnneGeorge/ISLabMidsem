# Activate venv (Linux)
# source ~/py_venvs/global_venv/bin/activate

# Playfair Cipher Encryption & Decryption

# Define the plaintext
plaintext = "The key is hidden under the door pad"

# Remove spaces and convert to uppercase
plaintext = plaintext.replace(" ", "").upper()

# Replace 'J' with 'I' (Playfair convention)
plaintext = plaintext.replace('J', 'I')

# Define the secret key
key_word = "GUIDANCE"

# Create the Playfair 5x5 matrix
def create_playfair_matrix(key):
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # 'J' is omitted
    matrix = []
    used = set()  # Keep track of letters already in matrix

    # Add key letters first
    for char in key:
        if char not in used and char in alphabet:
            matrix.append(char)
            used.add(char)

    # Add remaining letters
    for char in alphabet:
        if char not in used:
            matrix.append(char)
            used.add(char)

    # Convert flat list to 5x5 matrix
    matrix_2d = [matrix[i*5:(i+1)*5] for i in range(5)]
    return matrix_2d

# Function to find position of a letter in matrix
def find_position(matrix, char):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == char:
                return row, col
    return None

# Function to process plaintext into digraphs (pairs)
def create_digraphs(text):
    digraphs = []
    i = 0
    while i < len(text):
        a = text[i]
        b = ''
        if i+1 < len(text):
            b = text[i+1]
            if a == b:
                b = 'X'  # Insert 'X' if two letters are same
                digraphs.append(a+b)
                i += 1
            else:
                digraphs.append(a+b)
                i += 2
        else:
            b = 'X'  # Pad last letter if odd length
            digraphs.append(a+b)
            i += 2
    return digraphs

# Function to encrypt using Playfair cipher
def playfair_encrypt(plaintext, matrix):
    digraphs = create_digraphs(plaintext)
    cipher_text = ""
    for a, b in digraphs:
        row1, col1 = find_position(matrix, a)
        row2, col2 = find_position(matrix, b)

        if row1 == row2:  # Same row
            cipher_text += matrix[row1][(col1 + 1) % 5]
            cipher_text += matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:  # Same column
            cipher_text += matrix[(row1 + 1) % 5][col1]
            cipher_text += matrix[(row2 + 1) % 5][col2]
        else:  # Rectangle swap
            cipher_text += matrix[row1][col2]
            cipher_text += matrix[row2][col1]
    return cipher_text

# Function to decrypt using Playfair cipher
def playfair_decrypt(cipher_text, matrix):
    digraphs = create_digraphs(cipher_text)  # Split into pairs
    decrypted_text = ""
    for a, b in digraphs:
        row1, col1 = find_position(matrix, a)
        row2, col2 = find_position(matrix, b)

        if row1 == row2:  # Same row
            decrypted_text += matrix[row1][(col1 - 1) % 5]
            decrypted_text += matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:  # Same column
            decrypted_text += matrix[(row1 - 1) % 5][col1]
            decrypted_text += matrix[(row2 - 1) % 5][col2]
        else:  # Rectangle swap
            decrypted_text += matrix[row1][col2]
            decrypted_text += matrix[row2][col1]
    return decrypted_text

# Create matrix
matrix = create_playfair_matrix(key_word)

# Encrypt the plaintext
cipher_text = playfair_encrypt(plaintext, matrix)
print("Encrypted message (Playfair Cipher):", cipher_text)

# Decrypt the ciphertext
decrypted_text = playfair_decrypt(cipher_text, matrix)
print("Decrypted message:", decrypted_text)
