# -------------------- Imports --------------------
import socket
import random
import hashlib

# -------------------- Diffie-Hellman Parameters --------------------
p = 23  # Must match server
g = 5

# -------------------- Hash Function --------------------
def custom_hash(input_bytes):
    """
    Compute 32-bit hash of a byte string using djb2-like algorithm
    """
    hash_value = 5381
    for b in input_bytes:
        hash_value = ((hash_value * 33) + b) & 0xFFFFFFFF
        hash_value = hash_value ^ (hash_value >> 16)
    return hash_value

# -------------------- XOR Encryption/Decryption --------------------
def xor_encrypt_decrypt(message_bytes, key_bytes):
    """
    Encrypt/decrypt a byte string using XOR with the shared key
    """
    key_len = len(key_bytes)
    result = bytes([b ^ key_bytes[i % key_len] for i, b in enumerate(message_bytes)])
    return result

# -------------------- Client Communication --------------------
def send_message(message, host='127.0.0.1', port=5000):
    """
    Connect to server, perform Diffie-Hellman key exchange, send encrypted message,
    and verify hash to ensure integrity
    """
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))

    # Step 1: Generate private key
    a_private = random.randint(1, p-2)

    # Compute public key A
    A_public = pow(g, a_private, p)

    # Send A to server
    client.send(str(A_public).encode('utf-8'))

    # Step 2: Receive B from server
    B_public = int(client.recv(1024).decode('utf-8'))

    # Step 3: Compute shared secret
    shared_secret = pow(B_public, a_private, p)
    shared_key = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big')

    # Step 4: Encrypt message
    message_bytes = message.encode('utf-8')
    encrypted_msg = xor_encrypt_decrypt(message_bytes, shared_key)

    # Send encrypted message
    client.send(encrypted_msg)

    # Step 5: Receive server hash
    server_hash = int(client.recv(1024).decode('utf-8'))

    # Step 6: Compute local hash
    local_hash = custom_hash(message_bytes)

    # Verify integrity
    print(f"Message sent: {message}")
    print(f"Server hash: {server_hash}")
    print(f"Local hash: {local_hash}")

    if server_hash == local_hash:
        print("Data integrity verified")
    else:
        print("Data integrity failed")

    client.close()

# -------------------- Demo --------------------
if __name__ == "__main__":
    test_message = "ConfidentialData123"
    send_message(test_message)
