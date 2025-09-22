# -------------------- Imports --------------------
import socket
import threading
import random
import hashlib
import time

# -------------------- Diffie-Hellman Parameters --------------------
p = 7919  # Small prime for demo; use large prime in real applications
g = 2     # Primitive root modulo p

# -------------------- Server Function --------------------
def server():
    """
    Server listens for connections, receives encrypted message,
    computes hash, and sends hash back to client.
    """
    host = '127.0.0.1'
    port = 5000

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(1)
        print("[SERVER] Listening on {}:{}...".format(host, port))
        conn, addr = s.accept()
        with conn:
            print(f"[SERVER] Connected by {addr}")

            # Receive client's public key
            client_pub_bytes = conn.recv(1024)
            client_public = int(client_pub_bytes.decode())
            print(f"[SERVER] Received client public key: {client_public}")

            # Server generates private key and public key
            server_private = random.randint(1, p-2)
            server_public = pow(g, server_private, p)
            conn.sendall(str(server_public).encode())  # Send server public key

            # Compute shared secret
            shared_secret = pow(client_public, server_private, p)
            shared_key = shared_secret.to_bytes((shared_secret.bit_length()+7)//8, 'big')

            # Receive encrypted message
            encrypted_msg = conn.recv(1024)
            decrypted_msg = bytes([b ^ shared_key[i % len(shared_key)] for i, b in enumerate(encrypted_msg)])
            print(f"[SERVER] Decrypted Message: {decrypted_msg.decode()}")

            # Compute SHA-256 hash
            msg_hash = hashlib.sha256(decrypted_msg).hexdigest()
            conn.sendall(msg_hash.encode())
            print("[SERVER] Hash sent back to client")

# -------------------- Client Function --------------------
def client():
    """
    Client connects to server, performs DH key exchange,
    sends encrypted message, receives hash, and verifies integrity.
    """
    time.sleep(1)  # Ensure server is running

    host = '127.0.0.1'
    port = 5000

    # Client generates private and public key
    client_private = random.randint(1, p-2)
    client_public = pow(g, client_private, p)

    message = "Hello Server, this is Client!"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        print(f"[CLIENT] Connected to server at {host}:{port}")

        # Send client public key
        s.sendall(str(client_public).encode())

        # Receive server public key
        server_pub_bytes = s.recv(1024)
        server_public = int(server_pub_bytes.decode())
        print(f"[CLIENT] Received server public key: {server_public}")

        # Compute shared secret
        shared_secret = pow(server_public, client_private, p)
        shared_key = shared_secret.to_bytes((shared_secret.bit_length()+7)//8, 'big')

        # Encrypt message using XOR with shared key
        encrypted_msg = bytes([b ^ shared_key[i % len(shared_key)] for i, b in enumerate(message.encode())])
        s.sendall(encrypted_msg)
        print(f"[CLIENT] Encrypted message sent: {encrypted_msg}")

        # Receive hash from server
        received_hash = s.recv(1024).decode()
        print(f"[CLIENT] Received hash from server: {received_hash}")

        # Compute local hash
        local_hash = hashlib.sha256(message.encode()).hexdigest()
        print(f"[CLIENT] Local hash: {local_hash}")

        # Verify integrity
        if local_hash == received_hash:
            print("[CLIENT] Data integrity verified ✅")
        else:
            print("[CLIENT] Data integrity failed ❌")

# -------------------- Run Server and Client Threads --------------------
server_thread = threading.Thread(target=server, daemon=True)
server_thread.start()

client_thread = threading.Thread(target=client)
client_thread.start()
client_thread.join()

print("\n--- Client-Server Diffie-Hellman Demo Completed ---")
