# -------------------- Imports --------------------
import socket
import threading
import hashlib
import time

# -------------------- Server Function --------------------
def server():
    """
    Server listens for client connections, receives data,
    computes SHA-256 hash, and sends the hash back.
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
            data = conn.recv(1024)  # Receive data
            print(f"[SERVER] Received data: {data.decode()}")

            # Compute SHA-256 hash
            data_hash = hashlib.sha256(data).hexdigest()
            print(f"[SERVER] Computed hash: {data_hash}")

            # Send hash back to client
            conn.sendall(data_hash.encode())
            print("[SERVER] Hash sent back to client")
            
# -------------------- Client Function --------------------
def client(tamper=False):
    """
    Client connects to server, sends data, receives hash,
    and verifies integrity. Optionally simulates tampering.
    """
    time.sleep(1)  # Ensure server is ready

    host = '127.0.0.1'
    port = 5000
    message = "Hello Server, this is Client!"

    if tamper:
        message += "X"  # Simulate tampering

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        print(f"[CLIENT] Connected to server at {host}:{port}")
        s.sendall(message.encode())
        print(f"[CLIENT] Sent data: {message}")

        # Receive hash from server
        received_hash = s.recv(1024).decode()
        print(f"[CLIENT] Received hash: {received_hash}")

        # Compute local hash
        local_hash = hashlib.sha256(message.encode()).hexdigest()
        print(f"[CLIENT] Local hash: {local_hash}")

        # Verify integrity
        if local_hash == received_hash:
            print("[CLIENT] Data integrity verified! ✅")
        else:
            print("[CLIENT] Data corrupted! ❌")

# -------------------- Run Server and Client Threads --------------------
server_thread = threading.Thread(target=server, daemon=True)
server_thread.start()

# Run client normally (integrity check passes)
client_thread = threading.Thread(target=client)
client_thread.start()
client_thread.join()

print("\n--- Now simulating tampered data ---\n")

# Run client again with tampering
client_thread_tampered = threading.Thread(target=client, args=(True,))
client_thread_tampered.start()
client_thread_tampered.join()
