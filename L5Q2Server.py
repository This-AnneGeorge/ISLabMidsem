# -------------------- Server Script --------------------
import socket  # For network communication
import threading  # Optional: to handle multiple clients
import time

# -------------------- Custom Hash Function --------------------
def custom_hash(input_string):
    """
    Compute a 32-bit hash of the input string using djb2-like algorithm.
    """
    hash_value = 5381  # Initial hash
    for char in input_string:
        ascii_val = ord(char)  # ASCII value of character
        hash_value = (hash_value * 33) + ascii_val  # Multiply by 33 and add ASCII
        hash_value = hash_value ^ (hash_value >> 16)  # Bitwise mixing
        hash_value = hash_value & 0xFFFFFFFF  # Keep in 32-bit range
    return hash_value

# -------------------- Server Function --------------------
def handle_client(client_socket, addr):
    """
    Handle communication with a connected client
    """
    print(f"[SERVER] Connection established with {addr}")

    try:
        # Receive data from client
        data = client_socket.recv(1024).decode('utf-8')  # Decode bytes to string
        print(f"[SERVER] Received data: {data}")

        # Compute hash of received data
        data_hash = custom_hash(data)
        print(f"[SERVER] Computed hash: {data_hash}")

        # Send the hash back to the client
        client_socket.send(str(data_hash).encode('utf-8'))  # Encode int to bytes

    except Exception as e:
        print(f"[SERVER] Error: {e}")

    finally:
        # Close client connection
        client_socket.close()
        print(f"[SERVER] Connection closed with {addr}")

# -------------------- Main Server Setup --------------------
def start_server(host='127.0.0.1', port=5000):
    """
    Start the TCP server to accept client connections
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create TCP socket
    server.bind((host, port))  # Bind to host and port
    server.listen(5)  # Listen for incoming connections
    print(f"[SERVER] Listening on {host}:{port}...")

    while True:
        client_socket, addr = server.accept()  # Accept new client
        # Handle client in a new thread
        client_thread = threading.Thread(target=handle_client, args=(client_socket, addr))
        client_thread.start()

# -------------------- Run Server --------------------
if __name__ == "__main__":
    start_server()
