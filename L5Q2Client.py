# -------------------- Client Script --------------------
import socket  # For network communication

# -------------------- Custom Hash Function --------------------
def custom_hash(input_string):
    """
    Compute a 32-bit hash of the input string
    """
    hash_value = 5381
    for char in input_string:
        ascii_val = ord(char)
        hash_value = (hash_value * 33) + ascii_val
        hash_value = hash_value ^ (hash_value >> 16)
        hash_value = hash_value & 0xFFFFFFFF
    return hash_value

# -------------------- Client Function --------------------
def send_data(data, host='127.0.0.1', port=5000, tamper=False):
    """
    Send data to server and verify its integrity using hash
    """
    # Create TCP socket
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))  # Connect to server

    # Optionally tamper data to simulate corruption
    if tamper:
        data = data + "!"  # Alter data

    # Send data to server
    client.send(data.encode('utf-8'))

    # Receive hash from server
    server_hash = int(client.recv(1024).decode('utf-8'))
    print(f"[CLIENT] Server reported hash: {server_hash}")

    # Compute local hash of original data
    local_hash = custom_hash(data if not tamper else data[:-1])
    print(f"[CLIENT] Local computed hash: {local_hash}")

    # Compare hashes to verify integrity
    if server_hash == local_hash:
        print("[CLIENT] Data integrity verified ✅")
    else:
        print("[CLIENT] Data integrity failed ❌ (data may be corrupted or tampered)")

    # Close connection
    client.close()

# -------------------- Demo --------------------
if __name__ == "__main__":
    message = "PatientRecord123"
    print("----- Sending correct data -----")
    send_data(message)  # Normal transmission

    print("\n----- Sending tampered data -----")
    send_data(message, tamper=True)  # Simulate corruption
