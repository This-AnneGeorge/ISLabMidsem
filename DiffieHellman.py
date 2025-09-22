# -------------------- Import necessary libraries --------------------
import time   # Used to measure execution time
import random # Used to generate random private keys

# -------------------- Define Diffie-Hellman parameters --------------------
# Prime modulus p (2048-bit prime)
# Written as a continuous hex string to avoid Python syntax errors
p_hex = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E08A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
)
p = int(p_hex, 16)  # Convert the hexadecimal string to an integer

g = 2  # Generator (primitive root modulo p)

# -------------------- Peer 1 Key Generation --------------------
start_time = time.time()  # Start timer for key generation
private_key_1 = random.randint(2, p-2)  # Generate random private key a for Peer 1
public_key_1 = pow(g, private_key_1, p)  # Compute public key A = g^a mod p
peer1_keygen_time = time.time() - start_time  # Calculate key generation time for Peer 1

# -------------------- Peer 2 Key Generation --------------------
start_time = time.time()  # Start timer for key generation
private_key_2 = random.randint(2, p-2)  # Generate random private key b for Peer 2
public_key_2 = pow(g, private_key_2, p)  # Compute public key B = g^b mod p
peer2_keygen_time = time.time() - start_time  # Calculate key generation time for Peer 2

# -------------------- Exchange Public Keys and Compute Shared Secret --------------------
start_time = time.time()  # Start timer for key exchange
# Peer 1 computes shared secret using Peer 2's public key: s = B^a mod p
shared_secret_1 = pow(public_key_2, private_key_1, p)
# Peer 2 computes shared secret using Peer 1's public key: s = A^b mod p
shared_secret_2 = pow(public_key_1, private_key_2, p)
key_exchange_time = time.time() - start_time  # Calculate time taken for key exchange

# -------------------- Verify that both shared secrets match --------------------
assert shared_secret_1 == shared_secret_2, "Error: Shared secrets do not match!"
shared_secret = shared_secret_1  # Use this value as symmetric key for encryption

# -------------------- Display Results --------------------
print("Peer 1 Key Generation Time: {:.6f} seconds".format(peer1_keygen_time))  # Peer 1 keygen time
print("Peer 2 Key Generation Time: {:.6f} seconds".format(peer2_keygen_time))  # Peer 2 keygen time
print("Key Exchange Time: {:.6f} seconds".format(key_exchange_time))  # Key exchange time
print("Shared Secret Key (hex):", hex(shared_secret))  # Display shared secret in hexadecimal
