# -------------------- Activate venv (Linux) --------------------
# source ~/py_venvs/global_venv/bin/activate

# -------------------- Import required libraries --------------------
import random  # For generating private keys in Diffie-Hellman
from Crypto.PublicKey import RSA  # For RSA key pair generation
from Crypto.Cipher import PKCS1_OAEP  # For RSA encryption/decryption
from Crypto.Cipher import AES  # For symmetric message encryption
from Crypto.Util.Padding import pad, unpad  # For AES padding/unpadding

# -------------------- Define Diffie-Hellman parameters --------------------
# Safe prime for demonstration; in production, use large 2048-bit primes
DH_PRIME_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
)
DH_PRIME = int(DH_PRIME_HEX, 16)  # Convert hex string to integer
DH_GENERATOR = 2  # Generator for Diffie-Hellman

# -------------------- Define Subsystem Class --------------------
# Each subsystem has a name, RSA key pair, and Diffie-Hellman private/public keys
class Subsystem:
    def __init__(self, name):
        self.name = name  # Subsystem name (e.g., "Finance")
        
        # -------------------- Generate RSA key pair --------------------
        # RSA-2048 for secure asymmetric encryption of AES keys/documents
        self.rsa_key = RSA.generate(2048)
        self.rsa_public = self.rsa_key.publickey()  # Public key to share with others
        
        # -------------------- Generate Diffie-Hellman private key --------------------
        self.dh_private = random.randint(2, DH_PRIME - 2)  # Private key for DH
        self.dh_public = pow(DH_GENERATOR, self.dh_private, DH_PRIME)  # Public key
        
        # Dictionary to store shared symmetric AES keys with other subsystems
        self.shared_keys = {}  # Keyed by subsystem name

# -------------------- Function to perform Diffie-Hellman key exchange --------------------
def establish_shared_key(sender, receiver):
    """
    Establish a symmetric AES key between sender and receiver using Diffie-Hellman
    """
    # Compute shared secret: receiver's public ^ sender's private mod p
    shared_secret = pow(receiver.dh_public, sender.dh_private, DH_PRIME)
    
    # Convert shared secret integer to bytes dynamically
    num_bytes = (shared_secret.bit_length() + 7) // 8  # Minimum bytes to store integer
    shared_secret_bytes = shared_secret.to_bytes(num_bytes, 'big')
    
    # Take first 16 bytes for AES-128 key
    aes_key = shared_secret_bytes[:16]
    
    # Store the AES key in both subsystems
    sender.shared_keys[receiver.name] = aes_key
    receiver.shared_keys[sender.name] = aes_key

# -------------------- Function to send an encrypted document --------------------
def send_document(sender, receiver, document_text):
    """
    Sender encrypts a document using the shared AES key and RSA for key transfer
    """
    # Retrieve shared AES key
    aes_key = sender.shared_keys[receiver.name]
    
    # Encrypt document using AES in CBC mode
    aes_cipher = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = aes_cipher.encrypt(pad(document_text.encode('utf-8'), AES.block_size))
    
    # Initialization vector for decryption
    iv = aes_cipher.iv
    
    # Optionally encrypt AES key with receiver's RSA public key
    rsa_cipher = PKCS1_OAEP.new(receiver.rsa_public)
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)
    
    return ciphertext, iv, encrypted_aes_key

# -------------------- Function to receive and decrypt a document --------------------
def receive_document(receiver, sender_name, ciphertext, iv, encrypted_aes_key):
    """
    Receiver decrypts the document using AES key (retrieved via RSA)
    """
    # Decrypt AES key using receiver's RSA private key
    rsa_cipher = PKCS1_OAEP.new(receiver.rsa_key)
    aes_key = rsa_cipher.decrypt(encrypted_aes_key)
    
    # Decrypt document using AES
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    decrypted_text = unpad(aes_cipher.decrypt(ciphertext), AES.block_size)
    
    return decrypted_text.decode('utf-8')

# -------------------- Initialize Subsystems --------------------
finance = Subsystem("Finance")
hr = Subsystem("HR")
supply_chain = Subsystem("SupplyChain")
subsystems = [finance, hr, supply_chain]

# -------------------- Establish shared AES keys between all subsystems --------------------
for i in range(len(subsystems)):
    for j in range(i + 1, len(subsystems)):
        establish_shared_key(subsystems[i], subsystems[j])

# -------------------- Simulate Document Exchange --------------------
# Finance sends a financial report to HR
document = "Quarterly Financial Report Q3 2025"
ciphertext, iv, encrypted_key = send_document(finance, hr, document)
decrypted_document = receive_document(hr, finance.name, ciphertext, iv, encrypted_key)
print(f"Finance sent to HR: {decrypted_document}")

# HR sends an employee contract to Supply Chain
document2 = "Employee Contract: John Doe"
ciphertext2, iv2, encrypted_key2 = send_document(hr, supply_chain, document2)
decrypted_document2 = receive_document(supply_chain, hr.name, ciphertext2, iv2, encrypted_key2)
print(f"HR sent to SupplyChain: {decrypted_document2}")

# Supply Chain sends a procurement order to Finance
document3 = "Procurement Order #56789"
ciphertext3, iv3, encrypted_key3 = send_document(supply_chain, finance, document3)
decrypted_document3 = receive_document(finance, supply_chain.name, ciphertext3, iv3, encrypted_key3)
print(f"SupplyChain sent to Finance: {decrypted_document3}")

# -------------------- Summary --------------------
print("\nSecure communication established between all subsystems using RSA + Diffie-Hellman")
print("Shared AES keys:")
for subsystem in subsystems:
    print(f"{subsystem.name}: {subsystem.shared_keys}")
