# Activate venv (Linux)
# source ~/py_venvs/global_venv/bin/activate

# -------------------- Imports --------------------
import random  # For generating primes and random keys
import hashlib  # For hashing messages (optional, for signing verification)
import time  # For timestamped logs
from sympy import isprime  # For prime number checks (pip install sympy)

# -------------------- Key Management Service Class --------------------
class KeyManagementService:
    """
    Centralized Key Management Service for HealthCare Inc.
    Manages Rabin cryptosystem keys for multiple hospitals/clinics.
    """

    def __init__(self):
        # Dictionary to store key pairs
        # Format: {facility_name: {'public': (n), 'private': (p,q), 'timestamp': time}}
        self.key_store = {}

        # List of logs for auditing operations
        self.logs = []

    # -------------------- Helper function to generate large primes --------------------
    def generate_prime(self, bits):
        """
        Generate a prime number of specified bit length congruent to 3 mod 4
        Rabin cryptosystem requires primes p and q such that p ≡ q ≡ 3 mod 4
        """
        while True:
            prime_candidate = random.getrandbits(bits)  # Generate random bits
            if prime_candidate % 4 != 3:  # Ensure prime ≡ 3 mod 4
                prime_candidate += (3 - prime_candidate % 4)
            if isprime(prime_candidate):
                return prime_candidate

    # -------------------- Key Generation --------------------
    def generate_rabin_keys(self, facility_name, bits=1024):
        """
        Generate Rabin public/private key pair for a hospital/clinic
        """
        # Generate p and q primes
        p = self.generate_prime(bits)
        q = self.generate_prime(bits)
        n = p * q  # Public modulus

        # Store keys securely in memory
        self.key_store[facility_name] = {
            'public': n,
            'private': (p, q),
            'timestamp': time.time()
        }

        # Log the key generation
        self.logs.append(f"{time.ctime()}: Generated keys for {facility_name}")

        return n, (p, q)

    # -------------------- Key Distribution --------------------
    def distribute_keys(self, facility_name):
        """
        Return the public and private keys of a facility securely
        """
        if facility_name not in self.key_store:
            raise ValueError("Facility not found.")
        
        # Log distribution
        self.logs.append(f"{time.ctime()}: Distributed keys for {facility_name}")

        return self.key_store[facility_name]['public'], self.key_store[facility_name]['private']

    # -------------------- Key Revocation --------------------
    def revoke_keys(self, facility_name):
        """
        Revoke keys of a facility (e.g., if compromised)
        """
        if facility_name in self.key_store:
            del self.key_store[facility_name]  # Remove keys
            self.logs.append(f"{time.ctime()}: Revoked keys for {facility_name}")
        else:
            self.logs.append(f"{time.ctime()}: Attempted revocation of non-existent facility {facility_name}")

    # -------------------- Key Renewal --------------------
    def renew_keys(self, bits=1024):
        """
        Renew keys for all facilities (e.g., every 12 months)
        """
        for facility in list(self.key_store.keys()):
            n, priv = self.generate_rabin_keys(facility, bits)
            self.logs.append(f"{time.ctime()}: Renewed keys for {facility}")

    # -------------------- Auditing --------------------
    def show_logs(self):
        """
        Display all key management logs
        """
        print("\n--- Key Management Logs ---")
        for log in self.logs:
            print(log)
        print("--- End of Logs ---\n")

# -------------------- Example Usage --------------------
kms = KeyManagementService()

# Generate keys for hospitals and clinics
n1, priv1 = kms.generate_rabin_keys("HospitalA")
n2, priv2 = kms.generate_rabin_keys("ClinicB")
n3, priv3 = kms.generate_rabin_keys("HospitalC")

# Distribute keys (simulate secure API)
public1, private1 = kms.distribute_keys("HospitalA")
public2, private2 = kms.distribute_keys("ClinicB")

# Revoke keys for a compromised facility
kms.revoke_keys("ClinicB")

# Renew keys for all remaining facilities
kms.renew_keys()

# Display logs for auditing
kms.show_logs()
