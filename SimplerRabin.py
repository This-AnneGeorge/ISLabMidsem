# Activate venv (Linux)
# source ~/py_venvs/global_venv/bin/activate

# -------------------- Imports --------------------
import random  # To generate random numbers (used for prime numbers)
import time    # To add timestamps for logging operations

# -------------------- Helper function: Prime checking --------------------
def is_prime(n):
    """
    Check if a number n is prime using trial division.
    This is a simple method for demonstration; not efficient for large numbers.
    """
    if n < 2:
        return False  # Numbers less than 2 are not prime
    # Check divisibility from 2 up to sqrt(n)
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False  # Divisible by i → not prime
    return True  # No divisors found → prime

# -------------------- Helper function: Generate a prime ≡ 3 mod 4 --------------------
def generate_prime(bits):
    """
    Generate a random prime number of 'bits' length that is congruent to 3 modulo 4.
    This is required for the Rabin cryptosystem to work properly.
    """
    while True:
        # Generate a random number with 'bits' length
        p = random.getrandbits(bits)

        # Ensure the number has the correct number of bits
        p |= (1 << bits - 1)

        # Adjust p to satisfy p ≡ 3 (mod 4)
        if p % 4 != 3:
            p += (3 - p % 4)

        # Check if p is prime
        if is_prime(p):
            return p  # Return the prime number

# -------------------- Key Management System Class --------------------
class SimpleKMS:
    """
    Centralized Key Management Service (KMS) for healthcare facilities.
    Manages Rabin public/private keys, key distribution, revocation, renewal, and logging.
    """

    def __init__(self):
        # Dictionary to store keys for each facility
        # Format: {facility_name: {'public': n, 'private': (p,q), 'time': timestamp}}
        self.keys = {}

        # List to maintain logs for auditing purposes
        self.logs = []

    # -------------------- Key Generation --------------------
    def generate_keys(self, facility_name, bits=16):
        """
        Generate a Rabin public/private key pair for a facility.
        'bits' specifies the size of the prime numbers for demonstration purposes.
        """
        # Generate two primes p and q
        p = generate_prime(bits)
        q = generate_prime(bits)

        # Compute the public key n = p * q
        n = p * q

        # Store the keys securely in the dictionary with a timestamp
        self.keys[facility_name] = {
            'public': n,
            'private': (p, q),
            'time': time.time()
        }

        # Log the key generation operation with timestamp
        self.logs.append(f"{time.ctime()}: Generated keys for {facility_name}")

        # Return public and private keys
        return n, (p, q)

    # -------------------- Key Distribution --------------------
    def distribute_keys(self, facility_name):
        """
        Return the public and private keys of a facility.
        Simulates a secure API call for key distribution.
        """
        if facility_name in self.keys:
            # Log the distribution
            self.logs.append(f"{time.ctime()}: Distributed keys for {facility_name}")

            # Return the stored keys
            return self.keys[facility_name]['public'], self.keys[facility_name]['private']
        else:
            # Facility not found → return None
            return None, None

    # -------------------- Key Revocation --------------------
    def revoke_keys(self, facility_name):
        """
        Revoke the keys of a facility (e.g., if compromised or closed).
        Removes the keys from the KMS storage.
        """
        if facility_name in self.keys:
            # Delete the keys from storage
            del self.keys[facility_name]

            # Log the revocation
            self.logs.append(f"{time.ctime()}: Revoked keys for {facility_name}")

    # -------------------- Key Renewal --------------------
    def renew_keys(self, bits=16):
        """
        Renew keys for all facilities in the KMS.
        This simulates periodic key renewal (e.g., every 12 months).
        """
        for facility in list(self.keys.keys()):
            # Generate new keys and overwrite old ones
            self.generate_keys(facility, bits)

            # Log the renewal
            self.logs.append(f"{time.ctime()}: Renewed keys for {facility}")

    # -------------------- Audit Logging --------------------
    def show_logs(self):
        """
        Display all logs of key management operations for auditing purposes.
        """
        print("\n--- KMS Logs ---")
        for log in self.logs:
            print(log)
        print("--- End of Logs ---\n")

# -------------------- Demonstration --------------------
# Initialize the Key Management Service
kms = SimpleKMS()

# Generate keys for two healthcare facilities
n1, priv1 = kms.generate_keys("HospitalA")  # HospitalA keys
n2, priv2 = kms.generate_keys("ClinicB")   # ClinicB keys

# Distribute keys to facilities
pub1, pri1 = kms.distribute_keys("HospitalA")  # Retrieve HospitalA keys
pub2, pri2 = kms.distribute_keys("ClinicB")   # Retrieve ClinicB keys

# Revoke keys for ClinicB (simulate compromise or closure)
kms.revoke_keys("ClinicB")

# Renew keys for all remaining facilities
kms.renew_keys()

# Display audit logs to verify operations
kms.show_logs()
