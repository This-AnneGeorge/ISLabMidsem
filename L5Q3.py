# -------------------- Imports --------------------
import hashlib  # For MD5, SHA-1, SHA-256 hash functions
import random   # For generating random strings
import string   # For ASCII letters and digits
import time     # For timing hash computations

# -------------------- Helper Function: Random String Generator --------------------
def generate_random_strings(n, length_range=(5, 10)):
    """
    Generate 'n' random strings.
    Each string has a random length between length_range[0] and length_range[1].
    """
    strings = []
    for _ in range(n):
        # Randomly choose string length
        length = random.randint(length_range[0], length_range[1])
        # Generate string of random letters and digits
        rand_str = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        strings.append(rand_str)
    return strings

# -------------------- Helper Function: Compute Hash --------------------
def compute_hashes(strings, algorithm):
    """
    Compute hash values for a list of strings using the specified algorithm.
    algorithm: 'md5', 'sha1', or 'sha256'
    Returns: dict mapping string -> hash value
    """
    hashes = {}  # Dictionary to store results
    start_time = time.time()  # Start timer

    for s in strings:
        # Encode string to bytes for hashing
        encoded = s.encode('utf-8')

        # Select hash function
        if algorithm == 'md5':
            h = hashlib.md5(encoded).hexdigest()
        elif algorithm == 'sha1':
            h = hashlib.sha1(encoded).hexdigest()
        elif algorithm == 'sha256':
            h = hashlib.sha256(encoded).hexdigest()
        else:
            raise ValueError("Unsupported algorithm")

        # Store hash value
        hashes[s] = h

    end_time = time.time()  # End timer
    computation_time = end_time - start_time  # Total time taken

    return hashes, computation_time

# -------------------- Helper Function: Detect Collisions --------------------
def detect_collisions(hashes):
    """
    Detect any collisions in the hash values.
    Returns a list of tuples: (hash_value, [original strings with same hash])
    """
    reverse_map = {}  # Map hash -> list of original strings

    for original, h in hashes.items():
        if h in reverse_map:
            reverse_map[h].append(original)
        else:
            reverse_map[h] = [original]

    # Extract collisions (hash values with more than one original string)
    collisions = [(h, lst) for h, lst in reverse_map.items() if len(lst) > 1]
    return collisions

# -------------------- Main Experiment --------------------
def main():
    num_strings = random.randint(50, 100)  # Generate 50-100 random strings
    print(f"Generating {num_strings} random strings...")
    dataset = generate_random_strings(num_strings, length_range=(5, 15))

    # Algorithms to test
    algorithms = ['md5', 'sha1', 'sha256']

    for algo in algorithms:
        print(f"\n--- Testing {algo.upper()} ---")

        # Compute hashes and measure time
        hashes, time_taken = compute_hashes(dataset, algo)
        print(f"Time taken for {algo.upper()}: {time_taken:.6f} seconds")

        # Detect collisions
        collisions = detect_collisions(hashes)
        if collisions:
            print(f"Collisions detected for {algo.upper()}:")
            for h_val, originals in collisions:
                print(f"Hash: {h_val} -> Strings: {originals}")
        else:
            print(f"No collisions detected for {algo.upper()}.")

# -------------------- Run Experiment --------------------
if __name__ == "__main__":
    main()
