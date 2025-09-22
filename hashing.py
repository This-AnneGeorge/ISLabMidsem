# -------------------- Hash Function Implementation --------------------
def custom_hash(input_string):
    """
    Compute a hash value for the input string using the following steps:
    1. Start with initial hash value 5381
    2. For each character:
       - Multiply current hash by 33
       - Add ASCII value of the character
       - Mix the bits using bitwise operations
    3. Keep the hash within 32-bit range using masking
    """
    hash_value = 5381  # Step 1: Initialize hash value

    # Step 2: Iterate through each character in the input string
    for char in input_string:
        ascii_val = ord(char)  # Get ASCII integer value of character

        # Multiply current hash by 33
        hash_value = (hash_value * 33) 

        # Add ASCII value of character
        hash_value = hash_value + ascii_val

        # Optional bitwise mixing: XOR hash with itself shifted right 16 bits
        hash_value = hash_value ^ (hash_value >> 16)

        # Keep hash within 32-bit range
        hash_value = hash_value & 0xFFFFFFFF  # Masking to 32 bits

    # Return final 32-bit hash value
    return hash_value

# -------------------- Example Usage --------------------
# Input string to hash
input_str = "SecurePatientData"

# Compute the hash
hash_result = custom_hash(input_str)

# Display the result
print(f"Input string: {input_str}")
print(f"Hash value (32-bit): {hash_result}")
