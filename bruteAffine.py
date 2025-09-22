# Brute-force attack: try all possible a and b
def brute_force_affine(cipher_text, known_plaintext_pair, known_cipher_pair):
    # known_plaintext_pair: e.g., "ab"
    # known_cipher_pair: e.g., "GL"
    possible_solutions = []
    for a in range(1, 26):
        # a must be coprime with 26
        if gcd(a, 26) != 1:
            continue
        for b in range(26):
            decrypted = affine_decrypt(cipher_text, a, b)
            if decrypted is None:
                continue
            # Verify the known ciphertext pair maps to known plaintext pair
            index1 = alphabet.index(known_cipher_pair[0])
            index2 = alphabet.index(known_cipher_pair[1])
            a_inv = mod_inverse(a, 26)
            if a_inv is None:
                continue
            # Apply decryption formula only to the known pair
            dec1 = alphabet[(a_inv * (index1 - b)) % 26]
            dec2 = alphabet[(a_inv * (index2 - b)) % 26]
            if dec1.lower() == known_plaintext_pair[0] and dec2.lower() == known_plaintext_pair[1]:
                possible_solutions.append((a, b, decrypted))
    return possible_solutions
