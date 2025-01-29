# Affine-Cipher.
import string
import random

def gcd(a, b):
    """Compute the Greatest Common Divisor (GCD)"""
    while b:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    """Find the modular inverse of a under modulo m"""
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None  # If no modular inverse exists

def affine_encrypt(text, a, b):
    """Encrypt text using the Affine Cipher"""
    if gcd(a, 26) != 1:
        raise ValueError("Key 'a' must be coprime with 26")

    text = text.lower()
    alphabet = string.ascii_lowercase
    encrypted_text = ""

    for char in text:
        if char in alphabet:
            idx = alphabet.index(char)
            encrypted_idx = (a * idx + b) % 26
            encrypted_text += alphabet[encrypted_idx]
        else:
            encrypted_text += char  # Preserve non-alphabetic characters

    return encrypted_text

def affine_decrypt(text, a, b):
    """Decrypt text using the Affine Cipher"""
    if gcd(a, 26) != 1:
        raise ValueError("Key 'a' must be coprime with 26")

    a_inv = mod_inverse(a, 26)
    if a_inv is None:
        raise ValueError("No modular inverse found for 'a'")

    text = text.lower()
    alphabet = string.ascii_lowercase
    decrypted_text = ""

    for char in text:
        if char in alphabet:
            idx = alphabet.index(char)
            decrypted_idx = (a_inv * (idx - b)) % 26
            decrypted_text += alphabet[decrypted_idx]
        else:
            decrypted_text += char  # Preserve non-alphabetic characters

    return decrypted_text

# Example usage
if __name__ == "__main__":
    a = 5  # 'a' must be coprime with 26
    b = 8  # 'b' can be any integer

    plaintext = "hello world"
    ciphertext = affine_encrypt(plaintext, a, b)
    decrypted_text = affine_decrypt(ciphertext, a, b)

    print(f"Plaintext: {plaintext}")
    print(f"Ciphertext: {ciphertext}")
    print(f"Decrypted: {decrypted_text}")

Plaintext: hello world
Ciphertext: rclla ozapu
Decrypted: hello world

