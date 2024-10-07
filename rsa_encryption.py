import random

def gcd(a, b):
    """Return the greatest common divisor of a and b."""
    while b:
        a, b = b, a % b
    return a

def generate_prime_candidate(length):
    """Generate an odd prime candidate of specified length in bits."""
    p = random.getrandbits(length)
    p |= (1 << length - 1) | 1  # Ensure p is odd and has the correct bit length
    return p

def is_prime(num):
    """Check if a number is prime using 6k +/- 1 optimization."""
    if num <= 1:
        return False
    if num <= 3:
        return True
    if num % 2 == 0 or num % 3 == 0:
        return False
    i = 5
    while i * i <= num:
        if num % i == 0 or num % (i + 2) == 0:
            return False
        i += 6
    return True

def generate_prime_number(length):
    """Generate a prime number of specified length in bits."""
    p = 4
    while not is_prime(p):
        p = generate_prime_candidate(length)
    return p

def mod_inverse(e, phi):
    """Return the modular inverse of e mod phi using Extended Euclidean Algorithm."""
    d_old, d = 1, 0
    r_old, r = phi, e
    while r != 0:
        quotient = r_old // r
        d_old, d = d, d_old - quotient * d
        r_old, r = r, r_old - quotient * r
    if r_old > 1:
        raise Exception('e is not invertible')
    return d_old % phi

def generate_keys(length):
    """Generate RSA public and private keys."""
    p = generate_prime_number(length)
    q = generate_prime_number(length)
    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose e
    e = 65537  # Commonly used value for e
    # Calculate d
    d = mod_inverse(e, phi)
    
    return (e, n), (d, n)  # Public and private keys

def encrypt(message, public_key):
    """Encrypt a message using the public key."""
    e, n = public_key
    # Convert the message to an integer
    message_int = int.from_bytes(message.encode('utf-8'), byteorder='big')
    if message_int >= n:
        raise ValueError("Message is too long for the key size.")
    cipher_int = pow(message_int, e, n)
    return cipher_int

def decrypt(ciphertext, private_key):
    """Decrypt a ciphertext using the private key."""
    d, n = private_key
    decrypted_int = pow(ciphertext, d, n)
    # Convert back to bytes and then decode to string
    decrypted_bytes = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, byteorder='big')
    try:
        return decrypted_bytes.decode('utf-8')
    except UnicodeDecodeError:
        return "Decryption failed: Invalid bytes."

if __name__ == "__main__":
    # Generate keys
    public_key, private_key = generate_keys(16)  # Use 16 bits for faster testing, increase for real use
    print(f"Public Key: {public_key}")
    print(f"Private Key: {private_key}")

    # Encrypt a message
    message = "This is a secret message."
    ciphertext = encrypt(message, public_key)
    print(f"Ciphertext: {ciphertext}")

    # Decrypt the message
    decrypted_message = decrypt(ciphertext, private_key)
    print(f"Decrypted: {decrypted_message}")
