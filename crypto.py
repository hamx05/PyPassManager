import struct
from math import gcd

def leftRotate(x: int, c: int) -> int:
    """
    Performs a circular left bitwise rotation on a 32-bit integer.

    This function rotates the bits of the input integer to the left by a 
    specified number of places, wrapping the overflowed bits back to the 
    right end. The operation is constrained to 32 bits.

    Args:
        x (int): The 32-bit integer to rotate.
        c (int): The number of bit positions to rotate.

    Returns:
        int: The result of the left rotation as a 32-bit integer.
    """
    return (x << c | x >> (32 - c)) & 0xFFFFFFFF

def md5(key: str) -> str:
    """
    Computes the MD5 hash of an input string.

    This function implements the MD5 hashing algorithm to produce 
    a 128-bit hash value represented as a 32-character hexadecimal 
    string for a given input string. 
    
    It performs padding, initializes state variables, processes data 
    in 512-bit chunks, and applies bitwise operations and transformations 
    to compute the hash.

    Args:
        key (str): The input string to hash.

    Returns:
        str: The resulting hash value as a hexadecimal string.
    """

    # Shift Amounts: number of bits to left-rotate in each step of the MD5 transformation
    S = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ]

    # K Constants: set of 64 precomputed constants used in the main MD5 algorithm loop
    K = [
        int(abs(struct.unpack("f", struct.pack("f", i))[0]) * 2**32) & 0xFFFFFFFF
        for i in range(1, 65)
    ]

    # Initial hash values
    A = 0x67452301
    B = 0xefcdab89
    C = 0x98badcfe
    D = 0x10325476
    
    # Preprocessing
    original_length = len(key) * 8
    key = bytearray(key, 'utf-8')
    key.append(0x80)
    
    while (len(key) * 8) % 512 != 448:
        key.append(0)
    
    key += struct.pack('<Q', original_length)
    
    # Process each 512-bit chunk
    for i in range(0, len(key), 64):
        chunk = key[i:i + 64]
        M = [struct.unpack('<I', chunk[j:j + 4])[0] for j in range(0, 64, 4)]
        
        a, b, c, d = A, B, C, D
        
        for i in range(64):
            if 0 <= i <= 15:
                f = (b & c) | (~b & d)
                g = i
            elif 16 <= i <= 31:
                f = (d & b) | (~d & c)
                g = (5 * i + 1) % 16
            elif 32 <= i <= 47:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            elif 48 <= i <= 63:
                f = c ^ (b | ~d)
                g = (7 * i) % 16
            
            temp = (a + f + K[i] + M[g]) & 0xFFFFFFFF
            temp = leftRotate(temp, S[i])
            temp = (temp + b) & 0xFFFFFFFF
            a, b, c, d = d, temp, b, c
        
        A = (A + a) & 0xFFFFFFFF
        B = (B + b) & 0xFFFFFFFF
        C = (C + c) & 0xFFFFFFFF
        D = (D + d) & 0xFFFFFFFF
    
    # Produce the final hash value (little-endian)
    return ''.join(f'{x:02x}' for x in struct.pack('<4I', A, B, C, D))

def modInverse(e: int, phi: int) -> int:
    """
    Finds the modular multiplicative inverse of e under modulo phi.
    Uses the Extended Euclidean Algorithm.

    Args:
        e (int): The number to find the inverse for.
        phi (int): The modulo.

    Returns:
        int: The modular inverse of e modulo phi.
    """
    t, new_t = 0, 1
    r, new_r = phi, e

    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r

    if r > 1:
        raise ValueError("e is not invertible")
    if t < 0:
        t += phi

    return t

def generateRSAkeys() -> tuple[tuple[int, int], tuple[int, int]]:
    """
    Generates RSA keys manually.

    Returns:
        tuple: (public_key, private_key, n)
    """
    # Step 1: Choose two prime numbers
    # Example small prime numbers
    p = 61 
    q = 53 
    n = p * q  # Modulus
    phi = (p - 1) * (q - 1)  # Euler's Totient

    # Step 2: Choose e such that gcd(e, phi) = 1 and 1 < e < phi
    e = 17  # Commonly used public exponent
    if gcd(e, phi) != 1:
        raise ValueError("e and phi(n) are not coprime.")

    # Step 3: Compute d, the modular inverse of e
    d = modInverse(e, phi)

    public_key = (e, n)
    private_key = (d, n)

    return public_key, private_key

def RSAencrypt(plaintext: str, public_key: tuple) -> str:
    """
    Encrypts a plaintext string using RSA.

    Args:
        plaintext (str): The plaintext to encrypt.
        public_key (tuple): The public key (e, n).

    Returns:
        str: The encrypted message as a string of list of integers.
    """
    e, n = public_key
    encrypted = [(ord(char) ** e) % n for char in plaintext]
    encrypted = ",".join(map(str, encrypted)) # convert list of integers to a string of csv
    return encrypted

def RSAdecrypt(encrypted_message: str, private_key: tuple) -> str:
    """
    Decrypts an encrypted message using RSA.

    Args:
        encrypted_message (str): The encrypted message as a string of list of integers.
        private_key (tuple): The private key (d, n).

    Returns:
        str: The decrypted plaintext.
    """
    d, n = private_key
    encrypted_message = list(map(int, encrypted_message.split(','))) # revert to list of integers
    decrypted = ''.join([chr((char ** d) % n) for char in encrypted_message])
    return decrypted