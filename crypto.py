import base64
import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def md5(text):
    """
    Computes the MD5 hash of the given text.
    
    Args:
        text (str): The text to hash.
        
    Returns:
        str: The MD5 hash of the text.
    """
    return hashlib.md5(text.encode()).hexdigest()

def generate_aes_key():
    """
    Generates a random AES-256 key.
    
    Returns:
        bytes: A 32-byte key for AES-256.
    """
    return os.urandom(32)  # 32 bytes = 256 bits

def encrypt_data(data, key):
    """
    Encrypts data using AES-256 in CBC mode with PKCS7 padding.
    
    Args:
        data (str): The data to encrypt.
        key (bytes): The 32-byte AES key.
        
    Returns:
        str: The base64-encoded encrypted data.
    """
    # Generate a random IV
    iv = os.urandom(16)
    
    # Create a padder
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    
    # Pad the data
    padded_data = padder.update(data.encode()) + padder.finalize()
    
    # Create an encryptor
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    # Encrypt the data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Combine IV and encrypted data and encode as base64
    result = base64.b64encode(iv + encrypted_data).decode('utf-8')
    
    return result

def decrypt_data(encrypted_data, key):
    """
    Decrypts data that was encrypted using AES-256 in CBC mode with PKCS7 padding.
    
    Args:
        encrypted_data (str): The base64-encoded encrypted data.
        key (bytes): The 32-byte AES key.
        
    Returns:
        str: The decrypted data.
    """
    # Decode the base64 data
    encrypted_bytes = base64.b64decode(encrypted_data)
    
    # Extract the IV (first 16 bytes)
    iv = encrypted_bytes[:16]
    ciphertext = encrypted_bytes[16:]
    
    # Create a decryptor
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    
    # Decrypt the data
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Create an unpadder
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    
    # Unpad the data
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    return data.decode('utf-8')

# For backward compatibility
encrypt_password = encrypt_data
decrypt_password = decrypt_data
