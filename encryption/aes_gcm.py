
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def encrypt_data(data, key):
    """Encrypt data using AES-GCM"""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # Generate a secure random nonce
    ciphertext = aesgcm.encrypt(nonce, data, None)  # No associated data
    return nonce, ciphertext

def decrypt_data(nonce, ciphertext, key):
    """Decrypt data using AES-GCM"""
    try:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)  # No associated data
    except Exception:
        return None  # Return None if decryption fails
