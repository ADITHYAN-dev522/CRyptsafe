# Description: This module provides functions to generate X25519 key pairs, encrypt and decrypt AES keys using X25519 keys.

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os

def generate_x25519_keypair():
    """Generates an X25519 key pair (private and public keys)."""
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key.private_bytes_raw(), public_key.public_bytes_raw()

def encrypt_aes_key(aes_key, public_key_bytes):
    """Encrypts an AES key using an X25519 public key."""
    public_key = x25519.X25519PublicKey.from_public_bytes(public_key_bytes)
    ephemeral_private = x25519.X25519PrivateKey.generate()
    shared_secret = ephemeral_private.exchange(public_key)
    
    # Derive a symmetric key from the shared secret
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"CryptSafe-X25519-KeyWrap",
    ).derive(shared_secret)
    
    # XOR AES key with derived key for simple key wrapping
    encrypted_key = bytes(a ^ b for a, b in zip(aes_key, derived_key))
    
    return ephemeral_private.public_key().public_bytes_raw() + encrypted_key

def decrypt_aes_key(encrypted_aes_key, private_key_bytes):
    """Decrypts an AES key using an X25519 private key."""
    private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)
    
    # Extract the ephemeral public key
    ephemeral_public_bytes = encrypted_aes_key[:32]
    encrypted_key = encrypted_aes_key[32:]
    
    ephemeral_public = x25519.X25519PublicKey.from_public_bytes(ephemeral_public_bytes)
    shared_secret = private_key.exchange(ephemeral_public)
    
    # Derive the same symmetric key from the shared secret
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"CryptSafe-X25519-KeyWrap",
    ).derive(shared_secret)
    
    # XOR back to recover AES key
    aes_key = bytes(a ^ b for a, b in zip(encrypted_key, derived_key))
    
    return aes_key
