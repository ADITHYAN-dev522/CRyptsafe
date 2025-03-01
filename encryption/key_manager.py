

import os
import json
import base64
import logging
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from encryption.aes_gcm import encrypt_data, decrypt_data
from encryption.hashing import sha256_hash
from encryption.key_exchange import generate_x25519_keypair, derive_shared_secret
from cryptography.hazmat.primitives import serialization


# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Define key storage directory
KEY_STORAGE = "storage/keys/"
os.makedirs(KEY_STORAGE, exist_ok=True)

def store_encrypted_key(key_name: str, aes_key: bytes, private_x25519: x25519.X25519PrivateKey):
    try:
        ephemeral_private_key = x25519.X25519PrivateKey.generate()
        ephemeral_public_key = ephemeral_private_key.public_key()

        user_private_key = x25519.X25519PrivateKey.from_private_bytes(private_x25519)
        shared_secret = derive_shared_secret(user_private_key, ephemeral_public_key)

        salt = os.urandom(16)  # Secure salt
        encryption_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"Key Wrapping",
        ).derive(shared_secret)

        nonce, encrypted_key = encrypt_data(aes_key, encryption_key)

        metadata = {
            "timestamp": datetime.utcnow().isoformat(),
            "ephemeral_public_key": base64.b64encode(ephemeral_public_key.public_bytes_raw()).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "encrypted_key": base64.b64encode(encrypted_key).decode(),
            "salt": base64.b64encode(salt).decode(),
            "integrity_check": sha256_hash(encrypted_key),
        }

        key_file = os.path.join(KEY_STORAGE, f"{key_name}.json")
        with open(key_file, "w") as f:
            json.dump(metadata, f, indent=4)

        logging.info(f"Key {key_name} securely stored using X25519 key wrapping.")
    except Exception as e:
        logging.error(f"Error storing key {key_name}: {e}")

def retrieve_encrypted_key(key_name: str, private_x25519: bytes) -> bytes:
    try:
        key_file = os.path.join(KEY_STORAGE, f"{key_name}.json")
        if not os.path.exists(key_file):
            raise FileNotFoundError(f"Key file {key_name} not found.")

        with open(key_file, "r") as f:
            metadata = json.load(f)

        user_private_key = x25519.X25519PrivateKey.from_private_bytes(private_x25519)
        ephemeral_public_key_bytes = base64.b64decode(metadata["ephemeral_public_key"])
        ephemeral_public_key = x25519.X25519PublicKey.from_public_bytes(ephemeral_public_key_bytes)

        shared_secret = derive_shared_secret(user_private_key, ephemeral_public_key)
        salt = base64.b64decode(metadata["salt"])

        encryption_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"Key Wrapping",
        ).derive(shared_secret)

        nonce = base64.b64decode(metadata["nonce"])
        encrypted_key = base64.b64decode(metadata["encrypted_key"])
        decrypted_key = decrypt_data(nonce, encrypted_key, encryption_key)

        if sha256_hash(encrypted_key) != metadata["integrity_check"]:
            raise ValueError("Integrity check failed!")

        if len(decrypted_key) != 32:
            raise ValueError("Retrieved private key is not 32 bytes long!")

        logging.info(f"Key {key_name} successfully retrieved and decrypted.")
        return decrypted_key
    except Exception as e:
        logging.error(f"Error retrieving key {key_name}: {e}")
        return None
