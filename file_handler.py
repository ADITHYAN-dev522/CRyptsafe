# Description: This file contains the implementation of the SecureFileTransfer class which is responsible for encrypting and decrypting files using AES-GCM and X25519.

import os
import json
import logging
import hashlib
from encryption.aes_gcm import encrypt_data, decrypt_data
from encryption.hashing import sha256_hash
from encryption.x25519_wrapper import generate_x25519_keypair, encrypt_aes_key, decrypt_aes_key

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class SecureFileTransfer:
    def __init__(self, keypair_file="x25519_keypair.json", storage_dir="storage"):
        self.keypair_file = keypair_file
        self.storage_dir = storage_dir
        self.encrypted_file_storage = os.path.join(self.storage_dir, "encrypted_files/")
        self.decrypted_file_storage = os.path.join(self.storage_dir, "decrypted_files/")
        self.metadata_storage = os.path.join(self.storage_dir, "metadata/")

        os.makedirs(self.encrypted_file_storage, exist_ok=True)
        os.makedirs(self.decrypted_file_storage, exist_ok=True)
        os.makedirs(self.metadata_storage, exist_ok=True)

        self.private_key, self.public_key = self.load_or_generate_x25519_keypair()

    def load_or_generate_x25519_keypair(self):
        """Loads an existing X25519 keypair or generates a new one."""
        if os.path.exists(self.keypair_file):
            with open(self.keypair_file, "r") as f:
                keypair = json.load(f)
            logging.info("✅ Loaded existing X25519 keypair.")
            return bytes.fromhex(keypair["private_key"]), bytes.fromhex(keypair["public_key"])
        
        private_key, public_key = generate_x25519_keypair()
        with open(self.keypair_file, "w") as f:
            json.dump({"private_key": private_key.hex(), "public_key": public_key.hex()}, f, indent=4)
        logging.info("🔑 Generated new X25519 keypair.")
        return private_key, public_key

    def encrypt(self, file_path):
        """Encrypts a file with a unique AES key and stores metadata."""
        try:
            logging.info(f"🔐 Encrypting file: {file_path}")
            if not os.path.exists(file_path):
                logging.error(f"❌ File does not exist: {file_path}")
                return None, None

            with open(file_path, "rb") as f:
                file_data = f.read()
            
            # Generate a unique AES key per file
            aes_key = os.urandom(32)
            
            # Encrypt AES key with X25519
            encrypted_aes_key = encrypt_aes_key(aes_key, self.public_key)
            
            nonce, ciphertext = encrypt_data(file_data, aes_key)
            file_hash = sha256_hash(file_data)

            encrypted_file_path = os.path.join(self.encrypted_file_storage, os.path.basename(file_path) + ".enc")
            with open(encrypted_file_path, "wb") as f:
                f.write(nonce + ciphertext)
            
            metadata = {
                "original_filename": os.path.basename(file_path),
                "file_hash": file_hash,
                "encrypted_filename": os.path.basename(encrypted_file_path),
                "nonce": nonce.hex(),
                "encrypted_aes_key": encrypted_aes_key.hex(),
            }

            metadata_path = os.path.join(self.metadata_storage, os.path.basename(file_path) + ".json")
            with open(metadata_path, "w") as f:
                json.dump(metadata, f, indent=4)

            logging.info(f"✅ File encrypted successfully: {encrypted_file_path}")
            return encrypted_file_path, metadata_path
        except Exception as e:
            logging.error(f"❌ Error encrypting file {file_path}: {e}", exc_info=True)
            return None, None

    def decrypt(self, encrypted_file_path):
        """Decrypts a file using the stored encrypted AES key."""
        try:
            logging.info(f"🔓 Decrypting file: {encrypted_file_path}")

            metadata_path = os.path.join(self.metadata_storage, os.path.basename(encrypted_file_path).replace(".enc", ".json"))
            if not os.path.exists(metadata_path):
                logging.error("❌ Metadata file missing. Cannot decrypt.")
                return None

            with open(metadata_path, "r") as f:
                metadata = json.load(f)
            
            required_fields = {"file_hash", "original_filename", "nonce", "encrypted_aes_key"}
            if not required_fields.issubset(metadata.keys()):
                logging.error("❌ Metadata file is incomplete or corrupted.")
                return None
            
            with open(encrypted_file_path, "rb") as f:
                file_data = f.read()
            
            nonce, ciphertext = file_data[:12], file_data[12:]
            
            expected_nonce = bytes.fromhex(metadata["nonce"])
            if nonce != expected_nonce:
                logging.error("❌ Nonce mismatch! Possible data corruption or incorrect key.")
                return None
            
            # Decrypt AES key with X25519 private key
            encrypted_aes_key = bytes.fromhex(metadata["encrypted_aes_key"])
            aes_key = decrypt_aes_key(encrypted_aes_key, self.private_key)
            
            decrypted_data = decrypt_data(nonce, ciphertext, aes_key)
            if decrypted_data is None:
                logging.error("❌ Decryption failed. Possible incorrect key or data corruption.")
                return None
            
            computed_hash = sha256_hash(decrypted_data)
            expected_hash = metadata["file_hash"]
            
            if computed_hash != expected_hash:
                logging.warning("⚠️ File integrity check failed. Possible tampering detected.")
                return None
            
            decrypted_file_path = os.path.join(self.decrypted_file_storage, metadata["original_filename"])
            with open(decrypted_file_path, "wb") as f:
                f.write(decrypted_data)
            
            logging.info(f"✅ File decrypted successfully: {decrypted_file_path}")
            return decrypted_file_path
        except Exception as e:
            logging.error(f"❌ Error decrypting file {encrypted_file_path}: {e}", exc_info=True)
            return None
