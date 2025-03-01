# Description: This file contains the implementation of the SecureFileTransfer class which provides methods to encrypt, decrypt, sign and verify files.

import os
import logging
from encryption.aes_gcm import encrypt_data, decrypt_data
from encryption.key_exchange import generate_x25519_keypair, derive_shared_secret
from encryption.ecdsa_sign import sign_data, verify_signature

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SecureFileTransfer:
    def __init__(self, storage_dir="storage/files/"):
        self.storage_dir = storage_dir
        os.makedirs(self.storage_dir, exist_ok=True)

    def encrypt_and_store_file(self, filepath, aes_key):
        try:
            with open(filepath, "rb") as f:
                file_data = f.read()
            nonce, ciphertext = encrypt_data(file_data, aes_key)
            encrypted_file_path = os.path.join(self.storage_dir, os.path.basename(filepath) + ".enc")
            with open(encrypted_file_path, "wb") as f:
                f.write(nonce + ciphertext)
            logging.info(f"File encrypted and stored: {encrypted_file_path}")
            return encrypted_file_path
        except Exception as e:
            logging.error(f"Error encrypting file: {e}")
            return None

    def decrypt_file(self, encrypted_file_path, aes_key):
        try:
            with open(encrypted_file_path, "rb") as f:
                file_data = f.read()
            nonce, ciphertext = file_data[:12], file_data[12:]
            decrypted_data = decrypt_data(nonce, ciphertext, aes_key)
            original_file_path = encrypted_file_path.replace(".enc", ".dec")
            with open(original_file_path, "wb") as f:
                f.write(decrypted_data)
            logging.info(f"File decrypted and stored: {original_file_path}")
            return original_file_path
        except Exception as e:
            logging.error(f"Error decrypting file: {e}")
            return None

    def sign_file(self, private_key, filepath):
        try:
            with open(filepath, "rb") as f:
                file_data = f.read()
            signature = sign_data(private_key, file_data)
            signature_path = filepath + ".sig"
            with open(signature_path, "wb") as f:
                f.write(signature)
            logging.info(f"File signed successfully: {signature_path}")
            return signature_path
        except Exception as e:
            logging.error(f"Error signing file: {e}")
            return None

    def verify_file_signature(self, public_key, filepath, signature_path):
        try:
            with open(filepath, "rb") as f:
                file_data = f.read()
            with open(signature_path, "rb") as f:
                signature = f.read()
            if verify_signature(public_key, file_data, signature):
                logging.info("File signature verified successfully.")
                return True
            else:
                logging.error("File signature verification failed.")
                return False
        except Exception as e:
            logging.error(f"Error verifying file signature: {e}")
            return False
