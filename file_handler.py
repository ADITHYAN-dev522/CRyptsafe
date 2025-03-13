#Description: This file contains the implementation of the SecureFileTransfer class, which provides methods to encrypt, decrypt, sign, and verify files securely.
# It also includes methods to securely transfer files between two parties using X25519 key exchange and ECDSA signatures.
# The class uses the encryption functions from the encryption module to perform the cryptographic operations.
# The class also interacts with the SQLite database to fetch public keys for secure file transfer.
# The class is designed to be used in a secure file transfer application to ensure confidentiality, integrity, and authenticity of files.
# The class is implemented with error handling and logging to provide feedback on the success or failure of operations.
# The class is designed to be used in a secure file transfer application to ensure confidentiality, integrity, and authenticity of files.
import os
import json
import logging
from encryption.aes_gcm import encrypt_data, decrypt_data
from encryption.ecdsa_sign import generate_ecdsa_keypair, sign_data, verify_signature
from encryption.hashing import sha256_hash
from encryption.x25519_wrapper import derive_shared_secret
from cryptography.hazmat.primitives.asymmetric import x25519
import base64
import sqlite3

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SecureFileTransfer:
    def __init__(self, encrypted_storage, decrypted_storage, signed_storage, signature_storage):
        """Initialize the SecureFileTransfer class with storage directories."""
        self.encrypted_storage = encrypted_storage
        self.decrypted_storage = decrypted_storage
        self.signed_storage = signed_storage
        self.signature_storage = signature_storage

        # Create directories if they don't exist
        for directory in [self.encrypted_storage, self.decrypted_storage, self.signed_storage, self.signature_storage]:
            os.makedirs(directory, exist_ok=True)

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
            
            nonce, ciphertext = encrypt_data(file_data, aes_key)
            file_hash = sha256_hash(file_data)

            # Save encrypted file in ENCRYPTED_STORAGE
            encrypted_file_path = os.path.join(self.encrypted_storage, os.path.basename(file_path) + ".enc")
            with open(encrypted_file_path, "wb") as f:
                f.write(nonce + ciphertext)
            
            # Save metadata in ENCRYPTED_STORAGE
            metadata = {
                "original_filename": os.path.basename(file_path),
                "file_hash": file_hash,
                "encrypted_filename": os.path.basename(encrypted_file_path),
                "nonce": nonce.hex(),
                "aes_key": aes_key.hex(),  # Store AES key as hex string
            }

            metadata_path = os.path.join(self.encrypted_storage, os.path.basename(file_path) + ".json")
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

            metadata_path = os.path.join(self.encrypted_storage, os.path.basename(encrypted_file_path).replace(".enc", ".json"))
            if not os.path.exists(metadata_path):
                logging.error("❌ Metadata file missing. Cannot decrypt.")
                return None

            with open(metadata_path, "r") as f:
                metadata = json.load(f)
            
            required_fields = {"file_hash", "original_filename", "nonce", "aes_key"}
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
            
            # Retrieve the AES key from metadata
            aes_key = bytes.fromhex(metadata["aes_key"])
            
            # Decrypt the file
            decrypted_data = decrypt_data(nonce, ciphertext, aes_key)
            if decrypted_data is None:
                logging.error("❌ Decryption failed. Possible incorrect key or data corruption.")
                return None
            
            computed_hash = sha256_hash(decrypted_data)
            expected_hash = metadata["file_hash"]
            
            if computed_hash != expected_hash:
                logging.warning("⚠️ File integrity check failed. Possible tampering detected.")
                return None
            
            # Save decrypted file in DECRYPTED_STORAGE
            decrypted_file_path = os.path.join(self.decrypted_storage, metadata["original_filename"])
            with open(decrypted_file_path, "wb") as f:
                f.write(decrypted_data)
            
            logging.info(f"✅ File decrypted successfully: {decrypted_file_path}")
            return decrypted_file_path
        except Exception as e:
            logging.error(f"❌ Error decrypting file {encrypted_file_path}: {e}", exc_info=True)
            return None

    def sign_file(self, private_key, file_path):
        """Signs a file using ECDSA."""
        try:
            logging.info(f"🔏 Signing file: {file_path}")
            if not os.path.exists(file_path):
                logging.error(f"❌ File does not exist: {file_path}")
                return None

            with open(file_path, "rb") as f:
                file_data = f.read()

            # Save signed file in SIGNED_STORAGE
            signed_file_path = os.path.join(self.signed_storage, os.path.basename(file_path))
            with open(signed_file_path, "wb") as f:
                f.write(file_data)
            
            # Generate signature and save in SIGNATURE_STORAGE
            signature = sign_data(private_key, file_data)
            signature_path = os.path.join(self.signature_storage, os.path.basename(file_path) + ".sig")
            with open(signature_path, "wb") as f:
                f.write(signature)
            
            logging.info(f"✅ File signed successfully. Signature saved to: {signature_path}")
            return signature_path
        except Exception as e:
            logging.error(f"❌ Error signing file {file_path}: {e}", exc_info=True)
            return None

    def verify_file_signature(self, public_key, file_path, signature_path):
        """Verifies the signature of a file."""
        try:
            logging.info(f"🔍 Verifying file signature: {file_path}")
            if not os.path.exists(file_path) or not os.path.exists(signature_path):
                logging.error("❌ File or signature not found.")
                return False

            with open(file_path, "rb") as f:
                file_data = f.read()
            with open(signature_path, "rb") as f:
                signature = f.read()
            
            if verify_signature(public_key, file_data, signature):
                logging.info("✅ File signature verified successfully.")
                return True
            else:
                logging.error("❌ File signature verification failed.")
                return False
        except Exception as e:
            logging.error(f"❌ Error verifying file signature: {e}", exc_info=True)
            return False
        
    def secure_file_transfer_sender(self, file_path, receiver_username, sender_private_key, sender_ecdsa_private_key):
        """Securely transfer a file to a receiver."""
        try:
            # Fetch receiver's public key from the database
            with sqlite3.connect("storage/cryptsafe.db") as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT x25519_public_key FROM users WHERE username = ?", (receiver_username,))
                result = cursor.fetchone()
                if not result:
                    raise ValueError(f"Receiver {receiver_username} not found.")
                receiver_public_key_bytes = base64.b64decode(result[0])

            # Generate ephemeral key pair
            ephemeral_private_key = x25519.X25519PrivateKey.generate()
            ephemeral_public_key = ephemeral_private_key.public_key()

            # Derive shared secret
            receiver_public_key = x25519.X25519PublicKey.from_public_bytes(receiver_public_key_bytes)
            shared_secret = derive_shared_secret(ephemeral_private_key, receiver_public_key)

            # Encrypt AES key with shared secret
            aes_key = os.urandom(32)
            encrypted_aes_key = self._encrypt_aes_key(aes_key, shared_secret)

            # Encrypt the file with AES key
            nonce, ciphertext = encrypt_data(open(file_path, "rb").read(), aes_key)

            # Sign the file
            file_hash = sha256_hash(open(file_path, "rb").read())
            signature = sign_data(sender_ecdsa_private_key, file_hash.encode())

            # Prepare the payload
            payload = {
                "ephemeral_public_key": base64.b64encode(ephemeral_public_key.public_bytes_raw()).decode(),
                "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode(),
                "nonce": base64.b64encode(nonce).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "signature": base64.b64encode(signature).decode(),
                "file_hash": file_hash
            }

            # Save the payload (or send it over the network)
            payload_path = os.path.join(self.encrypted_storage, f"secure_transfer_payload_{receiver_username}.json")
            with open(payload_path, "w") as f:
                json.dump(payload, f, indent=4)

            logging.info(f"Secure file transfer payload created successfully: {payload_path}")
            return payload_path
        except Exception as e:
            logging.error(f"Error in secure file transfer sender: {e}")
            return None

    def secure_file_transfer_receiver(self, payload_path, receiver_private_key_bytes, sender_ecdsa_public_key):
        """Receive and decrypt a securely transferred file."""
        try:
            # Load the payload
            with open(payload_path, "r") as f:
                payload = json.load(f)

            # Extract components
            ephemeral_public_key_bytes = base64.b64decode(payload["ephemeral_public_key"])
            encrypted_aes_key = base64.b64decode(payload["encrypted_aes_key"])
            nonce = base64.b64decode(payload["nonce"])
            ciphertext = base64.b64decode(payload["ciphertext"])
            signature = base64.b64decode(payload["signature"])
            file_hash = payload["file_hash"]

            # Derive shared secret
            ephemeral_public_key = x25519.X25519PublicKey.from_public_bytes(ephemeral_public_key_bytes)
            receiver_private_key = x25519.X25519PrivateKey.from_private_bytes(receiver_private_key_bytes)
            shared_secret = derive_shared_secret(receiver_private_key, ephemeral_public_key)

            # Decrypt AES key
            aes_key = self._decrypt_aes_key(encrypted_aes_key, shared_secret)

            # Decrypt the file
            decrypted_data = decrypt_data(nonce, ciphertext, aes_key)

            # Verify file integrity
            if sha256_hash(decrypted_data) != file_hash:
                raise ValueError("File integrity check failed!")

            # Verify signature
            if not verify_signature(sender_ecdsa_public_key, file_hash.encode(), signature):
                raise ValueError("File signature verification failed!")

            # Save the decrypted file
            decrypted_file_path = os.path.join(self.decrypted_storage, "decrypted_file")
            with open(decrypted_file_path, "wb") as f:
                f.write(decrypted_data)

            logging.info(f"Secure file transfer completed successfully. Decrypted file saved to: {decrypted_file_path}")
            return decrypted_file_path
        except Exception as e:
            logging.error(f"Error in secure file transfer receiver: {e}")
            return None
        
    def _encrypt_aes_key(self, aes_key, shared_secret):
        """Encrypt the AES key using the shared secret."""
        return bytes(a ^ b for a, b in zip(aes_key, shared_secret))

    def _decrypt_aes_key(self, encrypted_aes_key, shared_secret):
        """Decrypt the AES key using the shared secret."""
        return bytes(a ^ b for a, b in zip(encrypted_aes_key, shared_secret))