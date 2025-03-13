# Description: This script demonstrates how to derive a 256-bit encryption key using PBKDF2-HMAC-SHA256.

import base64
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def derive_key_pbkdf2(passphrase: str, salt: bytes = b"static_salt", iterations: int = 100000) -> bytes:
    """Derive a 256-bit encryption key using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode())

# Example Usage
if __name__ == "__main__":
    passphrase = "SuperSecurePass123!"
    key = derive_key_pbkdf2(passphrase)
    print("Derived Key:", base64.b64encode(key).decode())