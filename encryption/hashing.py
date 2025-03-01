#this is hash

import hashlib

def sha256_hash(data):
    """Returns SHA-256 hash of given data."""
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()
