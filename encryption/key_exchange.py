# encryption/key_exchange.py
from cryptography.hazmat.primitives.asymmetric import x25519

def generate_x25519_keypair():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_secret(private_key, peer_public_key):
    return private_key.exchange(peer_public_key)
