# Description: This module provides functions for user registration, authentication, and role-based access control.
# It also includes functions to enable multi-factor authentication (MFA) using TOTP.
# The module interacts with the SQLite database to store user details and keys.
# The module also includes functions to generate and store ECDSA key pairs for users.
# The module provides a secure logging function to log user actions and errors.
# The module also defines roles and permissions for users.
# The main function provides a simple command-line interface to register and authenticate users.
import os
import json
import base64
import bcrypt
import logging
import pyotp
import sqlite3
from datetime import datetime
from encryption.aes_gcm import encrypt_data, decrypt_data
from encryption.key_derivation import derive_key_pbkdf2
from cryptography.hazmat.primitives import serialization
from encryption.ecdsa_sign import generate_ecdsa_keypair
from encryption.x25519_wrapper import generate_x25519_keypair

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Define database file path
DATABASE_FILE = os.path.join("storage", "cryptsafe.db")

# Define roles and permissions
ROLES = {
    "admin": ["read", "write", "manage_users", "manage_keys", "start_server"],
    "user": ["read", "write"],
    "readonly": ["read"]
}

# Initialize the database
def initialize_database():
    """Initialize the database and create the users table if it doesn't exist."""
    os.makedirs("storage", exist_ok=True)
    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                x25519_public_key TEXT NOT NULL,
                ecdsa_public_key TEXT NOT NULL,
                otp_secret TEXT
            )
        """)
        conn.commit()

# Initialize the database when the module is loaded
initialize_database()

# Secure logging function
def secure_log(user, action, details):
    timestamp = datetime.utcnow().isoformat()
    log_entry = json.dumps({"timestamp": timestamp, "user": user, "action": action, "details": details})
    logging.info(f"{timestamp} - {user} - {action}")
    with open("storage/logs/secure_access.log", "a") as log_file:
        log_file.write(log_entry + "\n")

def is_strong_password(password: str) -> bool:
    """Checks if the password meets strong password requirements."""
    if len(password) < 12:
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.islower() for char in password):
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(char in "!@#$%^&*()" for char in password):
        return False
    return True

def generate_totp_secret():
    """Generates a new TOTP secret."""
    return pyotp.random_base32()

def get_totp_uri(username: str, secret: str):
    """Generates the TOTP URI for the Authenticator App."""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="CryptSafe")

def register_user(username: str, password: str, private_key: bytes, role: str = "user"):
    """Registers a new user and stores their credentials and keys in the database."""
    try:
        # Check if the user already exists
        with sqlite3.connect(DATABASE_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                raise ValueError("User already exists.")
        
        if role not in ROLES:
            raise ValueError("Invalid role specified.")
        
        # Validate password strength
        if not is_strong_password(password):
            raise ValueError("Password does not meet strength requirements.")
        
        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        
        # Generate and store ECDSA key pair
        ecdsa_private_key, ecdsa_public_key = generate_and_store_ecdsa_keypair(username)
        
        # Generate X25519 key pair
        x25519_private_key, x25519_public_key = generate_x25519_keypair()
        
        # Add user to the database
        with sqlite3.connect(DATABASE_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (username, password_hash, role, x25519_public_key, ecdsa_public_key, otp_secret)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                username,
                base64.b64encode(hashed_password).decode(),
                role,
                base64.b64encode(x25519_public_key).decode(),
                base64.b64encode(ecdsa_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )).decode(),
                None  # OTP secret will be set during MFA setup
            ))
            conn.commit()
        
        secure_log(username, "User Registration", f"User registered successfully with role {role}.")
        logging.info(f"User {username} registered successfully with role {role}.")
        return True
    except Exception as e:
        logging.error(f"Error registering user {username}: {e}")
        secure_log(username, "User Registration Failed", str(e))
        return False

def authenticate_user(username: str, password: str):
    """Authenticates the user and retrieves their keys from the database."""
    try:
        with sqlite3.connect(DATABASE_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            if not user:
                raise ValueError("User does not exist.")
        
        # Verify password
        stored_hash = base64.b64decode(user[1])
        if not bcrypt.checkpw(password.encode(), stored_hash):
            raise ValueError("Invalid password.")
        
        # Retrieve user details
        role = user[2]
        x25519_public_key = base64.b64decode(user[3])
        ecdsa_public_key = base64.b64decode(user[4])
        otp_secret = user[5]
        
        # Load ECDSA private key
        ecdsa_private_key, _ = load_ecdsa_keypair(username)
        
        # Check if MFA is enabled
        if otp_secret:
            otp = input("Enter OTP from your Authenticator App: ")
            totp = pyotp.TOTP(otp_secret)
            if not totp.verify(otp):
                raise ValueError("Invalid OTP.")
        
        secure_log(username, "User Authentication", f"User authenticated successfully with role {role}.")
        logging.info(f"User {username} authenticated successfully with role {role}.")
        return x25519_public_key, role, ecdsa_private_key, ecdsa_public_key  # Return all four values
    except Exception as e:
        logging.error(f"Authentication failed for {username}: {e}")
        secure_log(username, "User Authentication Failed", str(e))
        return None, None, None, None  # Return None for all values on failure

def enable_mfa(username: str):
    """Enables MFA for the user by generating and storing an OTP secret."""
    try:
        with sqlite3.connect(DATABASE_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
            if not cursor.fetchone():
                raise ValueError("User does not exist.")
        
        # Generate TOTP secret
        otp_secret = generate_totp_secret()
        totp_uri = get_totp_uri(username, otp_secret)
        
        # Display the TOTP URI to the user (to be scanned by the Authenticator App)
        print("Scan the following QR code with your Authenticator App:")
        print(totp_uri)
        
        # Store OTP secret in the database
        with sqlite3.connect(DATABASE_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET otp_secret = ? WHERE username = ?", (otp_secret, username))
            conn.commit()
        
        secure_log(username, "MFA Enabled", "MFA enabled successfully.")
        logging.info(f"MFA enabled for user {username}.")
        return True
    except Exception as e:
        logging.error(f"Error enabling MFA for {username}: {e}")
        secure_log(username, "MFA Enable Failed", str(e))
        return False

def generate_and_store_ecdsa_keypair(username):
    """Generate and store an ECDSA key pair for the user."""
    private_key, public_key = generate_ecdsa_keypair()
    key_dir = os.path.join("storage/keys/", username)
    os.makedirs(key_dir, exist_ok=True)

    # Save private key
    with open(os.path.join(key_dir, "ecdsa_private_key.pem"), "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key
    with open(os.path.join(key_dir, "ecdsa_public_key.pem"), "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return private_key, public_key

def load_ecdsa_keypair(username):
    """Load the ECDSA key pair for the user."""
    key_dir = os.path.join("storage/keys/", username)

    # Load private key
    with open(os.path.join(key_dir, "ecdsa_private_key.pem"), "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )

    # Load public key
    with open(os.path.join(key_dir, "ecdsa_public_key.pem"), "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    return private_key, public_key

def check_permission(role: str, action: str):
    """Checks if the user's role allows the requested action."""
    return action in ROLES.get(role, [])

def main():
    print("Welcome to CryptSafe!")
    choice = input("Do you want to (1) Register or (2) Login? ")
    if choice == "1":
        username = input("Enter username: ")
        password = input("Enter password: ")
        role = input("Enter role (admin/user/readonly): ") or "user"
        private_key = os.urandom(32)  # Generate a random private key for testing
        if register_user(username, password, private_key, role):
            print(f"User registered successfully with role {role}.")
            enable_mfa_choice = input("Do you want to enable MFA? (y/n): ")
            if enable_mfa_choice.lower() == "y":
                if enable_mfa(username):
                    print("MFA enabled successfully.")
    elif choice == "2":
        username = input("Enter username: ")
        password = input("Enter password: ")
        private_key, role = authenticate_user(username, password)
        if private_key:
            print(f"Login successful. Role: {role}")
            action = input("Enter action (read/write/manage_users): ")
            if check_permission(role, action):
                print(f"Action {action} permitted.")
            else:
                print(f"Action {action} denied.")
        else:
            print("Login failed.")
    else:
        print("Invalid choice. Exiting.")

if __name__ == "__main__":
    main()