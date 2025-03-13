import os
import json
import base64
import bcrypt
import logging
import pyotp
from datetime import datetime
from encryption.aes_gcm import encrypt_data, decrypt_data
from encryption.key_derivation import derive_key_pbkdf2
from cryptography.hazmat.primitives import serialization
from encryption.ecdsa_sign import generate_ecdsa_keypair

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Define storage directory for user authentication
USER_STORAGE = "storage/users/"
os.makedirs(USER_STORAGE, exist_ok=True)

# Define roles and permissions
ROLES = {
    "admin": ["read", "write", "manage_users", "manage_keys", "start_server"],
    "user": ["read", "write"],
    "readonly": ["read"]
}

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
    """Registers a new user, encrypts their private key, and stores credentials with role."""
    try:
        user_file = os.path.join(USER_STORAGE, f"{username}.json")
        if os.path.exists(user_file):
            raise ValueError("User already exists.")
        
        if role not in ROLES:
            raise ValueError("Invalid role specified.")
        
        # Validate password strength
        if not is_strong_password(password):
            raise ValueError("Password does not meet strength requirements.")
        
        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        
        # Derive encryption key from password
        encryption_key = derive_key_pbkdf2(password)
        nonce, encrypted_key = encrypt_data(private_key, encryption_key)
        
        # Generate and store ECDSA key pair
        ecdsa_private_key, ecdsa_public_key = generate_and_store_ecdsa_keypair(username)
        
        # Store user metadata securely
        user_data = {
            "username": username,
            "password_hash": base64.b64encode(hashed_password).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "encrypted_private_key": base64.b64encode(encrypted_key).decode(),
            "role": role,
            "otp_secret": None,  # OTP secret will be set during MFA setup
            "ecdsa_public_key": base64.b64encode(ecdsa_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )).decode(),
        }
        with open(user_file, "w") as f:
            json.dump(user_data, f, indent=4)
        
        secure_log(username, "User Registration", f"User registered successfully with role {role}.")
        logging.info(f"User {username} registered successfully with role {role}.")
        return True
    except Exception as e:
        logging.error(f"Error registering user {username}: {e}")
        secure_log(username, "User Registration Failed", str(e))
        return False

def authenticate_user(username: str, password: str):
    """Authenticates the user, retrieves role, and decrypts private key."""
    try:
        user_file = os.path.join(USER_STORAGE, f"{username}.json")
        if not os.path.exists(user_file):
            raise ValueError("User does not exist.")
        
        with open(user_file, "r") as f:
            user_data = json.load(f)
        
        # Verify password
        stored_hash = base64.b64decode(user_data["password_hash"])
        if not bcrypt.checkpw(password.encode(), stored_hash):
            raise ValueError("Invalid password.")
        
        # Retrieve user role
        role = user_data.get("role", "user")
        
        # Decrypt private key
        encryption_key = derive_key_pbkdf2(password)
        nonce = base64.b64decode(user_data["nonce"])
        encrypted_private_key = base64.b64decode(user_data["encrypted_private_key"])
        private_key = decrypt_data(nonce, encrypted_private_key, encryption_key)
        
        # Load ECDSA key pair
        ecdsa_private_key, ecdsa_public_key = load_ecdsa_keypair(username)
        
        # Check if MFA is enabled
        otp_secret = user_data.get("otp_secret")
        if otp_secret:
            otp = input("Enter OTP from your Authenticator App: ")
            totp = pyotp.TOTP(otp_secret)
            if not totp.verify(otp):
                raise ValueError("Invalid OTP.")
        
        secure_log(username, "User Authentication", f"User authenticated successfully with role {role}.")
        logging.info(f"User {username} authenticated successfully with role {role}.")
        return private_key, role, ecdsa_private_key, ecdsa_public_key  # Return all four values
    except Exception as e:
        logging.error(f"Authentication failed for {username}: {e}")
        secure_log(username, "User Authentication Failed", str(e))
        return None, None, None, None  # Return None for all values on failure
    
def enable_mfa(username: str):
    """Enables MFA for the user by generating and storing an OTP secret."""
    try:
        user_file = os.path.join(USER_STORAGE, f"{username}.json")
        if not os.path.exists(user_file):
            raise ValueError("User does not exist.")
        
        with open(user_file, "r") as f:
            user_data = json.load(f)
        
        # Generate TOTP secret
        otp_secret = generate_totp_secret()
        totp_uri = get_totp_uri(username, otp_secret)
        
        # Display the TOTP URI to the user (to be scanned by the Authenticator App)
        print("Scan the following QR code with your Authenticator App:")
        print(totp_uri)
        
        # Store OTP secret
        user_data["otp_secret"] = otp_secret
        with open(user_file, "w") as f:
            json.dump(user_data, f, indent=4)
        
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