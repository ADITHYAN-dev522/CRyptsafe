# Description: This script implements user registration, authentication, and role-based access control.


import os
import json
import base64
import bcrypt
import logging
from encryption.aes_gcm import encrypt_data, decrypt_data
from encryption.key_derivation import derive_key_pbkdf2
from datetime import datetime

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

def register_user(username: str, password: str, private_key: bytes, role: str = "user"):
    """Registers a new user, encrypts their private key, and stores credentials with role."""
    try:
        user_file = os.path.join(USER_STORAGE, f"{username}.json")
        if os.path.exists(user_file):
            raise ValueError("User already exists.")
        
        if role not in ROLES:
            raise ValueError("Invalid role specified.")
        
        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        
        # Derive encryption key from password
        encryption_key = derive_key_pbkdf2(password)
        nonce, encrypted_key = encrypt_data(private_key, encryption_key)
        
        # Store user metadata securely
        user_data = {
            "username": username,
            "password_hash": base64.b64encode(hashed_password).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "encrypted_private_key": base64.b64encode(encrypted_key).decode(),
            "role": role
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
        
        secure_log(username, "User Authentication", f"User authenticated successfully with role {role}.")
        logging.info(f"User {username} authenticated successfully with role {role}.")
        return private_key, role
    except Exception as e:
        logging.error(f"Authentication failed for {username}: {e}")
        secure_log(username, "User Authentication Failed", str(e))
        return None, None

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
