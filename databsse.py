#Description: This file contains the database functions to interact with the SQLite database.
import sqlite3
import os

# Define the database file path
DATABASE_FILE = os.path.join("storage", "cryptsafe.db")

# Define the database file path (shared network location)
DATABASE_FILE = os.path.join("//network-share/storage", "cryptsafe.db")

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

def get_user(username):
    """Fetch a user's details from the database."""
    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        return cursor.fetchone()

def add_user(username, password_hash, role, x25519_public_key, ecdsa_public_key, otp_secret=None):
    """Add a new user to the database."""
    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (username, password_hash, role, x25519_public_key, ecdsa_public_key, otp_secret)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (username, password_hash, role, x25519_public_key, ecdsa_public_key, otp_secret))
        conn.commit()

def update_user_otp_secret(username, otp_secret):
    """Update a user's OTP secret in the database."""
    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET otp_secret = ? WHERE username = ?", (otp_secret, username))
        conn.commit()