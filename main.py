# Description: Main CryptSafe CLI Application


import os
import sys
import json
import logging
from datetime import datetime
from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from encryption.aes_gcm import encrypt_data, decrypt_data
from encryption.key_exchange import generate_x25519_keypair
from encryption.key_manager import store_encrypted_key
from file_handler import SecureFileTransfer
from auth import register_user, authenticate_user, check_permission
from cryptography.hazmat.primitives import serialization

# Initialize rich console
console = Console()

# Logging Configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Define Directories
STORAGE_DIR = "storage/"
KEY_STORAGE = os.path.join(STORAGE_DIR, "keys/")
FILE_STORAGE = os.path.join(STORAGE_DIR, "files/")
LOG_STORAGE = os.path.join(STORAGE_DIR, "logs/")
USER_STORAGE = os.path.join(STORAGE_DIR, "users/")

for directory in [KEY_STORAGE, FILE_STORAGE, LOG_STORAGE, USER_STORAGE]:
    os.makedirs(directory, exist_ok=True)

def secure_log(user, action, details):
    timestamp = datetime.utcnow().isoformat()
    log_entry = json.dumps({"timestamp": timestamp, "user": user, "action": action, "details": details})
    logging.info(f"{timestamp} - {user} - {action}")

# Authentication Phase
console.rule("[bold red]🔒 CryptSafe Authentication 🔒")
choice = Prompt.ask("[cyan]Do you want to (1) Register or (2) Login?[/cyan]")
username = Prompt.ask("[bold yellow]Enter username[/bold yellow]")
password = Prompt.ask("[bold yellow]Enter password[/bold yellow]", password=True)

if choice == "1":
    role = Prompt.ask("[bold yellow]Assign role (admin/user/readonly)[/bold yellow]", choices=["admin", "user", "readonly"], default="user")
    private_key, public_key = generate_x25519_keypair()
    if register_user(username, password, private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    ), role):
        console.print(f"[green]✅ User {username} registered successfully with role {role}. Please restart and log in.[/green]")
        sys.exit(0)
    else:
        console.log("[bold red]❌ Registration failed.[/bold red]")
        sys.exit(1)

elif choice == "2":
    private_key, role = authenticate_user(username, password)
    if not private_key:
        console.log("[bold red]❌ Authentication failed. Exiting.[/bold red]")
        sys.exit(1)
    console.rule(f"[green]✅ Logged in as {username} ({role})[/green]")
else:
    console.log("[bold red]❌ Invalid choice. Exiting.[/bold red]")
    sys.exit(1)

# Function to Display Menu
def show_menu():
    table = Table(title="🔐 CryptSafe CLI Menu", header_style="bold magenta")
    table.add_column("Option", style="cyan", justify="center")
    table.add_column("Command", style="yellow")
    table.add_row("1", "Generate Keys")
    table.add_row("2", "Encrypt/Decrypt Data")
    table.add_row("3", "Perform File Operations")
    table.add_row("4", "Exit")
    console.print(table)

# Main Interactive Loop
def main_cli():
    while True:
        show_menu()
        command = Prompt.ask("[bold cyan]Select an option[/bold cyan]", choices=["1", "2", "3", "4"])
        
        if command == "1" and check_permission(role, "manage_keys"):
            try:
                private_key, public_key = generate_x25519_keypair()
                store_encrypted_key(
                    "private_x25519",
                    private_key.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption()
                    ),
                    private_key.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
                )
                with open(f"{KEY_STORAGE}public_x25519.pem", "wb") as f:
                    f.write(public_key.public_bytes_raw())
                console.log("[green]🔑 X25519 Key Pair Generated and Securely Stored[/green]")
            except Exception as e:
                console.log(f"[bold red]❌ Error generating/storing X25519 key pair: {e}[/bold red]")
        
        elif command == "2" and check_permission(role, "write"):
            console.log("[yellow]🔐 Running AES-GCM Encryption Test...[/yellow]")
            AES_KEY = os.urandom(32)
            data = b"Confidential Data!"
            try:
                nonce, ciphertext = encrypt_data(data, AES_KEY)
                decrypted = decrypt_data(nonce, ciphertext, AES_KEY)
                assert decrypted == data
                console.log("[green]✅ AES-GCM Encryption/Decryption Successful[/green]")
            except Exception as e:
                console.log(f"[bold red]❌ AES-GCM Test Failed: {e}[/bold red]")
        
        elif command == "3" and check_permission(role, "write"):
            console.log("[yellow]📂 Secure File Operations...[/yellow]")
            action = Prompt.ask("[bold cyan]Do you want to (1) Encrypt or (2) Decrypt a file?[/bold cyan]", choices=["1", "2"])
                
            file_handler = SecureFileTransfer()

            if action == "1":
                file_path = Prompt.ask("[bold yellow]Enter the file path to encrypt[/bold yellow]")
                if os.path.exists(file_path):
                    enc_file, metadata_path = file_handler.encrypt(file_path)
                    if enc_file:
                        secure_log(username, "Encrypted File", enc_file)
                        console.log(f"[green]✅ File encrypted successfully: {enc_file}[/green]")
                    else:
                        console.log("[bold red]❌ Encryption failed.[/bold red]")
                else:
                    console.log("[bold red]❌ File not found.[/bold red]")

            elif action == "2":
                file_path = Prompt.ask("[bold yellow]Enter the encrypted file path to decrypt[/bold yellow]")
                if os.path.exists(file_path):
                    dec_file = file_handler.decrypt(file_path)
                    if dec_file:
                        secure_log(username, "Decrypted File", dec_file)
                        console.log(f"[green]✅ File decrypted successfully: {dec_file}[/green]")
                    else:
                        console.log("[bold red]❌ Decryption failed. Check the key or metadata.[/bold red]")
                else:
                    console.log("[bold red]❌ Encrypted file not found.[/bold red]")
        
        elif command == "4":
            console.log("[green]🔒 Exiting CryptSafe.[/green]")
            break
        else:
            console.log("[bold red]❌ Invalid command or insufficient permissions.[/bold red]")

main_cli()