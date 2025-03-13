import os
import sys
import json
import logging
import time
import asyncio
from datetime import datetime
from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.shortcuts import ProgressBar
from prompt_toolkit.shortcuts import button_dialog
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich.theme import Theme
from rich.panel import Panel
from rich.live import Live
from rich.progress import track
from rich.progress import Progress, SpinnerColumn, BarColumn, TimeRemainingColumn
from encryption.aes_gcm import encrypt_data, decrypt_data
from encryption.key_exchange import generate_x25519_keypair
from encryption.key_manager import store_encrypted_key
from file_handler import SecureFileTransfer
from auth import register_user, authenticate_user, check_permission, is_strong_password, enable_mfa
from auth import generate_and_store_ecdsa_keypair, load_ecdsa_keypair
from cryptography.hazmat.primitives import serialization
from blessed import Terminal

# Initialize rich console
console = Console()
term = Terminal()

# Logging Configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Define Directories
STORAGE_DIR = "storage/"
KEY_STORAGE = os.path.join(STORAGE_DIR, "keys/")
FILE_STORAGE = os.path.join(STORAGE_DIR, "files/")
LOG_STORAGE = os.path.join(STORAGE_DIR, "logs/")
USER_STORAGE = os.path.join(STORAGE_DIR, "users/")
ENCRYPTED_STORAGE = os.path.join(STORAGE_DIR, "encrypted_files/")
DECRYPTED_STORAGE = os.path.join(STORAGE_DIR, "decrypted_files/")
SIGNED_STORAGE = os.path.join(STORAGE_DIR, "signed_files/")
SIGNATURE_STORAGE = os.path.join(STORAGE_DIR, "signatures/")

# Create directories if they don't exist
for directory in [KEY_STORAGE, FILE_STORAGE, LOG_STORAGE, USER_STORAGE, ENCRYPTED_STORAGE, DECRYPTED_STORAGE, SIGNED_STORAGE, SIGNATURE_STORAGE]:
    os.makedirs(directory, exist_ok=True)

# Initialize SecureFileTransfer with storage directories
file_handler = SecureFileTransfer(
    encrypted_storage=ENCRYPTED_STORAGE,
    decrypted_storage=DECRYPTED_STORAGE,
    signed_storage=SIGNED_STORAGE,
    signature_storage=SIGNATURE_STORAGE
)

def secure_log(user, action, details):
    timestamp = datetime.utcnow().isoformat()
    log_entry = json.dumps({"timestamp": timestamp, "user": user, "action": action, "details": details})
    logging.info(f"{timestamp} - {user} - {action}")

def animated_text(text, delay=0.05):
    for char in text:
        sys.stdout.write(term.green + char)
        sys.stdout.flush()
        time.sleep(delay)
    print(term.normal)

def progress_task(task_name, duration=3):
    with Progress(
        SpinnerColumn(), BarColumn(), TimeRemainingColumn()
    ) as progress:
        task = progress.add_task(f"[cyan]{task_name}...", total=duration)
        for _ in range(duration):
            time.sleep(1)
            progress.update(task, advance=1)

# Authentication Phase
console.rule("[bold red]🔒 CryptSafe Authentication 🔒")
choice = Prompt.ask("[cyan]Do you want to (1) Register or (2) Login?[/cyan]")
username = Prompt.ask("[bold yellow]Enter username[/bold yellow]")
password = Prompt.ask("[bold yellow]Enter password[/bold yellow]", password=True)

if choice == "1":
    # Check password strength
    if not is_strong_password(password):
        console.print("[bold red]❌ Password does not meet strength requirements. Use at least 12 characters with uppercase, lowercase, digits, and special characters.[/bold red]")
        sys.exit(1)
    
    role = Prompt.ask("[bold yellow]Assign role (admin/user/readonly)[/bold yellow]", choices=["admin", "user", "readonly"], default="user")
    private_key, public_key = generate_x25519_keypair()
    if register_user(username, password, private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    ), role):
        console.print(f"[green]✅ User {username} registered successfully with role {role}.[/green]")
        
        # Prompt to enable MFA
        enable_mfa_choice = Prompt.ask("[bold yellow]Do you want to enable Multi-Factor Authentication (MFA)? (y/n)[/bold yellow]", choices=["y", "n"], default="n")
        if enable_mfa_choice == "y":
            if enable_mfa(username):
                console.print("[green]✅ MFA enabled successfully. Scan the QR code with your Authenticator App.[/green]")
            else:
                console.print("[bold red]❌ Failed to enable MFA.[/bold red]")
        
        sys.exit(0)
    else:
        console.print("[bold red]❌ Registration failed.[/bold red]")
        sys.exit(1)

elif choice == "2":
    private_key, role, ecdsa_private_key, ecdsa_public_key = authenticate_user(username, password)
    if not private_key:
        console.print("[bold red]❌ Authentication failed. Exiting.[/bold red]")
        sys.exit(1)
    console.rule(f"[green]✅ Logged in as {username} ({role})[/green]")
    secure_log(username, "Login", "Successful")
else:
    console.print("[bold red]❌ Invalid choice. Exiting.[/bold red]")
    sys.exit(1)

def banner():
    print(term.clear + term.bold_cyan_on_black(term.center("🚀 WELCOME TO CRYPTSAFE 🚀")))
    time.sleep(1)

console.print(Panel(
    """       
   ______  _______   ____  ____  _______   _________   ______        _       ________  ________  
 .' ___  ||_   __ \ |_  _||_  _||_   __ \ |  _   _  |.' ____ \      / \     |_   __  ||_   __  | 
/ .'   \_|  | |__) |  \ \  / /    | |__) ||_/ | | \_|| (___ \_|    / _ \      | |_ \_|  | |_ \_| 
| |         |  __ /    \ \/ /     |  ___/     | |     _.____`.    / ___ \     |  _|     |  _| _  
\ `.___.'\ _| |  \ \_  _|  |_    _| |_       _| |_   | \____) | _/ /   \ \_  _| |_     _| |__/ | 
 `.____ .'|____| |___||______|  |_____|     |_____|   \______.'|____| |____||_____|   |________| 
""",
    title="[bold red]🚀 Welcome to CryptSafe 🔐[/bold red]", 
    style="bold cyan", 
    expand=False
), justify="center")

# Function to Display Menu
def show_menu():
    table = Table(title="🔐 CryptSafe CLI Menu", header_style="bold magenta")
    table.add_column("Option", style="cyan", justify="center")
    table.add_column("Command", style="yellow")
    table.add_row("1", "Generate Keys")
    table.add_row("2", "Encrypt/Decrypt Data")
    table.add_row("3", "Perform File Operations")
    table.add_row("4", "View Stored Encrypted Files")
    table.add_row("5", "Sign File")  
    table.add_row("6", "Verify File Signature")  
    table.add_row("7", "Help & Information")
    table.add_row("8", "Secure File Transfer")  # Updated option name
    table.add_row("9", "Exit CryptSafe")

    console.print("\n")
    console.print(table, justify="center")

def list_encrypted_files():
    console.print("[bold cyan]📂 Encrypted Files in Storage:[/bold cyan]")
    try:
        encrypted_files = [f for f in os.listdir(ENCRYPTED_STORAGE) if f.endswith(".enc")]
        if encrypted_files:
            animated_text("📂 Listing Encrypted Files...")
            time.sleep(1)
            for file in encrypted_files:
                console.print(f"[green]🔒 {file}[/green]")
        else:
            console.print("[yellow]⚠️ No encrypted files found.[/yellow]")
    except Exception as e:
        console.log(f"[bold red]❌ Error listing encrypted files: {e}[/bold red]")
        return False
    
def show_help():
    animated_text("ℹ️  Displaying Help Information...")
    time.sleep(1)
    console.print("\n[bold cyan]ℹ️  CryptSafe Help & Information[/bold cyan]\n")

    help_table = Table(title="🛠️  Available Commands", header_style="bold magenta")
    help_table.add_column("Option", style="cyan", justify="center")
    help_table.add_column("Command", style="yellow")
    help_table.add_column("Description", style="white")

    help_table.add_row("1", "Generate Keys", 
                       "Generates an X25519 key pair for secure encryption and securely stores them.")
    help_table.add_row("2", "Encrypt/Decrypt Data", 
                       "Performs an AES-GCM encryption and decryption test to validate encryption functionality.")
    help_table.add_row("3", "File Encryption/Decryption", 
                       "Encrypt or decrypt a file using AES encryption. Stores encrypted files securely.")
    help_table.add_row("4", "View Encrypted Files in Storage", 
                       "List all stored encrypted files in the secure storage location.")
    help_table.add_row("5", "Secure File Transfer", 
                       "Allows securely transferring encrypted files to another user or system.")
    help_table.add_row("6", "Help & Info", 
                       "Displays details about available commands and their usage.")
    help_table.add_row("7", "Exit CryptSafe", 
                       "Safely logs out and exits the CryptSafe CLI.")

    console.print(help_table, justify="center")


def sign_file_cli(file_handler, ecdsa_private_key):
    """CLI function to sign a file."""
    file_path = Prompt.ask("[bold yellow]Enter the file path to sign[/bold yellow]")
    if not os.path.exists(file_path):
        console.print("[bold red]❌ File not found.[/bold red]", justify="center")
        return

    with console.status("[bold cyan]Signing file...[/bold cyan]", spinner="dots"):
        signature_path = file_handler.sign_file(ecdsa_private_key, file_path)

    if signature_path:
        console.print(f"[green]✅ File signed successfully. Signature saved to: {signature_path}[/green]", justify="center")
    else:
        console.print("[bold red]❌ File signing failed.[/bold red]", justify="center")

def verify_file_signature_cli(file_handler, ecdsa_public_key):
    """CLI function to verify a file signature."""
    file_path = Prompt.ask("[bold yellow]Enter the file path to verify[/bold yellow]")
    signature_path = Prompt.ask("[bold yellow]Enter the signature file path[/bold yellow]")

    if not os.path.exists(file_path) or not os.path.exists(signature_path):
        console.print("[bold red]❌ File or signature not found.[/bold red]", justify="center")
        return

    with console.status("[bold cyan]Verifying file signature...[/bold cyan]", spinner="dots"):
        if file_handler.verify_file_signature(ecdsa_public_key, file_path, signature_path):
            console.print("[green]✅ File signature verified successfully.[/green]", justify="center")
        else:
            console.print("[bold red]❌ File signature verification failed.[/bold red]", justify="center")

def main_cli():
    # Initialize SecureFileTransfer with storage directories
    file_handler = SecureFileTransfer(
        encrypted_storage=ENCRYPTED_STORAGE,
        decrypted_storage=DECRYPTED_STORAGE,
        signed_storage=SIGNED_STORAGE,
        signature_storage=SIGNATURE_STORAGE
    )

    # Generate or load the ECDSA key pair
    key_dir = os.path.join("storage/keys/", username)
    if not os.path.exists(key_dir):
        private_key, public_key = generate_and_store_ecdsa_keypair(username)
    else:
        private_key, public_key = load_ecdsa_keypair(username)

    # Authenticate the user and get keys
    private_key, role, ecdsa_private_key, ecdsa_public_key = authenticate_user(username, password)
    if not private_key:
        console.print("[bold red]❌ Authentication failed. Exiting.[/bold red]")
        sys.exit(1)

    console.rule(f"[green]✅ Logged in as {username} ({role})[/green]")
    secure_log(username, "Login", "Successful")

    while True:
        show_menu()
        command = Prompt.ask("[bold cyan]Select an option[/bold cyan]", choices=["1", "2", "3", "4", "5", "6", "7", "8", "9"])

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
                animated_text("🔑 Generating X25519 Key Pair...")
                time.sleep(1)
                console.log("[green]🔑 X25519 Key Pair Generated and Securely Stored[/green]")
            except Exception as e:
                console.log(f"[bold red]❌ Error generating/storing X25519 key pair: {e}[/bold red]")

        elif command == "2" and check_permission(role, "write"):
            progress_task("Running AES-GCM Test")
            AES_KEY = os.urandom(32)
            data = b"Confidential Data!"

            nonce, ciphertext = encrypt_data(data, AES_KEY)
            decrypted = decrypt_data(nonce, ciphertext, AES_KEY)
            assert decrypted == data
            if decrypted == data:
                console.log("[green]✅ AES-GCM Encryption Successful[/green]")
            else:
                console.log("[bold red]❌ AES-GCM Test Failed[/bold red]")

        elif command == "3" and check_permission(role, "write"):
            animated_text("📂 Secure File Operations...")
            time.sleep(1)
            console.print("[yellow]Feature under development![/yellow]", justify="center")

            action = Prompt.ask("[bold cyan]Do you want to (1) Encrypt or (2) Decrypt a file?[/bold cyan]", choices=["1", "2"])

            if action == "1":
                file_path = Prompt.ask("[bold yellow]Enter the file path to encrypt[/bold yellow]")
                if os.path.exists(file_path):
                    with console.status("[bold cyan]Encrypting file...[/bold cyan]", spinner="dots"):
                        for progress in track(range(100), description="[cyan]Encrypting...[/cyan]"):
                            time.sleep(0.03)  # Simulate encryption progress
                        enc_file, metadata_path = file_handler.encrypt(file_path)

                    if enc_file:
                        secure_log(username, "Encrypted File", enc_file)
                        console.print(f"[green]✅ File encrypted successfully: {enc_file}[/green]", justify="center")
                    else:
                        console.print("[bold red]❌ Encryption failed.[/bold red]", justify="center")
                else:
                    console.print("[bold red]❌ File not found.[/bold red]", justify="center")

            elif action == "2":
                file_path = Prompt.ask("[bold yellow]Enter the encrypted file path to decrypt[/bold yellow]")
                if os.path.exists(file_path):
                    with console.status("[bold cyan]Decrypting file...[/bold cyan]", spinner="dots"):
                        for progress in track(range(100), description="[cyan]Decrypting...[/cyan]"):
                            time.sleep(0.03)  # Simulate decryption progress
                        dec_file = file_handler.decrypt(file_path)

                    if dec_file:
                        secure_log(username, "Decrypted File", dec_file)
                        console.print(f"[green]✅ File decrypted successfully: {dec_file}[/green]", justify="center")
                    else:
                        console.print("[bold red]❌ Decryption failed. Check the key or metadata.[/bold red]", justify="center")
                else:
                    console.print("[bold red]❌ Encrypted file not found.[/bold red]", justify="center")

        elif command == "4":
            list_encrypted_files()

        elif command == "5":  # New option: Sign File
            sign_file_cli(file_handler, ecdsa_private_key)

        elif command == "6":  # New option: Verify File Signature
            verify_file_signature_cli(file_handler, ecdsa_public_key)

        elif command == "7":
            show_help()

        elif command == "8":  # Secure File Transfer
            if check_permission(role, "write"):
                action = Prompt.ask("[bold cyan]Do you want to (1) Send or (2) Receive a file?[/bold cyan]", choices=["1", "2"])
                
                if action == "1":
                    file_path = Prompt.ask("[bold yellow]Enter the file path to send[/bold yellow]")
                    receiver_username = Prompt.ask("[bold yellow]Enter the receiver's username[/bold yellow]")
                    payload_path = file_handler.secure_file_transfer_sender(file_path, receiver_username, private_key, ecdsa_private_key)
                    if payload_path:
                        console.print(f"[green]✅ File sent securely. Payload saved to: {payload_path}[/green]")
                    else:
                        console.print("[bold red]❌ Secure file transfer failed.[/bold red]")
                
                elif action == "2":
                    payload_path = Prompt.ask("[bold yellow]Enter the payload file path[/bold yellow]")
                    decrypted_file_path = file_handler.secure_file_transfer_receiver(payload_path, private_key, ecdsa_public_key)
                    if decrypted_file_path:
                        console.print(f"[green]✅ File received and verified successfully. Decrypted file saved to: {decrypted_file_path}[/green]")
                    else:
                        console.print("[bold red]❌ Secure file transfer failed.[/bold red]")
            else:
                console.print("[bold red]❌ Insufficient permissions.[/bold red]")

        elif command == "9":
            animated_text("🔒 Exiting CryptSafe... Goodbye!")
            break
        else:
            console.log("[bold red]❌ Invalid command or insufficient permissions.[/bold red]")

main_cli()
