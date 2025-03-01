# Description: Securely transfer files over SCP using SSH in Python.

import paramiko
import os

# Secure SCP File Transfer Function
def secure_scp_transfer(host, username, password, local_file, remote_path):
    """Securely transfers a file over SCP using SSH."""
    try:
        # Create SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # Accept unknown keys
        ssh.connect(host, username=username, password=password)

        # Open SCP/SFTP session
        sftp = ssh.open_sftp()
        sftp.put(local_file, remote_path)  # Upload file securely
        sftp.close()
        ssh.close()
        print(f"✅ File '{local_file}' successfully transferred to '{host}:{remote_path}'")

    except Exception as e:
        print(f"❌ Secure Transfer Failed: {e}")

# Secure File Retrieval Function (Download)
def secure_scp_retrieve(host, username, password, remote_file, local_path):
    """Securely retrieves a file over SCP using SSH."""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=username, password=password)

        sftp = ssh.open_sftp()
        sftp.get(remote_file, local_path)  # Download file securely
        sftp.close()
        ssh.close()
        print(f"✅ File '{remote_file}' successfully retrieved from '{host}' to '{local_path}'")

    except Exception as e:
        print(f"❌ Secure Retrieval Failed: {e}")

# Example Usage
if __name__ == "__main__":
    SERVER_IP = "192.168.1.10"  # Replace with actual server IP
    USERNAME = "your_username"
    PASSWORD = "your_password"
    
    # Transfer file to server
    secure_scp_transfer(SERVER_IP, USERNAME, PASSWORD, "testfile.txt", "/home/user/testfile.txt")
    
    # Retrieve file from server
    secure_scp_retrieve(SERVER_IP, USERNAME, PASSWORD, "/home/user/testfile.txt", "retrieved_testfile.txt")
