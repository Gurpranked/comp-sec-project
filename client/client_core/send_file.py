#!/usr/bin/env python3
import ssl
import sys
import json
import socket
import struct
import hashlib
from pathlib import Path

# --- Configuration ---
DATA_DIR = Path("/data")
USER_FILES_DIR = Path("/user_files") 
CONTACTS_FILE = DATA_DIR / "contacts.json" # <--- Added for local verification
CA_CERT = Path("/tls_public/ca-cert.pem")
CLIENT_KEY = DATA_DIR / "client.key"
CLIENT_CERT = DATA_DIR / "client.crt"

def calculate_file_hash(path):
    """Calculates SHA-256 for end-to-end integrity verification."""
    sha256_hash = hashlib.sha256()
    with open(path, "rb") as f:
        for byte_block in iter(lambda: f.read(65536), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def is_contact_verified(email_hash):
    """Checks if the recipient exists in the local contacts database."""
    if not CONTACTS_FILE.exists():
        return False
    try:
        with open(CONTACTS_FILE, "r") as f:
            contacts = json.load(f)
        # Check if the full hash exists as a key in our contacts
        return email_hash in contacts
    except Exception as e:
        print(f"[ERROR] Failed to read contacts database: {e}")
        return False

def send_file(target_email_hash, filename):
    # 1. OUTBOUND WHITELIST CHECK
    # We reject the transfer before any network activity happens
    if not is_contact_verified(target_email_hash):
        print(f"[REJECTED] {target_email_hash[:12]}... is not in your contact list.")
        print("You can only send files to contacts you have explicitly added.")
        return

    # 2. File existence check
    path = USER_FILES_DIR / filename
    if not path.exists():
        print(f"[ERROR] File '{filename}' not found in /user_files.")
        return

    # 3. Integrity Hashing
    print(f"[INFO] Generating integrity hash...")
    file_hash = calculate_file_hash(path)

    # Identity/DNS Configuration
    short_hash = target_email_hash[:12].strip()
    target_hostname = f"sd_client_{short_hash}"
    port = 5001

    # Setup mTLS Context
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(CA_CERT))
    context.load_cert_chain(certfile=str(CLIENT_CERT), keyfile=str(CLIENT_KEY))

    print(f"[INFO] Connecting to verified contact {target_hostname}...")

    try:
        with socket.create_connection((target_hostname, port), timeout=10) as raw_sock:
            # server_hostname must match the CN in the peer's certificate
            with context.wrap_socket(raw_sock, server_hostname=short_hash) as tls_sock:
                
                # 4. Prepare Metadata (including the action and hash)
                metadata = {
                    "action": "send_file",
                    "filename": path.name,
                    "filesize": path.stat().st_size,
                    "sha256": file_hash
                }
                
                meta_json = json.dumps(metadata).encode('utf-8')
                tls_sock.sendall(struct.pack("!I", len(meta_json)) + meta_json)

                # 5. Stream File Data
                print(f"[INFO] Handshake successful. Streaming '{path.name}'...")
                
                with open(path, "rb") as f:
                    sent_bytes = 0
                    while chunk := f.read(16384):
                        tls_sock.sendall(chunk)
                        sent_bytes += len(chunk)
                        print(f"\rProgress: {sent_bytes}/{metadata['filesize']} bytes", end="")
                
                print("\n[SUCCESS] File sent securely to contact.")

    except socket.gaierror:
        print(f"[ERROR] DNS failure: Could not find '{target_hostname}'.")
    except (ConnectionRefusedError, socket.timeout):
        print(f"[ERROR] Contact is currently offline.")
    except ssl.SSLError as e:
        print(f"[AUTH ERROR] mTLS Handshake failed: {e}")
    except Exception as e:
        print(f"[FATAL ERROR] {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 send_file.py <target_email_hash> <filename>")
    else:
        send_file(sys.argv[1], sys.argv[2])
