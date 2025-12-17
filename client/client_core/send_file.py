#!/usr/bin/env python3
import ssl
import sys
import json
import socket
import struct
from pathlib import Path

# --- Configuration ---
DATA_DIR = Path("/data")
USER_FILES_DIR = Path("/user_files") 
CA_CERT = Path("/tls_public/ca-cert.pem")
CLIENT_KEY = DATA_DIR / "client.key"
CLIENT_CERT = DATA_DIR / "client.crt"

def send_file(target_email_hash, filename):
    # Ensure we look in the specific /user_files directory
    path = USER_FILES_DIR / filename
    
    if not path.exists():
        print(f"[ERROR] File '{filename}' not found in /user_files.")
        return

    # Identity/DNS Fix: Use the 12-char prefix
    short_hash = target_email_hash[:12].strip()
    target_hostname = f"sd_client_{short_hash}"
    port = 5001

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(CA_CERT))
    context.load_cert_chain(certfile=str(CLIENT_CERT), keyfile=str(CLIENT_KEY))

    print(f"[INFO] Connecting to {target_hostname}...")

    try:
        with socket.create_connection((target_hostname, port), timeout=10) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=short_hash) as tls_sock:
                
                metadata = {
                    "action": "send_file",
                    "filename": path.name,
                    "filesize": path.stat().st_size
                }
                
                meta_json = json.dumps(metadata).encode('utf-8')
                tls_sock.sendall(struct.pack("!I", len(meta_json)) + meta_json)

                print(f"[INFO] Identity verified. Sending '{path.name}'...")
                
                with open(path, "rb") as f:
                    sent_bytes = 0
                    while chunk := f.read(16384):
                        tls_sock.sendall(chunk)
                        sent_bytes += len(chunk)
                        print(f"\rProgress: {sent_bytes}/{metadata['filesize']} bytes", end="")
                
                print("\n[SUCCESS] File sent securely.")

    except socket.gaierror:
        print(f"[ERROR] Could not find contact '{target_hostname}'.")
    except (ConnectionRefusedError, socket.timeout):
        print(f"[ERROR] Contact is offline.")
    except Exception as e:
        print(f"[FATAL ERROR] {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 send_file.py <target_email_hash> <filename_in_user_files>")
    else:
        send_file(sys.argv[1], sys.argv[2])
