#!/usr/bin/env python3
import ssl
import json
import socket
import struct
import os
from pathlib import Path

# --- Configuration ---
DATA_DIR = Path("/data")
CA_CERT = Path("/tls_public/ca-cert.pem")
CLIENT_KEY = DATA_DIR / "client.key"
CLIENT_CERT = DATA_DIR / "client.crt"
CONTACTS_FILE = DATA_DIR / "contacts.json"

def send_file(target_email_hash, file_path):
    path = Path(file_path)
    if not path.exists():
        print(f"[ERROR] File {file_path} not found.")
        return

    # 1. Look up contact IP/Port (Mocking DNS for demo)
    # In a real demo, use the container name or a fixed IP
    target_address = (f"sd_client_{target_email_hash[:12]", 5001) 

    # 2. Setup mTLS Context
    # We load our cert to prove identity and the CA cert to verify them
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(CA_CERT))
    context.load_cert_chain(certfile=str(CLIENT_CERT), keyfile=str(CLIENT_KEY))

    print(f"[INFO] Connecting to {target_email_hash[:12]}...")

    try:
        with socket.create_connection(target_address, timeout=10) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=target_email_hash) as tls_sock:
                
                # 3. Send Metadata (Filename and Size)
                metadata = {
                    "filename": path.name,
                    "filesize": path.stat().st_size
                }
                meta_data = json.dumps(metadata).encode('utf-8')
                tls_sock.sendall(struct.pack("!I", len(meta_data)) + meta_data)

                # 4. Stream File (Encrypted via Session Key)
                print(f"[INFO] Sending {path.name} ({metadata['filesize']} bytes)...")
                with open(path, "rb") as f:
                    while chunk := f.read(16384): # 16KB chunks
                        tls_sock.sendall(chunk)
                
                print("[SUCCESS] File sent securely.")

    except ssl.SSLError as e:
        print(f"[AUTH ERROR] Handshake failed. Perhaps they haven't added you back? {e}")
    except Exception as e:
        print(f"[FATAL] {e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python3 send_file.py <target_email_hash> <path_in_container>")
    else:
        send_file(sys.argv[1], sys.argv[2])
