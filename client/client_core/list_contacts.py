#!/usr/bin/env python3
import ssl
import json
import socket
from pathlib import Path

# --- Configuration ---
DATA_DIR = Path("/data")
CONTACTS_FILE = DATA_DIR / "contacts.json"
CA_CERT_PATH = Path("/tls_public/ca-cert.pem")
CLIENT_KEY = DATA_DIR / "client.key"
CLIENT_CERT = DATA_DIR / "client.crt"

# Mock DNS: In a real P2P app, you'd store IP/Port in contacts.json

def check_contact_status(email_hash, cert_pem):
    address = get_contact_address(email_hash)
    
    # Create mTLS context
    # We load our identity to prove who we are (Reciprocity Check)
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(CA_CERT_PATH))
    context.load_cert_chain(certfile=str(CLIENT_CERT), keyfile=str(CLIENT_KEY))
    
    # Optimization: Short timeout for online check
    try:
        with socket.create_connection((target_hostname, 5001), timeout=2) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=email_hash) as tls_sock:
                # If the control flow reaches here, the handshake succeeded!
                # 1. Online = True
                # 2. Reciprocated = True (Server accepted our cert)
                # 3. Verified = True (Server cert is CA-signed)
                return "ONLINE (Reciprocated)"
    except socket.timeout:
        return "OFFLINE"
    except ConnectionRefusedError:
        return "OFFLINE (Service Down)"
    except ssl.SSLError as e:
        if "alert certificate unknown" in str(e).lower() or "handshake failure" in str(e).lower():
            return "ONLINE (Not Reciprocated)"
        return f"TLS Error: {e}"
    except Exception as e:
        return f"Unknown: {e}, hostname: {target_hostname}"

def list_contacts():
    if not CONTACTS_FILE.exists():
        print("No contacts found. Add a contact first.")
        return

    with open(CONTACTS_FILE, "r") as f:
        contacts = json.load(f)

    print(f"{'EMAIL':<15} | {'STATUS':<25}")
    print("-" * 45)

    for email_hash, info in contacts.items():
        status = check_contact_status(email_hash, info['certificate'])
        print(f"{info['email']:<15} | {status:<25}")

if __name__ == "__main__":
    list_contacts()
