#!/usr/bin/env python3
import ssl
import json
import socket
import struct
from pathlib import Path

# --- Configuration ---
DATA_DIR = Path("/data")
CONTACTS_FILE = DATA_DIR / "contacts.json"
CA_CERT_PATH = Path("/tls_public/ca-cert.pem")
CLIENT_KEY = DATA_DIR / "client.key"
CLIENT_CERT = DATA_DIR / "client.crt"


def check_contact_status(email_hash, cert_pem):
    # Create mTLS context
    # Load our identity to prove who we are (Reciprocity Check)
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(CA_CERT_PATH))
    context.load_cert_chain(certfile=str(CLIENT_CERT), keyfile=str(CLIENT_KEY))
    
    target_hostname = f"sd_client_{email_hash[:12].strip()}"  
    # Optimization: Short timeout for online check
    try:
        with socket.create_connection((target_hostname, 5001), timeout=2) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=email_hash[:12]) as tls_sock:
                ping_msg = json.dumps({"action": "ping"}).encode()
                tls_sock.sendall(struct.pack("!I", len(ping_msg)) + ping_msg)

                # Receive framed response
                header = tls_sock.recv(4)
                if header:
                    resp_len = struct.unpack("!I", header)[0]
                    resp_data = json.loads(tls_sock.recv(resp_len).decode())
                    if resp_data.get("status") == "reciprocated":
                        return "ONLINE (Reciprocated)"
                    return "ONLINE (Not Added Back)" 

    except socket.gaierror as e:
        return f"Offline (Logged out)"
    except socket.timeout:
        return "OFFLINE (timed out)"
    except ConnectionRefusedError:
        return "OFFLINE (Service Down)"
    except ssl.SSLError as e:
        if "alert certificate unknown" in str(e).lower() or "handshake failure" in str(e).lower():
            return "ONLINE (TLS)"
        return f"TLS Error: {e}"
    except Exception as e:
        return f"Unknown: {e}, hostname: {repr(target_hostname)}"

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
