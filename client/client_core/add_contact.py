#!/usr/bin/env python3
import os
import ssl
import json
import struct
import socket
import hashlib
from pathlib import Path

# --- Configuration ---
CA_HOST = "ca"
CA_PORT = 4444
DATA_DIR = Path("/data")
CA_CERT_PATH = Path("/tls_public/ca-cert.pem")
CONTACTS_FILE = DATA_DIR / "contacts.json"

def hash_email(email: str) -> str:
    return hashlib.sha256(email.encode()).hexdigest()

# --- Framing Helpers ---
def send_msg(sock, obj):
    data = json.dumps(obj).encode('utf-8')
    sock.sendall(struct.pack("!I", len(data)) + data)

def recv_msg(sock):
    header = sock.recv(4)
    if not header: return None
    length = struct.unpack("!I", header)[0]
    buf = b""
    while len(buf) < length:
        chunk = sock.recv(min(length - len(buf), 4096))
        if not chunk: break
        buf += chunk
    return json.loads(buf.decode('utf-8'))

# --- Contact Management ---
def save_contact(email_hash, certificate_pem, email_plaintext):
    contacts = {}
    if CONTACTS_FILE.exists():
        with open(CONTACTS_FILE, "r") as f:
            contacts = json.load(f)
    
    contacts[email_hash] = {
        "certificate": certificate_pem,
        "email": email_plaintext 
    }
    
    with open(CONTACTS_FILE, "w") as f:
        json.dump(contacts, f, indent=4)

def add_contact(target_email):
    target_hash = hash_email(target_email)
    print(f"[INFO] Looking up certificate for {target_email}...")

    # Connect to CA via TLS
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(CA_CERT_PATH))
    
    try:
        with socket.create_connection((CA_HOST, CA_PORT)) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=CA_HOST) as tls_sock:
                
                # Request the public key (certificate) from CA
                request = {
                    "action": "get_public_key",
                    "email_hash": target_hash
                }
                send_msg(tls_sock, request)
                
                response = recv_msg(tls_sock)
                
                if response.get("status") == "success":
                    cert_pem = response.get("signed_certificate")
                    save_contact(target_hash, cert_pem, target_email)
                    print(f"[SUCCESS] Contact {target_email} added and certificate stored locally.")
                else:
                    print(f"[ERROR] Could not add contact: {response.get('message')}")

    except Exception as e:
        print(f"[FATAL] Connection error: {e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 add_contact.py <email>")
    else:
        add_contact(sys.argv[1])
