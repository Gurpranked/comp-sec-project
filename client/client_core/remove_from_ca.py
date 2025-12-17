#!/usr/bin/env python3
import os
import ssl
import json
import struct
import socket
import hashlib
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# --- Configuration (Matches register.py) ---
CA_HOST = "ca"
CA_PORT = 4444
DATA_DIR = Path("/data")
CA_CERT_PATH = Path("/tls_public/ca-cert.pem")
CLIENT_KEY_PATH = DATA_DIR / "client.key"

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

# --- Logic ---
def remove_account():
    email = os.environ.get('EMAIL')
    if not email:
        print("[ERROR] EMAIL env var required.")
        return

    email_hash = hash_email(email)

    if not CLIENT_KEY_PATH.exists():
        print(f"[ERROR] Private key not found at {CLIENT_KEY_PATH}. Cannot authenticate removal.")
        return

    # 1. Load the Private Key to sign the challenge later
    with open(CLIENT_KEY_PATH, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    # 2. Connect to CA
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(CA_CERT_PATH))
    
    try:
        with socket.create_connection((CA_HOST, CA_PORT)) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=CA_HOST) as tls_sock:
                
                # 3. Step 1: Send Removal Request
                print(f"[INFO] Requesting removal for {email_hash}...")
                send_msg(tls_sock, {"action": "remove_user", "email_hash": email_hash})
                
                # 4. Step 2: Handle Challenge
                response = recv_msg(tls_sock)
                
                if response.get("status") == "challenge_required":
                    challenge_hex = response.get("challenge")
                    challenge_bytes = bytes.fromhex(challenge_hex)
                    print("[INFO] Challenge received. Signing...")

                    # Sign the challenge using PSS padding (matches CA server expectation)
                    signature = private_key.sign(
                        challenge_bytes,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )

                    # Send signature back
                    send_msg(tls_sock, {"signature": signature.hex()})
                    
                    # 5. Final Result
                    final_res = recv_msg(tls_sock)
                    if final_res.get("status") == "success":
                        print(f"[SUCCESS] {final_res.get('message')}")
                        # Cleanup local credentials
                        CLIENT_KEY_PATH.unlink(missing_ok=True)
                        (DATA_DIR / "client.crt").unlink(missing_ok=True)
                        print("[INFO] Local identity files deleted.")
                    else:
                        print(f"[ERROR] Removal failed: {final_res.get('message')}")
                
                else:
                    print(f"[ERROR] Unexpected CA response: {response}")

    except Exception as e:
        print(f"[FATAL] Connection error: {e}")

if __name__ == "__main__":
    remove_account()
