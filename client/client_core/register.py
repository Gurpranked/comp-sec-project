#!/usr/bin/env python3
import os
import ssl
import json
import struct
import socket
import hashlib
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# --- Configuration ---
CA_HOST = "ca"
CA_PORT = 4444
DATA_DIR = Path("/data")
CA_CERT_PATH = "/tls_public/ca-cert.pem" # Mount from Docker Volume
CLIENT_KEY_PATH = DATA_DIR / "client.key"
CLIENT_CERT_PATH = DATA_DIR / "client.crt"

def hash_email(email: str) -> str:
    return hashlib.sha256(email.encode()).hexdigest()

# --- Framing Helpers (Must match Server) ---
def send_msg(sock, obj):
    data = json.dumps(obj).encode('utf-8')
    sock.sendall(struct.pack("!I", len(data)) + data)

def recv_msg(sock):
    header = sock.recv(4)
    if not header: return None
    length = struct.unpack("!I", header)[0]
    chunks = []
    received = 0
    while received < length:
        chunk = sock.recv(min(length - received, 4096))
        if not chunk: break
        chunks.append(chunk)
        received += len(chunk)
    return json.loads(b"".join(chunks).decode('utf-8'))

# --- Logic ---
def register():
    # 1. Environment Variables
    email = os.environ.get('EMAIL')
    username = os.environ.get('USERNAME')
    if not email or not username:
        print("[ERROR] EMAIL and USERNAME env vars required.")
        return

    email_hash = hash_email(email)
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # 2. Generate Private Key for the Client
    print("[INFO] Generating private key...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # 3. Create Certificate Signing Request (CSR)
    print("[INFO] Creating CSR...")
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, email_hash[:12]),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, username),
    ])).sign(private_key, hashes.SHA256())

    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

    # 4. Connect to CA via TLS
    print(f"[INFO] Connecting to CA at {CA_HOST}:{CA_PORT}...")
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT_PATH)
    
    with socket.create_connection((CA_HOST, CA_PORT)) as raw_sock:
        with context.wrap_socket(raw_sock, server_hostname=CA_HOST) as tls_sock:
            
            # 5. Send Registration Request
            request = {
                "action": "register_user",
                "email_hash": email_hash,
                "csr": csr_pem
            }
            send_msg(tls_sock, request)
            
            # 6. Handle Response
            response = recv_msg(tls_sock)
            if response.get("status") == "success":
                # Save the issued certificate
                CLIENT_CERT_PATH.write_text(response["certificate"])
                
                # Save the private key (Keep this secure!)
                with open(CLIENT_KEY_PATH, "wb") as f:
                    f.write(private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
                
                print(f"[SUCCESS] Registered as {email_hash}")
                print(f"[INFO] Certificate saved to {CLIENT_CERT_PATH}")
            else:
                print(f"[FATAL] Registration failed: {response.get('message')}")

if __name__ == "__main__":
    register()
