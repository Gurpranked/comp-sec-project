#!/usr/bin/env python3
import ssl
import json
import socket
import os
import secrets
import struct
import threading
#from cryptography.exceptions import 
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Configuration
HOST = "0.0.0.0"
PORT = 4444

TLS_CERT = "/app/ca.crt"
TLS_KEY = "/app/ca.key"
DB_FILE = "/app/db/users.json"

db_lock = threading.Lock()

# Ensure DB file exists
if not os.path.exists(DB_FILE):
    with open(DB_FILE, "w") as f:
        json.dump({}, f)

# -----------------------------------------------------
# Utility
# -----------------------------------------------------

def load_ca_credentials():
    with open(TLS_KEY, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(TLS_CERT, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    return ca_key, ca_cert    

# Threading safe
def read_user_db():
    """ Read the database directly from the file """
    with db_lock: 
        with open(DB_FILE, "r") as f:
            return json.load(f)

# Threading safe
def write_user_db(user_db):
    """ Write database directly to the file """
    with db_lock: 
        with open(DB_FILE, "w") as f:
            json.dump(user_db, f)

# --------------------------
# Framing helpers
# --------------------------

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
            if not chunk: 
                # A return of b"" means the socket was closed cleanly
                return None 
            buf += chunk
        except (ConnectionResetError, BrokenPipeError):
            return None
    return buf

def recv_msg(sock):
    header = recv_exact(sock, 4)
    if header is None: 
        return None # Signal to the caller that the client is gone
    
    length = struct.unpack("!I", header)[0]
    body = recv_exact(sock, length)
    if body is None:
        return None
        
    return json.loads(body.decode())

def send_msg(sock, obj):
    data = json.dumps(obj).encode()
    sock.sendall(struct.pack("!I", len(data)) + data)

# -----------------------------------------------------
# Command handlers
# -----------------------------------------------------

def handle_register(sock, request, ca_key, ca_cert):
    print("[INFO] Handling registration request")
    email_hash = request.get("email_hash")
    csr_pem = request.get("csr")

    if not email_hash or not csr_pem:
        send_msg(sock, {"status": "error", "message": "Bad request: Missing email_hash or csr"})

    user_db = read_user_db()
    if email_hash in user_db:
        print(f"[WARN] Registration denied: {email_hash} already exists.")
        send_msg(sock, {"status": "error", "message": "User already registered"})
        return
   
    try:
        # Load and verify CSR
        print("[INFO] Verifying CSR...")
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        
        # Build new certificate
        # The subject comes from the CSR, but the issuer is our CA
        print("[INFO] Building new certificate...")
        cert = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        ).sign(ca_key, hashes.SHA256())

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

        # Update DB
        print("[INFO] Updating local database...")
        user_db = read_user_db()
        user_db[email_hash] = cert_pem
        write_user_db(user_db)

        send_msg(sock, {
            "status": "success", 
            "certificate": cert_pem,
            "ca_certificate": open(TLS_CERT, "r").read()
        })
        print(f"[SUCCESS] Issued certificate for {email_hash}")

    except Exception as e:
        print(f"[ERROR] Signing failed: {e}")
        send_msg(sock, {"status": "error", "message": str(e)}) 
  
def handle_remove_user(sock, request):
    print("[INFO] Handling user removal request")
    email_hash = request.get("email_hash")
    user_db = read_user_db()

    # 1. Immediate check: Does user exist?
    if email_hash not in user_db:
        print(f"[WARNING] User {email_hash} does not exist")
        send_msg(sock, {"status": "error", "message": "User not found in registry"})
        return

    # 2. Initiate Challenge
    print(f"[INFO] Generating challenge...")
    challenge = secrets.token_bytes(32)
    
    
    print("[INFO] Sending challenge...")
    send_msg(sock, {
        "status": "challenge_required",
        "challenge": challenge.hex()
    })

    try:
        # 3. Wait for client response (with timeout logic if needed)
        response = recv_msg(sock)
        signature_hex = response.get("signature")
        
        if not signature_hex:
            print("[WARNING] No signature provided in response")
            send_msg(sock, {"status": "error", "message": "No signature provided in response"})
            return
        
        signature = bytes.fromhex(signature_hex)
        user_cert = x509.load_pem_x509_certificate(user_db[email_hash].encode())
        public_key = user_cert.public_key()

        # 4. Attempt Verification
        print("[INFO] Verifying challenge signature...")
        public_key.verify(
            signature,
            challenge,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # 5. Success Path
        user_db = read_user_db()
        del user_db[email_hash]
        write_user_db(user_db)
        print(f"[SUCCESS] User {email_hash} removed")
        send_msg(sock, {"status": "success", "message": f"Identity {email_hash} removed"})

    except cryptography.exceptions.InvalidSignature:
        print("[WARNING] Invalid signature: Challenge failed")
        send_msg(sock, {"status": "error", "message": "Invalid signature: Challenge failed"})
    except Exception as e:
        # Catch-all for unexpected issues (e.g., malformed signature hex)
        print(f"[WARNING] User removal failed: {e}")
        send_msg(sock, {"status": "error", "message": f"Removal failed: {str(e)}"})

def handle_get_key(sock, request):
    print("[INFO] Handling user key request")
    target_hash = request.get("email_hash")
    user_db = read_user_db()
    
    if not target_hash:
        print(f"[WARNING] Request missing target email hash")
        send_msg(sock, {"status": "error", "message": "Missing email_hash"})
        return
    
    print("[INFO] Obtaining key...") 
    user_db = read_user_db()
    cert = user_db.get(target_hash)
    
    if not cert:
        print("[INFO] Invalid key request: No such user")
        send_msg(sock, {"status": "error", "message": "No such user"})
        return
    
    send_msg(sock, {"status": "success", "signed_certificate": cert})
    print("[SUCCESS] Certificate obtained and sent")

# -----------------------------------------------------
# Server main loop
# -----------------------------------------------------

def handle_client(sock, ca_key, ca_cert):
    try:
        while True:
            req = recv_msg(sock)
            if req is None:
                print(f"[INFO] Client disconnected (session ended).")
                break
            action = req.get("action")
        
            if action == "register_user":
                handle_register(sock, req, ca_key, ca_cert)
            elif action == "get_public_key":
                handle_get_key(sock, req)
            elif action == "remove_user":
                handle_remove_user(sock, req)
            else:
                send_msg(sock, {"status": "error", "message": "Unknown action"})
        
    except ssl.SSLError as e:
        if "EOF" not in str(e):
            print(f"[SSL ERROR] Handshake failed: {e}")
    except ConnectionError as e:
        print(f"[NET ERROR] Client disconnected unexpectedly")
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        sock.close()

def run_ca_server():
    # TLS setup
    ca_key, ca_cert = load_ca_credentials()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=TLS_CERT, keyfile=TLS_KEY)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as server: 
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(5)
        print(f"[INFO] CA server listening on {HOST}:{PORT}")

        while True:
            client, addr = server.accept()
            print(f"[INFO] Connection from {addr}")
            try:
                tls_conn = context.wrap_socket(client, server_side=True)    
                threading.Thread(
                    target=handle_client, 
                    args=(tls_conn, ca_key, ca_cert), 
                    daemon=True
                ).start()
            except Exception as e:
                print(f"[SSL ERROR] {e}")

if __name__ == "__main__":
    run_ca_server()

