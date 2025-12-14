#!/usr/bin/env python3
import ssl
import json
import yaml
import socket
import gnupg
import os

# Configuration
HOST = "0.0.0.0"
PORT = 4444

TLS_CERT = "/app/ca.crt"
TLS_KEY = "/app/ca.key"

DB_FILE = "/app/db/users.yaml"
GNUPG_HOME = "/app/gnupg_home/"

CHALLENGES = {}

gpg = gnupg.GPG(gnupghome=GPG_HOME)

# Ensure DB file exists
if not os.path.exists(DB_FILE):
    with open(DB_FILE, "w") as f:
        json.dump({}, f)

# -----------------------------------------------------
# Utility
# -----------------------------------------------------

def read_user_db():
    """ Read the database directly from the file """
    with open(DB_FILE, "r") as f:
        return json.load(f)

def write_user_db(user_db):
    """ Write database directly to the file """
    with open(DB_FILE, "w") as f:
        json.dump(user_db, f)


# --------------------------
# Crytography helpers
# --------------------------

def generate_challenge(length=32):
    return secrets.token_hex(length)

def verify_signature(fingerprint, message, signaature):
    """ Verify a signed message with teh user's public key """
    keys = gpg.list_keys()
    if not any (k['fingerprint'] == fingerprint for k in keys):
        return False
    verified = gpg.verify_data(signature, message.encode())
    return verified.valid


# --------------------------
# Framing helpers
# --------------------------

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Client disconnected")
        buf += chunk
    return buf

def recv_msg(sock):
    header = recv_exact(sock, 4)
    length = struct.unpack("!I", header)[0]
    body = recv_exact(sock, length)
    return json.loads(body.decode())
    
def send_msg(sock, obj):
    data = json.dumps(obj).encode()
    sock.sendall(struct.pack("!I", len(data)) + data)

# -----------------------------------------------------
# Command handlers
# -----------------------------------------------------

def handle_register(sock, request):
    email_hash = request.get("email_hash")
    public_key = request.get("public_key")

    if not email_hash or not public_key:
        send_msg(sock, {"status": "error", "message": "Bad request: Missing email_hash or public_key"})

    user_db = read_user_db()
    if email_hash in user_db:
        send_msg(sock, {"status": "error", "message": "User exists"})
        return
    
    # Import user key
    import_result = gpg.import_key(public_key)

    if not import_result.count:
        send_msg(sock, {"status": "error", "message": "Failed to import public key"})
        return

    # Sign key
    fingerprint = import_result.fingerprints[0]
    signed_cert = gpg.sign_keys(fingerprint, local=True, detach=False)
    if not signed_cert
        send_msg(sock, {"status": "error", "message": "Key signing failed"})
        return

    # Store user entry
    user_db[email_hash] = str(signed_cert)
    write_user_db(user_db) 
    
    send_msg(sock, {
        "status": "success",
        "message": "User registered",
        "signed_certificate": str(signed_cert)
    })
   
def handle_remove_user(sock, request):
    """ Generate a challenge and send to user. """
    email_hash = request.get("email_hash")
    if not email_hash:
        send_msg(sock, {"status": "error", "message": "Missing email_hash"})
        return

    user_db = read_user_db()
    if email_hash not in user_db:
        send_msg(sock, {"status": "error", "message": "No such user"})
        return
    
    signed_cert = user_db[email_hash]
    verified_key = gpg.import_keys(signed_cert)
    fingerprint = verified_key.fingerprints[0]
    
    challenge = generate_challenge()
    send_msg(sock, {"status": "challenge", "challenge": challenge})

    response = recv_msg(sock)
    signature = response.get("signature")
    
    if not signature:
        send_msg(sock, {"status": "error", "message": "Missing signature"})
        return 
    
    if verify_signature(fingerprint, challenge, signature):
        del user_db[email_hash]
        write_user_db(user_db)
        send_msg(sock, {"status": "success", "message": "User removed"})
    else:
        send_msg(sock, {"status": "error", "message": "Invalid signature"})

def handle_get_key(sock, request):
    target_hash = request.get("email_hash")
    if not target_hash:
        send_msg(sock, {"status": "error", "message": "Missing email_hash"})
        return
     
    user_db = read_user_db()
    signed_cert = user_db[target_hash]
    if not signed_cert:
        send_msg(sock, {"status": "error", "message": "No such user"})
        return

    send_msg(sock, {"status": "success", "signed_certificate": signed_cert})

# -----------------------------------------------------
# Server main loop
# -----------------------------------------------------

def handle_client(sock):
    try:
        while True:
            req = recv_msg(sock)
            action = req.get("action")
        
            if action == "register_user":
                handle_register(sock, req)
            elif action == "get_public_key":
                handle_get_key(sock, req)
            elif action == "remove_user":
                handle_remove_user(sock, req)
            else:
                send_msg(sock, {"status": "error", "message": "Unknown action"})
        
    except (ConnectionError, ssl.SSLError):
        pass
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        sock.close()

def run_ca_server():
    # TLS setup
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=TLS_CERT, keyfile=TLS_KEY)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as server: 
        sock.bind((HOST, PORT))
        sock.listen(5)
        print(f"[INFO] CA server listening on {HOST}:{PORT}")

        while True:
            client, addr = server.accept()
            print(f"[INFO] Connection from {addr}")
            tls_conn = context.wrap_socket(client, server_side=True)    
            threading.Thread(
                target=handle_client, 
                args=(tls_conn,), 
                daemon=True
            ).start()

if __name__ == "__main__":
    run_ca_server()

