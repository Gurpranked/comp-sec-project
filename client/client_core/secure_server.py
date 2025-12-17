#!/usr/bin/env python3
import ssl
import socket
import struct
import json
import threading
from pathlib import Path

# --- Configuration ---
DATA_DIR = Path("/data")
CONTACTS_FILE = DATA_DIR / "contacts.json" # <--- Added to track who we trust
RECEIVE_DIR = DATA_DIR / "received_files"
RECEIVE_DIR.mkdir(exist_ok=True)

CA_CERT = Path("/tls_public/ca-cert.pem")
CLIENT_KEY = DATA_DIR / "client.key"
CLIENT_CERT = DATA_DIR / "client.crt"
LISTEN_PORT = 5001

def is_authorized_contact(sender_id):
    """Checks if the sender's CN identity exists in our contacts list."""
    if not CONTACTS_FILE.exists():
        return False
    
    try:
        with open(CONTACTS_FILE, "r") as f:
            contacts = json.load(f)
        
        # Note: If sender_id is 'sd_client_3f4e...', and your JSON keys 
        # are the full 64-char hashes, we need to find a match.
        # We check if any key in contacts starts with the prefix in the sender_id.
        for email_hash in contacts.keys():
            if f"sd_client_{email_hash[:12]}" == sender_id:
                return True
        return False
    except Exception as e:
        print(f"[ERROR] Could not read contacts file: {e}")
        return False

def handle_peer(tls_sock, addr):
    try:
        # Get the peer's identity from their certificate
        cert = tls_sock.getpeercert()
        # sender_id is the Common Name (CN), e.g., 'sd_client_3f4e0b7b6f13'
        sender_id = dict(x[0] for x in cert['subject'])['commonName']
        
        # 1. Read the command header
        header = tls_sock.recv(4)
        if not header: return

        msg_len = struct.unpack("!I", header)[0]
        msg_data = tls_sock.recv(msg_len).decode('utf-8')
        request = json.loads(msg_data)
        action = request.get("action")

        # 2. Authorization Logic
        authorized = is_authorized_contact(sender_id)

        if action == "ping":
            if authorized:
                print(f"[INFO] Reciprocal ping from {sender_id}")
                response = {"status": "reciprocated", "message": "Mutual trust established."}
            else:
                print(f"[WARN] Unauthorized ping from {sender_id} (Not in contacts)")
                response = {"status": "unauthorized", "message": "You are not in my contact list."}
            
            resp_data = json.dumps(response).encode('utf-8')
            tls_sock.sendall(struct.pack("!I", len(resp_data)) + resp_data)

        elif action == "send_file":
            if not authorized:
                print(f"[SECURITY] Blocking file transfer from unauthorized peer: {sender_id}")
                return

            filename = request.get("filename")
            filesize = request.get("filesize")
            save_path = RECEIVE_DIR / filename
            
            print(f"[RECV] Receiving file '{filename}' from {sender_id}...")
            remaining = filesize
            with open(save_path, "wb") as f:
                while remaining > 0:
                    chunk = tls_sock.recv(min(remaining, 16384))
                    if not chunk: break
                    f.write(chunk)
                    remaining -= len(chunk)
            print(f"[SUCCESS] File saved to {save_path}")

    except Exception as e:
        print(f"[ERROR] Session error with {addr}: {e}")
    finally:
        tls_sock.close()


def start_client_server():
    # Setup mTLS Context
    # Purpose.CLIENT_AUTH means we are acting as a server verifying a client
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=str(CA_CERT))
    context.load_cert_chain(certfile=str(CLIENT_CERT), keyfile=str(CLIENT_KEY))
    
    # REQUIRE the other side to have a valid CA-signed certificate
    context.verify_mode = ssl.CERT_REQUIRED 

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', LISTEN_PORT))
        server.listen(10)
        print(f"[LISTENER] Waiting for contacts on port {LISTEN_PORT}...")

        while True:
            conn, addr = server.accept()
            try:
                # Perform the mTLS handshake
                tls_conn = context.wrap_socket(conn, server_side=True)
                # Handle the request in a new thread so the listener stays free
                threading.Thread(target=handle_peer, args=(tls_conn, addr), daemon=True).start()
            except ssl.SSLError as e:
                print(f"[AUTH FAILED] Unauthorized connection attempt from {addr}: {e}")
            except Exception as e:
                print(f"[NET ERROR] {e}")

if __name__ == "__main__":
    start_client_server()
