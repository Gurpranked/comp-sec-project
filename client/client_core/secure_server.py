#!/usr/bin/env python3
import ssl
import socket
import struct
import json
import threading
from pathlib import Path

# --- Configuration ---
DATA_DIR = Path("/data")
RECEIVE_DIR = DATA_DIR / "received_files"
RECEIVE_DIR.mkdir(exist_ok=True)

CA_CERT = Path("/tls_public/ca-cert.pem")
CLIENT_KEY = DATA_DIR / "client.key"
CLIENT_CERT = DATA_DIR / "client.crt"
LISTEN_PORT = 5001

def handle_peer(tls_sock, addr):
    try:
        # Get the peer's identity from their certificate
        cert = tls_sock.getpeercert()
        # commonName is the email_hash we stored during registration
        sender_id = dict(x[0] for x in cert['subject'])['commonName']
        print(f"[INFO] Connection verified: {sender_id} from {addr}")

        # 1. Read the command header
        header = tls_sock.recv(4)
        if not header:
            return # Connection closed (likely just a status check)

        msg_len = struct.unpack("!I", header)[0]
        msg_data = tls_sock.recv(msg_len).decode('utf-8')
        request = json.loads(msg_data)

        # 2. Handle Actions
        action = request.get("action")

        if action == "ping":
            # Simple status check
            response = {"status": "online", "message": "I am here!"}
            resp_data = json.dumps(response).encode('utf-8')
            tls_sock.sendall(struct.pack("!I", len(resp_data)) + resp_data)

        elif action == "send_file":
            filename = request.get("filename")
            filesize = request.get("filesize")
            save_path = RECEIVE_DIR / filename

            print(f"[RECV] Receiving file '{filename}' ({filesize} bytes) from {sender_id}...")
            
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
