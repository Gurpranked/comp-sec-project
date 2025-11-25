#!/usr/bin/env python3
import ssl
import json
import yaml
import socket
import gnupg
import os

HOST = "0.0.0.0"
PORT = 4444
DB_PATH = "/app/db/users.yaml"
GPG_HOME = "/app/gpg_home/"

gpg = gnupg.GPG(gnupghome=GPG_HOME)

# -----------------------------------------------------
# Utility
# -----------------------------------------------------

def load_users():
    if not os.path.exists(DB_PATH):
        return {}
    with open(DB_PATH) as f:
        return yaml.safe_load(f) or {}


def save_users(data):
    with open(DB_PATH, "w") as f:
        yaml.safe_dump(data, f)


# -----------------------------------------------------
# Command handlers
# -----------------------------------------------------

def handle_register(data):
    email = data.get("email")
    public_key = data.get("public_key")

    if not email or not public_key:
        return {"status": "error", "message": "Bad request"}

    users = load_users()

    if email_hash in users:
        return {"status": "error", "message": "User exists"}

    # Import user key
    result = gpg.import_keys(public_key)
    if not result.fingerprints:
        return {"status": "error", "message": "Invalid key"}

    fp = result.fingerprints[0]

    # Sign key
    sign_res = gpg.sign_key(fp)
    if not sign_res:
        return {"status": "error", "message": "Key signing failed"}

    # Export signed key
    signed_key = gpg.export_keys(fp)

    # Store user entry
    users[email_hash] = {
        "fp": fp,
        "public_key": signed_key
    }

    save_users(users)
    return {"status": "success", "public_key": signed_key}


def handle_remove_user(data):
    email_hash = data.get("email_hash")
    users = load_users()

    if email_hash not in users:
        return {"status": "error", "message": "No such user"}

    # Remove key from CA keyring
    fp = users[email_hash]["fp"]
    gpg.delete_keys(fp, secret=False)

    users.pop(email_hash)
    save_users(users)

    return {"status": "success", "message": f"User removed"}


def handle_get_key(data):
    email_hash = data.get("email_hash")
    users = load_users()

    if email_hash not in users:
        return {"status": "error", "message": "No such user"}

    return {"status": "success", "public_key": users[email_hash]["public_key"]}


# -----------------------------------------------------
# Server main loop
# -----------------------------------------------------

def handle_request(req):
    cmd = req.get("command")

    if cmd == "register":
        return handle_register(req)
    if cmd == "remove_user":
        return handle_remove_user(req)
    if cmd == "get_key":
        return handle_get_key(req)

    return {"status": "error", "message": "Unknown command"}


def main():
    # TLS setup
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/app/ca.crt", "/app/ca.key")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, PORT))
        sock.listen(10)
        print("CA running on port", PORT)

        while True:
            client, addr = sock.accept()
            with context.wrap_socket(client, server_side=True) as ssock:
                try:
                    data = json.loads(ssock.recv(65535).decode())
                    resp = handle_request(data)
                except Exception as e:
                    resp = {"status": "error", "message": str(e)}

                ssock.sendall(json.dumps(resp).encode())

if __name__ == "__main__":
    main()

