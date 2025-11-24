# Copyright 2025
# Author: Gurpreet Singh

# Designed to execute within a container

import gnupg
import json
import socket 
import ssl
import os
import yaml
import base64

HOST="0.0.0.0"
PORT=4444
GPG_HOME="/app/gpg_home"
DB_PATH="/app/data.yaml"
MAX_CONNECTIONS=10

gpg = gnupg.GPG(gnupghome=GPG_HOME)

# Load users from yaml
with open(DB_PATH) as f:
   users_yaml = yaml.safe_load(f)
USERS = users_yaml.get("users", {})


def authenticate_user(username, password):
    """Simple password authentication"""
    user = USERS.get(username)
    return user and user.get("password") == password

def store_user_key(username, armored_key):
    """Store or update a user's PGP key"""
    USERS[username]["pgp_key"] = armored_key
    
    with open("/app/users.yaml", "w") as f:
        yaml.safe_dump(("users": USERS), f)

def sign_user_key(username):
    """
    Sign user's PGP key with authority's key.
    Return ASCII-armored signed public key block
    """
    key_data = USERS[username].get("pgp_key")
    if not key_data:
        raise ValueError("User has no key uploaded.")
    
    # Import into GPG keyring
    import_result = gpg.import_keys(key_data)
    fingerprint = import_result.fingerprint[0]


    # Sign the key with authority key in keyring
    sign_result = gpg.sign_key(fingerprint)
    if not sign_result:
        raise RuntimeError("Failed to sign key")
    
    # Export signed key
    exportable = gpg.export_keys(fingerprint)
    return exportable

def handle_request():
    """Process JSON commands form clients."""
    cmd = data.get("command")
    username = data.get("username")
    password = data.get("password")
    
    if not authenticate_user(username, password):
        return {"status": "error", "message": "unauthorized"}
    
    if cmd == "upload_key":
        armored_key = data.get("pgp_key")
        store_user_key(username, armored_key)
        return {"status": "success", "message": "key stored"}
    
    elif cmd == "get_key":
        target = data.get("target_user")
        if target not in USERS:
            return {"status": "error", "message": "user not found"}
        key_data = USERS[target].get("pgp_key")
        if not key_data:
            return {"status": "success", "message": "target user has no key"}
        
        signed_key = sign_user_key(target)
        return {"status": "success", "pgp_key": signed_key}
        
    return {"status": "error", "message": "invalid command"}

def main():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="/app/ca.crt", keyfile="/app/ca.key")
    
    # TCP Socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, PORT))
        sock.listen(MAX_CONNECTIONS)
        print(f"[*] PGP Authority running on {HOST}:{PORT}")
        
        while True:
            raw_client, addr = socket.accept()
            with context.wrap_socket(raw_client, server_side=True) as ssock:
                try:
                    data = ssock.recv(8192)
                    if not data:
                        continue
                    req = json.loads(data.decode())
                    resp = handle_request(req)
            
                except Exception as e:
                    resp = {"status": "error", "message" str(e)}
                
                ssock.sendall(json.dumps(resp).encode())

if __name__ == "__main__":
    main()
                    
        

    

 
