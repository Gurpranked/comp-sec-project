# Copyright 2025
# Author: Gurpreet Singh

import os
import ssl
import json
import socket
import gnupg

AUTH_HOST = "auth"
AUTH_PORT = 4444
GPG_HOME="/app/gpg_home"


gpg = gpupg.GPG(GPG_HOME)

def connect_to_authority():
    """Establish a TLS connection to the Authority Server"""
    context = ssl.create_default_context()
    context.load_verify_locations(cafile="/app/ca.crt")
    
    sock = socket.create_connection((AUTH_HOST, AUTH_PORT))
    return context.wrap_socket(sock, server_hostname=AUTH_HOST)

def generate_pgp_keypair(name, email):
    """Create a local PGP keypair"""
    print("[*] Generating PGP keypair...")
    input_data = gpg.gen_key_input(
        key_type = "RSA",
        key_length=2048,
        name_real=name,
        name_email=email,
    )
    
    key = gpg.gen_key(input_data)
    print(f"[*] Generated PGP key: {key.fingerprint}")
    return key.fingerprint

def upload_public_key(username, password):
    """Upload this client's public key to the authority."""
    pubkey = gpg.export_keys(gpg.list_keys[0]["fingerprint"])
    
    req = {
        "command": "upload_key",
        "username": username,
        "password": password,
        "pgp_key": pubkey,
    }
        
    with connect_to_authority() as ssock:
        ssock.sendall(json.dumps(req).encode())
        resp = json.loads(ssock.recv(8192).decode())
        
    print("[Authority response]", resp)
    return resp

    
def fetch_and_verify_key(username, password, target_user):
    """Fetch and verify another client's signed PGP key"""
    
    req = {
        "command": "get_key",
        "username": username,
        "password": password,
        "target_user": target_user,
    }
        
    with connect_to_authority() as ssock:
        ssock.sendall(json.dumps(req).encode())
        resp = json.loads(ssock.recv(8192).decode())
    
    if resp["status"] != "success":
        print("[-] Error: ", resp["message"])
        return None

    signed_key = resp["pgp_key"]
    
    with open("/app/authority_public.asc") as f:
        authority_pub = f.read()

    gpg.import_keys(authority_pub)
    import_result = gpg.import_keys(signed_key)
    
    fingerprint = import_result.fingerprints[0]
    print("[+] Imported signed key for user {user}: {fingerprint}")
    
    verify_result = gpg.verify(signed_key)
    
    if verify_result.valid:
        print("[+] Key is valid and signed by authority")
        return fingerprint
    else:
        print("[-] Signature verification failed.")
        return None

    
def encrypt_message(target_fp, message):
    encrypted = gpg.encrypt(message, recipients=[target_fp])
    if not encrypted.ok:
        raise RuntimeError("Encrypted failed")
    return str(encrypted)



        
