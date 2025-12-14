#!/user/bin/env python3

import gnupg
import sys
import os
import stat
import yaml
import hashlib
import subprocess
from ca_client import ca_req
from pathlib import Path

DATA_DIR = Path("/data")
GNUPG_HOME = DATA_DIR / "gnupg_home"
CREDS_PATH = DATA_DIR / "creds.yaml"
SIGNED_CERT_PATH = DATA_DIR / "signed_pubkey.asc"

# NOTE: Running as binary required these configured environment variables
# EMAIL: User email
# USERNAME: Self-explanatory
# PASSWORD: Hashed

# -----------------
# Helpers
# -----------------
def hash_email(email: str) -> str:
    return hashlib.sha256(email.encode()).hexdigest()

def ensure_dirs():
    for d in [DATA_DIR, GNUPG_HOME]:
        d.mkdir(parents=True, exist_ok=True)

def init_gpg():
    return gnupg.GPG(gnupghome=str(GNUPG_HOME))

def generate_keys(gpg, email:str, username:str):
    # Prevent key overwrite / tampering
    for key in gpg.list_keys():
        for uid in key.get("uids", []):
            if email in uid:
                raise RuntimeError("GPG key already exists for this email")

    params = gpg.gen_key_input(
        name_email=email,
        name_real=username
        key_type="RSA",
        key_length=2048
    )

    key = gpg.gen_key(params)
    if not key or not key.fingerprint:
        raise RuntimeError("GPG key generation failed")

    # Export public key to /data/pubkey.asc
    pub_key = gpg.export_keys(key.fingerprint, armor=True)
   
    print("[INFO] Keys generated")
    
    return key.fingerprint, public_key

def store_creds(email_hash, username, password_hash, fingerprint):
    if CREDS_PATH.exists():
        raise RuntimeError("Credentials already exist")
    creds = {
        "username": username,
        "email_hash": email_hash,
        "password_hash": password_hash, 
        "fingerprint": fingerprint
        "contacts:": []
    }
    
    with CREDS_PATH.open('w') as f:
        yaml.dump(creds, f)
   
    # Make user credentials file readonly, prevent tampering
    CREDS_PATH.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

    print("[INFO] Credentials stored locally")
        

def register_with_ca(email:str, username:str, password_hash:str):
    ensure_dirs()
    gpg = init_gpg()
    email_hash = hash_email(email)

    # Generate keys
    fingerprint, public_key = generate_keys(gpg, email)

    # Make request to CA
    request = {
        "action": "register_user",
        "email_hash": email_hash,
        "public_key": public_key,
    }
    
    client = CAClient()
    response = client.request(request)
    client.close()

    if response.get("status") != "success":
        raise RuntimeError(f"CA registration failed: {response}")
    
    signed_cert = response["signed_certificate"]
    
    # Stored signed certificate
    SIGNED_CERT_PATH.write_text(signed_cert)
    SIGNED_CERT_PATH.chmod(stat.S_IRUSR | stat.S_IRGPR | stat.S_IROTH)
    
    store_credentials_email_hash, username, fingerptint, password_hash)
    print("[INFO] Registration complete")
    print(f"[INFO] Fingerprint: {fingerprint}")

if __name__ == "__main__":
    email, username, password_hash = os.environ['EMAIL'], os.environ['USERNAME'], os.environ['PASSWORD_HASH']
    if not email or not username or not password_hash:
        print("NOTE: Required env vars: EMAIL, USERNAME, PASSWORD_HASH") 
        return
    try:
        register_with_ca(email, password_hash)
    except Exception as e:
        print(f"[FATAL] {e}")
        sys.exit(1)
