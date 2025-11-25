import os
import gnupg
import yaml
from pathlib import Path


CREDS_PATH=Path("/data/creds.yaml")

def load_creds():
    with open(CREDS_PATH, "r") as file:
        creds = yaml.safe_load(file)
    return creds

def hash_content(content):
    return hashlib.sha256(content.encode()).hexdigest()

def login(email, hash_password):
    creds = get_creds() 
    email_hash = hash_content(email)    
    if not email or not hash_password or email_hash != creds["email_hash"] or hash_password != creds["password_hash"]:
        print("[ERROR] Invalid credentials.")
        return
    else:
        return creds["username"]
