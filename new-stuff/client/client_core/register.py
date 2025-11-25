#!/user/bin/env python3
import gnupg
import sys
import os
import subprocess
from gen_keys import gen_keys
from ca_client import ca_req
from pathlib import Path

CREDS_PATH=Path("/data/creds.yaml")

# NOTE: Running as binary required these configured environment variables
# EMAIL: User email
# USERNAME: Self-explanatory
# PASSWORD: In plaintext


def hash_content(content):
   return hashlib.sha256(content.encode()).hexdigest()

def creds_exist():
    return CREDS_PATH.exists()

def store_creds(email, username, password):
    if creds_exist():
        print("[WARNING] Credentials already exist.")
        print("[WARNING] Potential credential tampering.")
        return True
    else:
        email_hash = hash_content(email)
        password_hash = hash_content(password)
    
        credentials = {
            "username": username,
            "email_hash": email_hash,
            "password_hash": password_hash,    
            "contacts:": []
        }
    
        with CREDS_PATH.open('w') as f:
            yaml.dump(credentials, f)
   
        # Make user credentials file readonly, prevent tampering
        path.chmod(stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)

        print("[INFO] Credentials stored locally")
        
        return False

def register(email, username, password):
    threat_potential = store_creds(email, username, password) 
    pubkey, threat_potential = gen_keys(email, username, threat_potential)
        
    if threat_potential:
        print("[THREAT] Detected a re-run of register on configured container.")
        print("[TRHEAT] Aborting...")
        return 
    
    print("[INFO] Keys generated")
    
    ca_request = {
        "command": "register",
        "email_hash": email_hash,
        "public_key": pubkey 
    } 
    
    try:
        resp = ca_req(ca_request)
    except Exception as e:
        print("[FATAL] CA Key Signing failed.")
        print(json.dumps({"status": "error", "message": str(e)}))
        # Forces the container to fail from starting
        sys.exit(1)
    
    # Store the signed key     
   with open("/data/signed_pubkey.asc", "w+") as f:
        f.write(resp["public_key"])
   
   print("[INFO] Container registration completed")
 
if __name__ == "__main__":
    # If restarting the container, don't register 
    return if creds_exist()
    email, username, password = os.environ['EMAIL'], os.environ['USERNAME'], os.environ['PASSWORD']
    if not email or not username or not password:
        print("NOTE: Required env vars: EMAIL, USERNAME, PASSWORD")
        return
    os.environ['EMAIL'] = ''
    os.environ['USERNAME'] = ''
    os.environ['PASSWORD'] = '' 
    register(email, username, password)
