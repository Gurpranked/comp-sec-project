#!/user/bin/env python3

import sys
import yaml
import gnupg
from ca_client import ca_req
from pathlib import Path


CREDS_PATH = Path("/data/creds.yaml")
GNUPG_HOME = "/data/gnupg_home"

gpg = gnupg.GPG(gnupghome=GNUPG_HOME) 


# ------------
# Helpers
# ------------
def load_user_creds():
    if not CREDS_PATH.exists():
        raise RuntimeError("Credentials file not found")
     
    with CREDS_PATH.open('r') as f:
        return yaml.safe_load(f)

def sign_challenge(challenge: str, fingerprint: str) -> str:
    signed = gpg.sign(
        challenge,
        keyid=fingerprint,
        detach=True
    )
    if not signed:
        raise RuntimeError("Failed to sign challenge")
    
    return str(signed)

def remove_from_ca():
    creds = load_user_creds()
    email_hash = creds.get("email_hash")
    fingerprint = creds.get("fingerprint")
    
    if not email_hash or not fingerprint:
        raise RuntimeError("Invalid credentials file")

    # Request removal
    
    # Open CA connection
    client = CAClient()
    request1 = {
        "action": "remove_user",
        "email_hash": email_hash
    }
    response1 = client.request(request1)
    
    if response.get("status") != "challenge":
        raise RuntimeError (f"Unexpected CA response: {response}")

    challenge = response["challenge"]

    # Sign challenge
    signature = sign_challenge(challenge, fingerprint)
    
    # Send signature
    request2 = { 
        "signature": signature
    }
    response2 = client.request(request2)
    
    # Close CA connection
    client.close()
        
    if result.get("status") != "success":
        raise RuntimeError(f"Removal failed: {result}")
    
    print("[INFO] User successfully removed from CA")


if __name__ == "__main__":
    try:
        remove_from_ca()
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)
