#!/usr/bin/env python3
import sys
import json
import hashlib
import gnupg
from pathlib import Path
from ca_client import CAClient

# -----------
# Paths
# -----------

GNUPG_HOME = "/data/gnupg_home"
CONTACTS_DIR = Path("/data/contacts")
CONTACTS_DIR.mkdir(exists_ok=True)

CA_GNUPG_KEYRING = "/data/ca_pubkey.asc" # imported at build/runtime

gpg = gnupg.GPG(gnupghome=GNUPG_HOME)



# -----------
# Helpers
# -----------
def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def fail(msg:
    print(json.dumps({"status": "error", "message": msg})
    sys.exit(1)

def add_contact():
    if len(sys.argv) != 2:
        fail("Usage: add_contact.py <email>")
    
    email = sys.argv[1].strip()
    email_hash = sha256(email)
    
    # Request signed public key
    with CAClient() as ca:
        resp = ca.request({
            "action": "get_public_key",
            "email_hash": email_hash
        }
    
    if resp.get("status") != "success":
        fail(resp.get("message", "CA lookup failed"))
    
    signed_key = resp.get("signed_public_key")
    
    if not signed_key:
        fail("No public key returned")
    
    # Verify CA signature
    verified = gpg.verify(signed_key)
    if not verified:
        fail("CA signature verification failed")
    
    import_result = gpg.import_keys(str(signed_key))
    if not import_result.fingerprints:
        fail("Failed to import contact key")
    
    fingerprint = import_result.fingerprints[0]
    
    # Store contact metadata
    contact_file = CONTACTS_DIR / f"{email_hash}.json"
    contact_file.write_text(json.dumps({
        "email_hash": email_hash,
        "fingerprint": fingerprint
    }, indent=2)

    print(json.dumps({
        "status": "success",
        "fingerprint": fingerprint
    }))
    
    
if __name__=="__main__":
    add_contact()
