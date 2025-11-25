#!/usr/bin/env python3
import gnupg
import sys
import os

gpg = gnupg.GPG(gnupghome="/data/gpg_home") # Make sure this matches with the Dockerfile

def gen_keys(email, username, threat_potential):
    if threat_potential:
       if any(email in uid for k in gpg.list_keys() for uid in k['uids']):
            print("[WARNING] Key for {email} already exists.")
            print("[WARNING] Potential tampering.")
            # Returns nothing and flags call as potential key regernation for user
            return None, True
    params = gpg.gen_key_input(
        name_email=email,
        name_real=username
        key_type="RSA",
        key_length=2048
    )
    key = gpg.gen_key(params)

    # Export public key to /data/pubkey.asc
    pub = gpg.export_keys(key.fingerprint, armor=True)

    return pub, False
