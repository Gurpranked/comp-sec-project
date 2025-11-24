#!/usr/bin/env python3
import gnupg
import sys
import os

gpg = gnupg.GPG(gnupghome="/data/gpg_home") # Make sure this matches with the Dockerfile

if __name__ == "__main__":
    email = sys.argv[1]
    username = sys.argv[2]

    params = gpg.gen_key_input(
        name_email=email,
        name_real=username
        key_type="RSA",
        key_length=2048
    )
    key = gpg.gen_key(params)

    # Export public key to /data/pubkey.asc
    pub = gpg.export_keys(key.fingerprint)
    with open("/data/pubkey.asc", "w") as f:
        f.write(pub)

    print("Generated keys for:", user)

