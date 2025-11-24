#!/usr/bin/env python3
import gnupg
import sys
import os

gpg = gnupg.GPG(gnupghome="/data/gpg_home")

if __name__ == "__main__":
    username = sys.argv[1]
    key_path = f"/data/pubkeys/{username}.asc"

    if not os.path.exists(key_path):
        print("Key not found:", key_path)
        sys.exit(1)

    with open(key_path) as f:
        armored = f.read()

    gpg.import_keys(armored)
    print(f"Imported key for {username}")

