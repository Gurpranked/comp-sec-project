#!/usr/bin/env python3
import gnupg
import sys

gpg = gnupg.GPG(gnupghome="/data/gpg_home")

if __name__ == "__main__":
    path = sys.argv[1]
    with open(path) as f:
        data = f.read()

    dec = gpg.decrypt(data)
    print(dec.data.decode())

