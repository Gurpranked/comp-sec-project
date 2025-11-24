#!/usr/bin/env python3
import gnupg
import sys
import os
from datetime import datetime

gpg = gnupg.GPG(gnupghome="/data/gpg_home")

if __name__ == "__main__":
    recipient = sys.argv[1]
    message = sys.argv[2]

    pubkey_path = f"/data/pubkeys/{recipient}.asc"
    if not os.path.exists(pubkey_path):
        print("Recipient key missing. Cannot encrypt.")
        sys.exit(1)

    # Encrypt
    encrypted = gpg.encrypt(message, recipients=[recipient])
    if not encrypted.ok:
        print("Encryption failed:", encrypted.status)
        sys.exit(1)

    # Store in history
    out_dir = "/data/messages"
    os.makedirs(out_dir, exist_ok=True)

    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    msg_path = f"{out_dir}/to_{recipient}_{ts}.asc"

    with open(msg_path, "w") as f:
        f.write(str(encrypted))

    print(f"Encrypted message stored at {msg_path}")

