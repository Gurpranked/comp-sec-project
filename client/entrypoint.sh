#!/bin/sh
set -e

echo "[INFO] Container starting (mTLS Architecture)..."

# ---------------------------------------------------------
# 1. Ensure required dirs exist
# ---------------------------------------------------------
# /data: stores client.key, client.crt, and contacts.json
# /data/received_files: stores incoming file transfers
mkdir -p /data/received_files

# ---------------------------------------------------------
# 2. Set Permissions
# ---------------------------------------------------------
echo "[INFO] Securing data directory..."
chmod 755 /data
chmod 700 /data/received_files

# ---------------------------------------------------------
# 3. Registration Logic
# ---------------------------------------------------------
if [ ! -f /data/client.crt ]; then
    echo "[INFO] No identity certificate found, running registration with CA..."
    
    # Ensure EMAIL and USERNAME env vars are passed to the container.
    # register.py will generate the CSR and save client.key / client.crt
    python3 /client_core/register.py
else
    echo "[INFO] Identity certificate found (skipping registration)"
fi

# ---------------------------------------------------------
# 4. Start the Application
# ---------------------------------------------------------
echo "[INFO] Starting mTLS peer-to-peer server..."

# Executing the unified listener
# This handles status checks and file transfers over TLS.
exec python3 /client_core/secure_server.py
