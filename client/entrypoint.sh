#!/bin/sh
set -e

echo "[INFO] Container starting (mTLS Architecture)..."

# 1. Ensure required dirs exist
mkdir -p /data
mkdir -p /user_files
mkdir -p /saved_files

# 2. Set Permissions
echo "[INFO] Securing directories..."
chmod 755 /user_files
chmod 700 /saved_files  # More restrictive for downloaded files

# 3. Registration Logic
if [ ! -f /data/client.crt ]; then
    echo "[INFO] No identity certificate found, running registration..."
    python3 /client_core/register.py
else
    echo "[INFO] Identity certificate found."
fi

echo "[INFO] Starting mTLS peer-to-peer server..."
exec python3 /client_core/secure_server.py
