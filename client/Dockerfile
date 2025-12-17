FROM python:3.12-slim

# ------------------------------------------------------
# Install System Dependencies
# Only 'openssl' is kept for potential manual debugging
# ------------------------------------------------------
RUN apt-get update && \
    apt-get install -y --no-install-recommends openssl && \
    rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------
# Create working directory
# ------------------------------------------------------
WORKDIR /client_core

# ------------------------------------------------------
# Install Python deps
# 'cryptography' is the heavy lifter for CSRs and mTLS
# ------------------------------------------------------
RUN pip install --no-cache-dir cryptography pyyaml

# ------------------------------------------------------
# Copy client code
# Ensure all your new scripts (register.py, client_listener.py, 
# list_contacts.py, etc.) are in the client_core folder.
# ------------------------------------------------------
COPY client_core /client_core/

# ------------------------------------------------------
# Prepare persistent data mount point
# ------------------------------------------------------
RUN mkdir -p /data && chmod 755 /data

# ------------------------------------------------------
# Entrypoint Setup
# ------------------------------------------------------
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# ------------------------------------------------------
# Expose server port
# Match this to LISTEN_PORT in secure_server.py
# ------------------------------------------------------
EXPOSE 5001

# ------------------------------------------------------
# Runtime Setup
# ------------------------------------------------------
ENTRYPOINT ["/entrypoint.sh"]
