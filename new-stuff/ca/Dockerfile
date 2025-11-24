FROM python:3.12-slim

# ------------------------------------------------------
# Install required system packages
# ------------------------------------------------------
RUN apt-get update && \
    apt-get install -y \
       gnupg \
       openssl \
       ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------
# Create app directory
# ------------------------------------------------------
RUN mkdir -p /app && chmod 755 /app
WORKDIR /app

# ------------------------------------------------------
# Copy CA server code
# ------------------------------------------------------
COPY ca_server.py /app/ca_server.py

# ------------------------------------------------------
# Create GPG home for CA root keypair
# ------------------------------------------------------
RUN mkdir -p /app/gpg_home && chmod 700 /app/gpg_home

# ------------------------------------------------------
# Create database directory
# ------------------------------------------------------
RUN mkdir -p /app/db && chmod 755 /app/db

# ------------------------------------------------------
# Generate self-signed TLS certificate for the CA 
# ------------------------------------------------------
RUN openssl req -x509 -newkey rsa:4096 \
    -keyout /app/ca.key \
    -out /app/ca.crt \
    -days 3650 -nodes \
    -subj "/CN=PGP_CA" && \
    chmod 600 /app/ca.key /app/ca.crt

# ------------------------------------------------------
# Install Python dependencies
# ------------------------------------------------------
RUN pip install --no-cache-dir python-gnupg pyyaml

# ------------------------------------------------------
# Expose CA port (TLS)
# ------------------------------------------------------
EXPOSE 4444

# ------------------------------------------------------
# Start CA server
# ------------------------------------------------------
CMD ["python", "/app/ca_server.py"]

