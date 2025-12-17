FROM python:3.12-slim

# 1. Install OpenSSL for certificate generation
RUN apt-get update && \
    apt-get install -y --no-install-recommends openssl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 2. Install Python dependencies (Cryptography is essential here)
RUN pip install --no-cache-dir cryptography pyyaml

# 3. Create necessary directories
RUN mkdir -p /app/db /tls_public && \
    chmod 755 /app/db /tls_public

# 4. Generate CA Root credentials
# This creates the "Master" identity that signs everyone else.
RUN openssl req -x509 -newkey rsa:4096 \
    -keyout /app/ca.key \
    -out /app/ca.crt \
    -days 3650 -nodes \
    -subj "/CN=ca" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,digitalSignature,keyCertSign,cRLSign" && \
    chmod 600 /app/ca.key /app/ca.crt && \
    cp /app/ca.crt /tls_public/ca-cert.pem && \
    chmod 444 /tls_public/ca-cert.pem


# 5. Copy the actual CA server code
COPY ca_server.py /app/ca_server.py

# 6. Expose the CA listener port
EXPOSE 4444

# 7. Define the volume for clients to mount
# When clients start, they use: -v securedrop_tls_public:/tls_public:ro
VOLUME /tls_public

CMD ["python", "/app/ca_server.py"]
