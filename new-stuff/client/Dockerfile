FROM python:3.12-slim

# ------------------------------------------------------
# Install required tools
# ------------------------------------------------------
RUN apt-get update && \
    apt-get install -y gnupg && \
    rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------
# Create working directory
# ------------------------------------------------------
RUN mkdir -p /client_core && chmod 755 /client_core
WORKDIR /client_core

# ------------------------------------------------------
# Copy client code
# ------------------------------------------------------
COPY client_core /client_core/

# ------------------------------------------------------
# Make gnupg home directory
# ------------------------------------------------------
RUN mkdir -p /data/gpg_home && chmod 755 /data/gpg_home 
RUN chmod 755 /data

# ------------------------------------------------------
# Install Python deps (if any)
# ------------------------------------------------------
RUN pip install --no-cache-dir python-gnupg

# ------------------------------------------------------
# The container sleeps indefinitely; all work is via docker exec
# ------------------------------------------------------
CMD ["sleep", "infinity"]

