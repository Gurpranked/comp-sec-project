FROM python:3.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends openssl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /client_core
RUN pip install --no-cache-dir cryptography pyyaml

# Create the new directories
RUN mkdir -p /data /user_files /saved_files && \
    chmod 755 /data /user_files /saved_files

COPY client_core /client_core/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 5001
ENTRYPOINT ["/entrypoint.sh"]
