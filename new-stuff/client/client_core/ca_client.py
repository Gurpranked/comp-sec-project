#!/usr/bin/env python3
import socket
import ssl
import json
import sys

CA_HOST = "ca"          # docker-compose service DNS name
CA_PORT = 4444

def main():
    if len(sys.argv) != 2:
        print(json.dumps({"status": "error", "message": "Missing payload"}))
        return

    payload = json.loads(sys.argv[1])

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((CA_HOST, CA_PORT)) as sock:
            with context.wrap_socket(sock, server_hostname="PGP_CA") as ssock:
                ssock.sendall(json.dumps(payload).encode())
                resp = ssock.recv(65535).decode()
                print(resp)
    except Exception as e:
        print(json.dumps({"status": "error", "message": str(e)}))

if __name__ == "__main__":
    main()

