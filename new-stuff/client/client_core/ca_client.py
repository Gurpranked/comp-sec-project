#!/usr/bin/env python3
import socket
import ssl
import json
import sys

CA_HOST = "ca"          # docker-compose service DNS name
CA_PORT = 4444

def ca_req(payload):
    context = ssl.create_default_context()
    context.check_hostname = True 
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((CA_HOST, CA_PORT)) as sock:
            with context.wrap_socket(sock, server_hostname=CA_HOST) as ssock:
                ssock.sendall(json.dumps(payload).encode())
                resp = ssock.recv(65535).decode()
    except Exception as e:
        resp = json.dumps({"status": "error", "message": str(e)})

    return resp
