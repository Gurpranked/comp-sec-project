#!/usr/bin/env python3
import socket
import ssl
import json
import sys

CA_HOST = "ca"          # docker-compose service DNS name
CA_PORT = 4444


def send_msg(sock, obj):
    data = json.dumps(obj).encode()
    length = struct.pack("!I", len(data))
    sock.sendall(length + data)

def recv_msg(sock):
    header = recv_exact(sock, 4)
    length = struct.unpack("!I", header)[0]
    body = recv_exact(sock, length)
    return  json.loads(body.decode())

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed")
        buf += chunk
    return buf

class CAClient:
    def __init__(self, cafile="/tls/ca-cert.pem"):
        context = ssl.create_default_context(cafile=cafile)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        
        raw_sock = socket.create_connection((CA_HOST, CA_PORT), timeout=10)
        self.sock = context.wrap_socket(raw_sock, server_hostname=CA_HOST)
    
    def request(self, payload):
        send_msg(self.sock, payload)
        return recv_msg(self.sock)
    
    def close(self):
        self.sock.close()

