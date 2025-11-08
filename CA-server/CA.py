# Copyright 2025
# Author: Gurpreet Singh

from bcolors import bcolors
from cryptography import
import yaml
import hashlib
import socket
import argparse

# A seperate process that listens on a unix socket for requests
# Generates and stores certs into a DB
# Has it's own private and public key



def start_receiver(port: int):
    # Handle incoming requests to CA server

    # Main listener for incoming connections
    def server():
       with socket.socket() as s:
        s.bind(('', port))          # Listen at the set port


if __name__=="__main__":
    parser = argparse.ArgumentParser("SecureDrop CA Server")
    parser.add_argument('-p', '--port', type=int, nargs='?'

