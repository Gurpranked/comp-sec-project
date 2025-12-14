#!/usr/bin/env python3
import hashlib
import json
import os
import sys
import re
import subprocess
from getpass import getpass
from pathlib import Path

# ------------------------------------------------------
# Paths & configs
# ------------------------------------------------------
BASE_DIR = Path.home() / "securedrop_clients"
BASE_DIR.mkdir(exist_ok=True)


USER_DB = BASE_DIR / "users.json"
CLIENT_IMAGE = "client_template:latest"
NETWORK = "securedrop-net"

# ------------------------------------------------------
# Helpers
# ------------------------------------------------------

def is_strong_password(password: str) -> bool:
    """
    Check whether a password meets basic strength requirements.
    
    Requirements:
    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least one special character
    """
    if len(password) < 8:
        return False

    # Requirements using regex
    has_upper = re.search(r"[A-Z]", password)
    has_lower = re.search(r"[a-z]", password)
    has_digit = re.search(r"\d", password)
    has_special = re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)

    return all([has_upper, has_lower, has_digit, has_special])


def load_db():
    return json.loads(USER_DB_PATH.read_text()) if USER_DB.exists() else {}

def save_db(users):
    USER_DB.write_text(json.dumps(users, indent=2))

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def hash_content(message):
    return hashlib.sha256(message.encode()).hexdigest()[:16]

def docker_exec(container_name, cmd):
    """Run command inside container and return stdout, stderr"""
    full_cmd = ["docker", "exec", container_name] + cmd
    result = subprocess.run(full_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout, result.stderr

def docker(cmd):
    return subprocess.run(cmd, check=False)

def container_exists(name: str) -> bool:
    """Check if a container with the exact name exists"""
    result = subprocess.run(
        ["docker", "ps", "-a", "--filter", f"name=^{name}$", "-q"],
        capture_output=True,
        text=True
    )
    return bool(result.stdout.strip())

def ensure_network():
    subproces.run([ 
        "docker", "network", "create",
        "--driver", "bridge",
        "--attachable",
        "securedrop-net"
    ], stdout=subprocess.DEVNULL, stder=subprocess.DEVNULL)

def create_client_container(container_name, email, username, password_hash):
    subprocess.run([
        "docker", "run", "-d",
        "--name", container_name,
        "-e", f"EMAIL={email}", 
        "-e", f"USERNAME={username}",
        "-e", f"PASSWORD_HASH={password_hash}",
        "--network", "securedrop-net", # make sure network matches docker-compose
        "-v", f"{CA_CERT}:/tls/ca-cert.pem:ro",
        CLIENT_IMAGE,
    ])

def start_client_container(container_name):
    subprocess.run(["docker", "start", container_name])

def stop_client_container(container_name):  
    if not container_exists(container_name):
        print(f"Container: '{container_name}' does not exist.") 
        print("Doing nothing")
    else:
        subprocess.run(["docker", "stop", container_name])

    
# ------------------------------------------------------
# CA communication through container
# ------------------------------------------------------
def ca_request_via_container(container_name, payload):
    """Send request to CA through the client's container"""
    payload_json = json.dumps(payload)
    cmd = ["python3", "ca_client.py", payload_json]
    out, err = docker_exec(container_name, cmd)
    if err.strip():
        return {"status": "error", "message": err.strip()}
    try:
        return json.loads(out)
    except Exception:
        return {"status": "error", "message": "Invalid CA response"}

# ------------------------------------------------------
# REPL session
# ------------------------------------------------------
class Session:
    def __init__(self):
        self.user = None
        self.container = None
        self.email = None
        self.users_db = load_users()

    def prompt(self):
        return f"SecureDrop@{self.user if self.user else 'guest'}> "

    def run(self):
        while True:
            try:
                cmd = input(self.prompt()).strip()
                if cmd == "exit":
                    # Logout first 
                    if self.user and self.container:
                        self.logout()
                    break
                if not cmd:
                    continue

                if cmd.startswith("register"):
                    self.register()
                elif cmd.startswith("login"):
                    self.login()
                elif cmd.startswith("logout"):
                    self.logout()
                elif cmd.startswith("remove"):
                    self.remove_account()
                elif cmd.startswith("add"):
                    self.add_contact()
                elif cmd.startswith("list"):
                    self.list_contacts()
                elif cmd.startswith("send"):
                    self.send_message()
                elif cmd.startswith("help"):
                    self.help_message()
                else:
                    print("Unknown command")
            except KeyboardInterrupt:
                print("\nExiting REPL.")
                break

    # --------------------------------------------------
    # Commands
    # --------------------------------------------------
    def register(self):
        username = input("New username: ").strip()
        email = input("New email: ").strip()
        email_hash = sha256(email)
       
        # Check local db
        if email_hash in self.users_db:
            print("User exists.")
            return

        print("""
    Password Requirements:
        - At least 8 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one number
        - At least one special character
             """) 
        password = getpass("Password: ")
        confirm = getpass("Confirm Password: ")
        while password != confirm or not is_strong_password(password):
            print("Passwords do not match")
            print("Try again")
            print("""
    Password Requirements:
        - At least 8 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one number
        - At least one special character
             """) 
            password = getpass("Password: ")
            confirm = getpass("Confirm Password: ")

        password_hash = sha256(password) 
        username_hash = sha256(username)
        container_name = f"client_{email_hash[:12]}"
        create_client_container(container_name, email, username, password_hash)

        # Update host db
        self.users_db[email_hash] = {
            "username": username,
            "password_hash": password_hash,
            "container": container_name
        }
        save_users(self.users_db)

        self.user = username
        self.email = email
        self.password = password_hash
        self.container = container_name
        print("Registration successful.")

    def login(self):
        email = input("Email: ").strip()
        email_hash = sha256(email)
        
        if email_hash not in self.users_db:
            print("User not found.")
            return

        password = getpass("Password: ")
        password_hash = hash_content(password)
        if self.users_db[email_hash]['password_hash'] != password_hash:
            print("Incorrect credentials.")
            return

        self.user = self.users_db[email_hash]['username']
        self.email = email
        self.container = self.users_db[email_hash]["container"]
        start_client_container(self.container)
        print(f"Login successful. Authenticated as {self.user}")

    def logout(self):
        if self.user:
            print(f"Logging out {self.user}")
            if not self.container:
                return
            stop_client_container(self.container)
            self.user = None
            self.email = None
            self.container = None
        else:
            print("Login first.")

# TODO
    def remove_account(self):
        if not self.user:
            print("Login first.")
            return
        confirm = input(f"Are you sure you want to delete your account '{self.user}'? (yes/no) ")
        if confirm != "yes":
            print("Aborted.")
            return

        # Remove from CA
        docker([
            "docker", "exec", self.container,
            "python3", "/client_core/remove_from_ca.py"
        ])
    
        # Stop & remove container
        subprocess.run(["docker", "rm", "-f", self.container])

        # Remove from DB
        self.users_db.pop(self.user)
        save_users(self.users_db)

        self.logout()
        print(f"Account '{self.user}' removed successfully.")

    def add_contact(self):
        if not self.user:
            print("Login first.")
            return
        target = input("Contact username: ").strip()
        if target not in self.users_db:
            print("User not found.")
            return
        if target in self.users_db[self.user]["contacts"]:
            print("Already in contacts.")
            return
        self.users_db[self.user]["contacts"].append(target)
        save_users(self.users_db)
        print(f"Added {target} to contacts.")

    def list_contacts(self):
        if not self.user:
            print("Login first.")
            return
        contacts = self.users_db[self.user]["contacts"]
        # Remove deleted accounts
        contacts = [c for c in contacts if c in self.users_db]
        self.users_db[self.user]["contacts"] = contacts
        save_users(self.users_db)
        print("Contacts:", ", ".join(contacts) if contacts else "No contacts")

    def send_message(self):
        if not self.user:
            print("Login first.")
            return
        target = input("Send to (username): ").strip()
        if target not in self.users_db[self.user]["contacts"]:
            print("Target not in contacts.")
            return
        message = input("Message: ").strip()
        # Send message via client container
        target_container = f"client_{self.users_db[target]['container_hash']}"
        docker_exec(self.container, ["python3", "/client_core/send_message.py", target, message])
        print("Message sent.")

    def help_message(self):
        if not self.user or not self.container:
            print("Usage: register, login, exit")
        else:
            print("Usage: commands: register, login, logout, remove, add, list, send, help, exit")
             

# ------------------------------------------------------
# Main
# ------------------------------------------------------
if __name__ == "__main__":
    repl = Session()
    print("Welcome to SecureDrop. Type 'register', 'login', 'exit'...")
    repl.run()
