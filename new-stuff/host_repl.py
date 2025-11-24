#!/usr/bin/env python3
import hashlib
import json
import os
import shutil
import sys
from getpass import getpass
from pathlib import Path
import subprocess

# ------------------------------------------------------
# Paths & configs
# ------------------------------------------------------
HOME = Path.home()
BASE_DIR = HOME / "pgp_clients"
BASE_DIR.mkdir(exist_ok=True)
USER_DB_PATH = BASE_DIR / "users.json"
CLIENT_IMAGE = "client_template:latest"

VERBOSE=True

# ------------------------------------------------------
# Helpers
# ------------------------------------------------------

def load_users():
    if USER_DB_PATH.exists():
        return json.loads(USER_DB_PATH.read_text())
    return {}

def save_users(users):
    USER_DB_PATH.write_text(json.dumps(users, indent=2))

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def hash_username(username):
    return hashlib.sha256(username.encode()).hexdigest()[:16]

def docker_exec(container_name, cmd):
    """Run command inside container and return stdout, stderr"""
    full_cmd = ["docker", "exec", container_name] + cmd
    result = subprocess.run(full_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout, result.stderr
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
        "new-stuff_pgpgnet"
    ], stdout=subprocess.DEVNULL, stder=subprocess.DEVNULL)

def start_client_container(container_name, volume_path):
    """Create and start client container for user"""
    if not container_exists(container_name):
        subprocess.run([
            "docker", "run", "-d",
            "--name", container_name,
            "-v", f"{volume_path}:/client_data",
            "--network", "new-stuff_pgpnet",   # make sure network matches docker-compose
            CLIENT_IMAGE,
            "sleep", "infinity"
        ])
    else:
        subprocess.run(["docker", "start", container_name])

# ------------------------------------------------------
# CA communication through container
# ------------------------------------------------------
def ca_request_via_container(container_name, payload):
    """Send request to CA through the client's container"""
    payload_json = json.dumps(payload)
    cmd = ["python3", "/client_core/ca_client.py", payload_json]
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
        self.users_db = load_users()

    def prompt(self):
        return f"pgp@{self.user if self.user else 'guest'}> "

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
        if username in self.users_db:
            print("User exists.")
            return
        password = getpass("Password: ")

        # Create container data path
        username_hash = hash_username(username)
        user_dir = BASE_DIR / username_hash
        user_dir.mkdir(parents=True, exist_ok=True)
        (user_dir / "data").mkdir(exist_ok=True)
        (user_dir / "pubkeys").mkdir(exist_ok=True)
        (user_dir / "messages").mkdir(exist_ok=True)

        container_name = f"client_{username_hash}"
        start_client_container(container_name, user_dir)

        # Generate keys inside container
        out, err = docker_exec(container_name, ["python3", "/client_core/gen_keys.py", email, username])
        print(out)

        # Read public key from container
        out, err = docker_exec(container_name, ["cat", "/data/pubkey.asc"])
        public_key = out.strip()

        print(f"[LOGGING]: Public Key: {public_key}")        
        print(f"[LOGGING]: {err}")

        # Register key with CA via container
        resp = ca_request_via_container(container_name, {
            "command": "register",
            "username": username,
            "public_key": public_key
        })

        if resp.get("status") != "success":
            print("Registration failed:", resp.get("message"))
            return

        # Store signed key in container
        signed_key = resp["public_key"]
        docker_exec(container_name, [
            "bash", "-c",
            f"echo '{signed_key}' > /client_data/data/signed_pubkey.asc"
        ])

        # Update host DB
        self.users_db[username] = {
            "password_hash": hash_password(password),
            "container_hash": username_hash,
            "contacts": []
        }
        save_users(self.users_db)
        print("Registration successful.")

    def login(self):
        username = input("Username: ").strip()
        if username not in self.users_db:
            print("User not found.")
            return
        password = getpass("Password: ")
        if hash_password(password) != self.users_db[username]["password_hash"]:
            print("Incorrect password.")
            return

        self.user = username
        self.container = f"client_{self.users_db[username]['container_hash']}"
        start_client_container(self.container, BASE_DIR / self.users_db[username]['container_hash'])
        print(f"Login successful. Authenticated as {self.user}")

    def logout(self):
        if self.user:
            print(f"Logging out {self.user}")
        self.user = None
        self.container = None

    def remove_account(self):
        if not self.user:
            print("Not logged in.")
            return
        confirm = input(f"Are you sure you want to delete your account '{self.user}'? (yes/no) ")
        if confirm != "yes":
            print("Aborted.")
            return

        # Remove from CA
        resp = ca_request_via_container(self.container, {"command": "remove_user", "username": self.user})
        if resp.get("status") != "success":
            print("Failed to remove from CA:", resp.get("message"))
            return

        # Stop & remove container
        subprocess.run(["docker", "rm", "-f", self.container])

        # Remove user data
        user_dir = BASE_DIR / self.users_db[self.user]["container_hash"]
        if user_dir.exists():
            shutil.rmtree(user_dir)

        # Remove from DB
        self.users_db.pop(self.user)
        save_users(self.users_db)

        print(f"Account '{self.user}' removed successfully.")
        self.user = None
        self.container = None

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
    print("Welcome to PGP REPL. Type 'register', 'login', 'exit'...")
    repl.run()
