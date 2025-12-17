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
# This matches the VOLUME defined in your CA Dockerfile
TLS_VOLUME = "securedrop_tls_public" 

# ------------------------------------------------------
# Helpers
# ------------------------------------------------------

def sha256(content):
    return hashlib.sha256(content.encode()).hexdigest()

def volume_name_for_user(email_hash: str) -> str:
    return f"sd_data_{email_hash[:12]}"

def ensure_network():
    subprocess.run(["docker", "network", "create", NETWORK], 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def docker_exec(container_name, cmd):
    full_cmd = ["docker", "exec", container_name] + cmd
    return subprocess.run(full_cmd, capture_output=True, text=True)

def is_strong_password(password: str) -> bool:
    if len(password) < 8: return False
    return all([
        re.search(r"[A-Z]", password),
        re.search(r"[a-z]", password),
        re.search(r"\d", password),
        re.search(r"[!@#$%^&*()]", password)
    ])

# ------------------------------------------------------
# REPL session
# ------------------------------------------------------
class Session:
    def __init__(self):
        self.user = None
        self.container = None
        self.email = None
        ensure_network()
        self.users_db = self.load_db()

    def load_db(self):
        return json.loads(USER_DB.read_text()) if USER_DB.exists() else {}

    def save_db(self):
        USER_DB.write_text(json.dumps(self.users_db, indent=2))

    def prompt(self):
        return f"SecureDrop@{self.user if self.user else 'guest'}> "

    def run(self):
        while True:
            try:
                cmd = input(self.prompt()).strip().lower()
                if cmd == "exit":
                    if self.container: self.logout()
                    break
                if not cmd: continue

                if cmd == "register": self.register()
                elif cmd == "login": self.login()
                elif cmd == "logout": self.logout()
                elif cmd == "remove": self.remove_account()
                elif cmd == "add": self.add_contact()
                elif cmd == "list": self.list_contacts()
                elif cmd == "send": self.send_file()
                elif cmd == "help": self.help_message()
                else: print("Unknown command")
            except KeyboardInterrupt:
                if self.container:
                    self.logout()
                print("\nExiting.")
                break

    # --- Commands ---

    def register(self):
        username = input("Username: ").strip()
        email = input("Email: ").strip()
        email_hash = sha256(email)

        if email_hash in self.users_db:
            print("User already exists.")
            return

        password = getpass("Password: ")
        while not is_strong_password(password):
            print("Password too weak.")
            password = getpass("Password: ")

        container_name = f"sd_client_{email_hash[:12]}"
        # Safety Check: If container exists but user isn't in DB, wipe it
        check = subprocess.run(["docker", "ps", "-a", "-q", "-f", f"name={container_name}"], capture_output=True, text=True)
        if check.stdout.strip():
            print("[INFO] Cleaning up stale container from a previous failed session...")
            subprocess.run(["docker", "rm", "-f", container_name])

        user_vol = volume_name_for_user(email_hash)

        # 1. Ensure the persistent data volume exists for this specific user
        subprocess.run(["docker", "volume", "create", user_vol], 
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # 2. Start container with corrected argument list
        # Ensure every flag is its own string followed by its value string
        cmd = [
            "docker", "run", "-d",
            "--name", container_name,
            "-e", f"EMAIL={email}",
            "-e", f"USERNAME={username}",
            "-e", "CA_HOST=ca", 
            "--network", NETWORK,         # "securedrop-net"
            "--network-alias", container_name,
            "-v", f"{user_vol}:/data",
            "-v", f"{TLS_VOLUME}:/tls_public:ro",
            CLIENT_IMAGE                  # "client_template:latest"
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"[ERROR] Docker failed to start: {result.stderr}")
            return

        self.users_db[email_hash] = {
            "username": username,
            "container": container_name,
            "volume": user_vol
        }
        self.save_db()
        
        self.user, self.email, self.container = username, email, container_name
        print("Registration and identity generation successful.")


    def login(self):
        email = input("Email: ").strip()
        email_hash = sha256(email)
        
        if email_hash not in self.users_db:
            print("User not found.")
            return

        self.user = self.users_db[email_hash]['username']
        self.email = email
        self.container = self.users_db[email_hash]["container"]
        
        subprocess.run(["docker", "start", self.container])
        print(f"Logged in as {self.user}. Client listener started.")

    def logout(self):
        if self.container:
            subprocess.run(["docker", "stop", self.container])
            print(f"Logged out {self.user}.")
            self.user = self.email = self.container = None
        else:
            print("No active session.")

    def add_contact(self):
        if not self.container: return print("Login first.")
        target = input("Contact email: ").strip()
        
        res = docker_exec(self.container, ["python3", "/client_core/add_contact.py", target])
        print(res.stdout if res.returncode == 0 else res.stderr)

    def list_contacts(self):
        if not self.container: return print("Login first.")
        print("Checking contacts (Online & Reciprocity check)...")
        res = docker_exec(self.container, ["python3", "/client_core/list_contacts.py"])
        print(res.stdout)

    def send_file(self):
        if not self.container: return print("Login first.")
        target_email = input("Recipient Email: ").strip()
        file_path = input("Path to file (inside container /data): ").strip()
        
        target_hash = sha256(target_email)
        res = docker_exec(self.container, ["python3", "/client_core/send_file.py", target_hash, file_path])
        print(res.stdout)

    
    def remove_account(self):
        if not self.container: return print("Login first.")
        if input(f"Type 'yes' to delete {self.user}: ") != "yes": return
        
        email_hash = sha256(self.email)
        container_name = self.container
        volume_name = self.users_db[email_hash]["volume"]

        print(f"[CLEANUP] Deleting user session for {self.user}...")

        # 1. Remove the user credentials from the CA
        print("[INFO] Requesting CA to revoke identity...")
        res = docker_exec(self.container, ["python3", "/client_core/remove_from_ca.py"])
        
        if "Requesting removal for" not in res.stdout:
            print(f"[WARNING] CA did not acknowledge removal: {res.stdout}")
 
        # 2. Force Stop and Remove Container
        # The -f flag handles running containers and -v removes associated anonymous volumes
        subprocess.run(["docker", "rm", "-fv", container_name], capture_output=True)

        # 3. Explicitly Remove the Named Volume
        # This is critical so that a re-registration starts with a blank slate
        subprocess.run(["docker", "volume", "rm", "-f", volume_name], capture_output=True)

        # 4. Final Check: Ensure no 'ghost' container exists
        res = subprocess.run(["docker", "ps", "-a", "-q", "-f", f"name={container_name}"], 
                             capture_output=True, text=True)
        if res.stdout.strip():
            print("[ERROR] Docker failed to release the container name. Manual intervention required.")
            return

        # 4. Remove from Host JSON Database
        del self.users_db[email_hash]
        self.save_db()
        
        # 5. Clear session variables
        self.user = self.email = self.container = None
        self.logout()
        print(f"[SUCCESS] Account {email_hash[:12]} fully purged.") 


    def help_message(self):
        cmds = ["register", "login", "exit"] if not self.user else \
               ["add", "list", "send", "remove", "logout", "exit"]
        print(f"Available commands: {', '.join(cmds)}")

if __name__ == "__main__":
    Session().run()
