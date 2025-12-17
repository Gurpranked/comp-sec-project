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

USERS_DIR = BASE_DIR / "users"
USERS_DIR.mkdir(exist_ok=True)
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

    def _get_user_path(self, email_hash):
        return USERS_DIR / f"{email_hash}.json"
    
    def get_user_data(self, email_hash):
        """Fetches data for a specific user only when needed."""
        path = self._get_user_path(email_hash)
        if path.exists():
            return json.loads(path.read_text())
        return None

    def save_user_data(self, email_hash, data):
        """Saves only this specific user's data to their own file."""
        path = self._get_user_path(email_hash)
        path.write_text(json.dumps(data, indent=2))

    def prompt(self):
        return f"SecureDrop@{self.user if self.user else 'guest'}> "

    def delete_user_data(self, email_hash):
        """Deletes the specific file for this user."""
        path = self._get_user_path(email_hash)
        if path.exists():
            path.unlink()
    
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

        if self.get_user_data(email_hash):
            print("User already exists.")
            return

        while True:
            password = getpass("Password: ")
            
            if not is_strong_password(password):
                print("Password too weak. Ensure it meets security requirements.")
                print("Password must contain a number, special character, and capital + lowercase leters") 
                continue
                
            confirm_password = getpass("Confirm Password: ")
            
            if password != confirm_password:
                print("Passwords do not match. Please try again.")
                continue
            
            # If we reach here, password is valid and confirmed
            break

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

        user_data = {
            "username": username,
            "container": container_name,
            "password_hash": sha256(password),
            "volume": user_vol
        }
        self.save_user_data(email_hash, user_data)
        
        self.user, self.email, self.container = username, email, container_name
        print("Registration and identity generation successful.")


    def login(self):
        email = input("Email: ").strip()
        email_hash = sha256(email)
        
        user_data = self.get_user_data(email_hash) 
        if not user_data:
            print("User not found.")
            return
        
        password = getpass("Password: ")
        if sha256(password) != user_data["password_hash"]:
            print("Incorrect password")
            return 
         
         
        self.user = user_data['username']
        self.email = email
        self.container = user_data["container"]
        
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
        if target == self.email:
            print("[ERROR] You're attempting to add yourself as a contact.")
            return
        res = docker_exec(self.container, ["python3", "/client_core/add_contact.py", target])
        print(res.stdout if res.returncode == 0 else res.stderr)

    def list_contacts(self):
        if not self.container: return print("Login first.")
        print("Checking contacts (Online & Reciprocity check)...")
        res = docker_exec(self.container, ["python3", "/client_core/list_contacts.py"])
        if res.stderr:
            print(res.stderr)
        print(res.stdout)

    def send_file(self):
        if not self.container: return print("Login first.")
        target_email = input("Recipient Email: ").strip()
        file_path = input("Path to file (inside container /user_files): ").strip()
        
        target_hash = sha256(target_email)
        res = docker_exec(self.container, ["python3", "/client_core/send_file.py", target_hash, file_path])
        print(res.stdout)

    
    def remove_account(self):
        if not self.container: return print("Login first.")
        if input(f"Type 'yes' to delete {self.user}: ") != "yes": return
        
        email_hash = sha256(self.email)
        container_name = self.container
        user_data = self.get_user_data(email_hash)
        volume_name = user_data["volume"]

        print(f"[CLEANUP] Deleting user session for {self.user}...")

        # 1. Remove the user credentials from the CA
        print("[INFO] Requesting CA to revoke identity...")
        res = docker_exec(self.container, ["python3", "/client_core/remove_from_ca.py"])
        
        if "Requesting removal for" not in res.stdout:
            print(f"[WARNING] CA did not acknowledge removal: {res.stdout}")
 
        # 2. Force Stop and Remove Container
        # The -f flag handles running containers and -v removes associated anonymous volumes
        subprocess.run(["docker", "rm", "-fv", self.container], capture_output=True)

        # 3. Explicitly Remove the Named Volume
        # This is critical so that a re-registration starts with a blank slate
        subprocess.run(["docker", "volume", "rm", "-f", user_data["volume"]], capture_output=True)

        # 4. Final Check: Ensure no 'ghost' container exists
        res = subprocess.run(["docker", "ps", "-a", "-q", "-f", f"name={container_name}"], 
                             capture_output=True, text=True)
        if res.stdout.strip():
            print("[ERROR] Docker failed to release the container name. Manual intervention required.")
            return

        # 4. Remove JSON file
        self.delete_user_data(email_hash)
        
        # 5. Clear session variables
        self.user = self.email = self.container = None
        print(f"[SUCCESS] Account {email_hash[:12]} fully purged.") 


    def help_message(self):
        if not self.user:
            cmds = """
   "register" -> Register a new user
   "login"    -> Login with an existing account 
   "exit"     -> Exit SecureDrop 
                   """
        else:
            cmds = """
   "add"      -> Add a new contact 
   "list"     -> List all online contacts 
   "send"     -> Send a file to contacts 
   "logout"   -> Logout from SecureDrop
   "exit"     -> Exit SecureDrop 
                   """
        print(cmds)
if __name__ == "__main__":
    print("Welcome to SecureDrop")
    print("Type 'help' for commands")
    Session().run()
