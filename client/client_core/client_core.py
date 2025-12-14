import os
import hashlib
import json
import getpass
import subprocess
from pathlib import Path

# ---------------------------
# Config
# ---------------------------
REPL_DB = Path.home() / ".pgp_repl_users.json"
CLIENTS_BASE_DIR = Path.home() / "pgp_clients"
CLIENT_IMAGE = "client_template:latest"  # change to your actual client image

# ---------------------------
# Helpers
# ---------------------------
def hash_string(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def load_users():
    if REPL_DB.exists():
        with open(REPL_DB, "r") as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(REPL_DB, "w") as f:
        json.dump(users, f, indent=2)

def get_user_volume(username_hash):
    CLIENTS_BASE_DIR.mkdir(parents=True, exist_ok=True)
    user_dir = CLIENTS_BASE_DIR / username_hash
    user_dir.mkdir(exist_ok=True)
    return str(user_dir.resolve())

def run_docker_container(username_hash, volume_path):
    container_name = f"client_{username_hash}"

    # Check if container exists
    result = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}"],
                            capture_output=True, text=True)
    if container_name not in result.stdout:
        # Create container
        subprocess.run([
            "docker", "run", "-d",
            "--name", container_name,
            "-v", f"{volume_path}:/data",
            CLIENT_IMAGE,
            "sleep", "infinity"
        ], check=True)
    else:
        # Start container if stopped
        subprocess.run(["docker", "start", container_name], check=True)
    return container_name

def docker_exec(container_name, cmd):
    full_cmd = ["docker", "exec", container_name] + cmd
    result = subprocess.run(full_cmd, capture_output=True, text=True)
    return result.stdout, result.stderr

# ---------------------------
# User Management
# ---------------------------
def register():
    users = load_users()
    username = input("Choose username: ").strip()
    if username in users:
        print("Username already exists.")
        return

    password = getpass.getpass("Choose password: ").strip()
    password_hash = hash_string(password)
    username_hash = hash_string(username)

    users[username] = {
        "password_hash": password_hash,
        "container_hash": username_hash,
        "contacts": []
    }
    save_users(users)

    volume_path = get_user_volume(username_hash)
    container_name = run_docker_container(username_hash, volume_path)
    print(f"User '{username}' registered. Container '{container_name}' ready at {volume_path}")

def login():
    users = load_users()
    username = input("Username: ").strip()
    if username not in users:
        print("User not found.")
        return None, None

    password = getpass.getpass("Password: ").strip()
    password_hash = hash_string(password)
    if password_hash != users[username]["password_hash"]:
        print("Incorrect password.")
        return None, None

    username_hash = users[username]["container_hash"]
    volume_path = get_user_volume(username_hash)
    container_name = run_docker_container(username_hash, volume_path)
    print(f"Logged in as '{username}'. Container '{container_name}' ready.")
    return username, container_name

# ---------------------------
# User Commands
# ---------------------------
def add_contact(username):
    users = load_users()
    contact = input("Enter contact username to add: ").strip()
    if contact not in users:
        print("Contact does not exist.")
        return
    if contact in users[username]["contacts"]:
        print("Contact already added.")
        return
    users[username]["contacts"].append(contact)
    save_users(users)
    print(f"Added contact '{contact}'.")

def list_contacts(username):
    users = load_users()
    contacts = users[username]["contacts"]
    if not contacts:
        print("No contacts added.")
        return
    print("Contacts:")
    for c in contacts:
        print(" -", c)

def send_message(username, container_name):
    recipient = input("Enter recipient username: ").strip()
    message = input("Enter message: ").strip()
    # Placeholder: in practice you'd encrypt the message with recipient's PGP key
    stdout, stderr = docker_exec(container_name, ["echo", f"Sending message to {recipient}: {message}"])
    print(stdout)

# ---------------------------
# REPL
# ---------------------------
def repl():
    session = {"username": None, "container_name": None}

    while True:
        prompt = f"{session['username']}> " if session["username"] else "> "
        cmd = input(prompt).strip()

        if cmd == "exit":
            break
        elif cmd == "register":
            register()
        elif cmd == "login":
            username, container_name = login()
            if username:
                session["username"] = username
                session["container_name"] = container_name
        elif cmd == "add":
            if not session["username"]:
                print("Login required.")
                continue
            add_contact(session["username"])
        elif cmd == "list":
            if not session["username"]:
                print("Login required.")
                continue
            list_contacts(session["username"])
        elif cmd == "send":
            if not session["username"]:
                print("Login required.")
                continue
            send_message(session["username"], session["container_name"])
        elif cmd.startswith("exec"):
            if not session["container_name"]:
                print("Login required.")
                continue
            parts = cmd.split()[1:]
            stdout, stderr = docker_exec(session["container_name"], parts)
            if stdout:
                print(stdout)
            if stderr:
                print(stderr)
        else:
            if session["username"]:
                print("Available commands: add, list, send, exec <cmd>, exit")
            else:
                print("Available commands: register, login, exit")

# ---------------------------
# Entry point
# ---------------------------
if __name__ == "__main__":
    repl()

