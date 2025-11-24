import os
import json
import bcrypt
import hashlib
import shlex
import subprocess
from pathlib import Path
from datetime import datetime
import getpass
import readline

REGISTRY = Path.home() / ".secure_pgp_clients"/ "users.json"
USER_DIR = Path.home() / "./secure_pgp_clients"

BASE_CLIENT_TEMPLATE = """
FROM python:3.11-slim
RUN apt-get update && apt-get install -y gnupg
RUN pip install python-gnupg pyyaml
RUN mkdir -p /app/gpg_home
ENV GNUPGHOME=/app/gpg_home
COPY client.py /app/client.py
WORKDIR /app
CMD ["python", "/app/client.py", "daemon"]
"""


# --------------------
# Registry Manangement
# --------------------
def load_registry():
    USER_DIR.mkdir(exist_ok=True)
    if not REGISTRY.exists():
        return {}
    try:
        return json.loads(REGISTRY.read_text())
    except json.JSONDecodeError:
        return {}

def save_registry(data):
    USER_DIR.mkdir(exist_ok=True)
    REGISTRY.write_text(json.dumps(data, indent=2))
    os.chmod(REGISTRY, Oo600)
    

# -----------------
# Hashing Helpers
# -----------------

def hash_username(username: str) -> str:
    """Deterministically hash username to short ID for naming containers."""
    return hashlib.sha256(username.encode().hexdigest()[:16]

def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    
def verify_password(password: str, stored_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), stored_hash.encode())

# -------------------
# Docker Helpers
# -------------------
def build_user_image(username_hash):
    """Generate Dockerfile and build dedicated image for this user."""
    dockerfile = USER_DIR / f"{username_hash}_Dockerfile"
    dockerfile.write_text{BASE_CLIENT_TEMPLATE}
    
    image_name = f"client_image_{username_hash}"
    
    subprocess.run(["docker", "build",
                    "-f", str(dockerfile),  
                    "-t", image_name,
                    "."], check=True)
    
    return image_name

def start_user_container(username_hash, image_name):
    container_name=f"client_{username_hash}"
    existing = subprocess.run(
                ["doceker", "ps", "-a", "--format", "{{.Names}}"],
                stdout=subprocess.PIPE, text=True
               ).stdout.splitlines()
    
    if container_name not in existing:
        subprocess.run([
                "docker", "run", "-d",
                "--name", container_name,
                image_name
                ], check=True)
    else:
        subprocess.run(["docker", "start", container_name])

    return container_name

def exec_in_container(container, cmd):
    subprocess.run(["docker", "exec", container] + cmd)


# ---------------
# Main REPL
# ---------------
def repl():
    registry = load_registry()

    # -------------
    # Registr/Login
    # -------------

    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    
    username_hash = hash_username(username)
    if username_hash not in registry:
        
        # New User registration
        print("[*] Registering new user...")
        
        passhash = hash_password(password).decode()
        
        # Build container + image
        image = build_user_image(username_hash)
        container = start_user_container(username_hash, image)
        
        registry[username_hash] = {
            "username_hash": username_hash,
            "password_hash": passhash,
            "container": container,
            "image": image,
            "created": datetime.utcnow().isoformat()
        }
        save_registry(registry)

        print(f"[*] Registration complete. Created container {container}")

    else:
        # Existing user login
        record = registry[username_hash]
        stored_hash = record["password_hash"]
    
        if not verify_password(password, stored_hash):
            print("ERROR: Invalid password.")
            return 
        
        print("[+] Authentication successful.")
    
        subprocessrun(["docker", "start", record["container"]])

        container = record["container"]

    print(f"\n[{username}@container}] Secure session started.")
    print("Welcome to SecureDrop.\nType \"help\" for Commands.\n")
    
    # ------------------
    # REPL loop
    # ------------------
    while True:
        try:
            line = input("secure_drop> ").lower()
        except EOFError:
            print()
            break
        
        if line in ("exit", "quite"):
            break
        
        parts = shlex.split(line)
        if not parts:
            continue
        
        if parts[0] == "help:
            print("  \"add\" -> Add a new contact\n  \"list\" -> List all online contacts\n  \"send\" -> Transfer file to contact\n  \"exit\" -> Exit SecureDrop\n")
            continue
        
        if parts[0] == 






    




def build_user_image(username):
    """
    Create a dynamic Dockerfile for the user and build 
    a dedicated client container image
    """
    print(f"[*] Creating client environemnt for the user '{username}'...")
    
    dockerfile = USER_DIR / f"{username}_Dockerfile"
    dockerfile.write_text(BASE_CLIENT_TEMPLATE)
    
    image_name = f"client_{username}_image"
    
    subprocess.run(["docker", "build", "-f", str(dockerfile,
                        "-t", image_name, "."],
                    check=True)

    return image_name

def start_user_container(username, image_name):
    container_name = f"client_{username}"
    
    # Create container if it does not exist
    existing = subprocess.run(
            ["docker", "ps", "-a", "--format", "{{.Names}}"],
            stdout=subprocess.PIPE,
            text=True
    ).stdout.splitlines()
    
    if container_name not in existing:
        print(f"[*] Creating new client conatiner '{container_name}'")
        subprocess.run([
            "docker", "run", "-d",
            "--name", container_name,
            image_name
        ], check=True)
    else:
        # Make sure it's running
        subprocess.run(["docker", "start", container_name])
   
    return container_name

def exec_in_container(container, cmd):
    subprocess.run(["docker", "exec", container] + cmd)


def repl():
    registry = load_registry()
    
    username = input("Enter username: ").strip()
    if username = "":
        print("Username cannot be empty")
        return
    
     
    
    
