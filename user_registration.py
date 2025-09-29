# Copyright 2025
# Author: Gurpreet Singh
from getpass import getpass
from bcolors import bcolors
import hashlib
import yaml
import os

PEPPER = "somegoodpeppa"

def user_registration(creds_filename: str):
    full_name = input(f"{bcolors.BOLD}Enter Full Name: {bcolors.ENDC}")
    email = input(f"{bcolors.BOLD}Enter Email Address: {bcolors.ENDC}")
    pwd = ""
    pwd1 = "1"
    while not (pwd == pwd1):
        pwd = getpass(f"{bcolors.BOLD}Enter Password: {bcolors.ENDC}") 
        pwd1 = getpass(f"{bcolors.BOLD}Re-enter Password: {bcolors.ENDC}")
        if not (pwd == pwd1):
            print(f"{bcolors.FAIL}Passwords don't match, try again{bcolors.ENDC}")
     
    print(f"\n{bcolors.OKGREEN}Passwords match.{bcolors.ENDC}")    

    # Hashing the password
    pwd_hash = create_secure_pwd(pwd)
    salt, key = pwd_hash[:16], pwd_hash[16:]
    hash_algo = "sha256"
    iterations = 100_000
    # Something something user registered
    data = {
        f'{email}': {
            'name': f'{full_name}',
            'pwd_hash': f'{key}',
            'salt': f'{salt}',
            'hash_algo': f'{hash_algo}',
        }
    }

    with open(creds_filename, 'w+') as file:
        yaml.dump(data, file)

    print("User Registered.")

def create_secure_pwd(pwd):
    salt = os.urandom(16)
    pwd_salt = b'pwd' + salt
    pwd_hash = hashlib.sha256(pwd_salt)
    return pwd_hash.hexdigest()
