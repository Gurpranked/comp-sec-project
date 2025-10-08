# Copyright 2025
# Author: Gurpreet Singh

from base64 import b64encode
from os import urandom
from getpass import getpass
from bcolors import bcolors
from hash import hash
import hashlib
import yaml

# Currently unused
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
    
    salt = urandom(16)
    hashed_email = hash(email)
    hashed_name = hash(full_name)
    hashed_pwd = hash(pwd, salt)
     
    # Something something user registered
    data = {
        hashed_email: {
            'name': hashed_name,
            'pwd': hashed_pwd,
            'salt': f'{salt}',
        }
    }

    with open(creds_filename, 'w+') as file:
        yaml.dump(data, file)

    print("User Registered.")
