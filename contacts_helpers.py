# Copyright 2025
# Author: Gurpreet Singh

import yaml
from cryptography.fernet import Fernet
from os.path import exists

CONTACTS_FILENAME="contacts.yaml"
CONTACTS_KEY_FILENAME="contacts_key.key"

# Create, save, and return key
def create_key():
    key = Fernet.generate_key()
    with open(CONTACTS_KEY_FILENAME, 'wb+') as key_file:
        key_file.write(key)
    return key

# Decrypt and read contacts with key
def read_contacts(key) -> dict:
    fernet = Fernet(key)
    
    # Load the contacts data
    with open(CONTACTS_FILENAME, 'rb') as contacts_file:
        contacts_enc = contacts_file.read()
    contacts = yaml.safe_load(fernet.decrypt(contacts_enc).decode())
    return contacts

# Encrypt and write back to a contacts file
def write_contacts(key, contacts: dict):
    fernet = Fernet(key)
    contacts_enc = fernet.encrypt(yaml.dump(contacts).encode())
    
    # Write the encrypted data back
    with open(CONTACTS_FILENAME, 'wb+') as contacts_file:
        contacts_file.write(contacts_enc)

# Loads key from keyfile
def load_key():
    with open(CONTACTS_KEY_FILENAME, 'rb') as key_file:
        key = key_file.read()
    return key

# Determines the condition of the contacts data
# 1 -> Both Data and key exists
# 0 -> Data exists without key
# -1 -> Neither data nor key exists
def contacts_exist():
    if exists(CONTACTS_FILENAME):
        if exists(CONTACTS_KEY_FILENAME):
            return 1
        else:
            return 0
    else:
        return -1
