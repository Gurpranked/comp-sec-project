# Copyright 2025
# Author: Gurpreet Singh

from bcolors import bcolors 
from contacts_helpers import create_key, read_contacts, write_contacts, contacts_exist, load_key, create_key

CONTACTS_FILENAME="contacts.yaml"
CONTACTS_KEY_FILENAME="contacts_key.key"

def add():
    name = input("  Enter Contact Full Name: ")
    email = input("  Enter Contact Email Address: ")
    
    match contacts_exist():
        case 1:
            key = load_key()
            contacts = read_contacts(key)
            contacts[email] = name
            write_contacts(key, contacts)
            print("Contact Added.")
        
        case 0:
            print(f"{bcolors.FAIL} Encryption key is missing for the data!{bcolors.ENDC}")
        
        case -1:
            contact_obj = {email:name}
            key = create_key()
            write_contacts(key, contact_obj)
            print("Contact Added.") 
    
