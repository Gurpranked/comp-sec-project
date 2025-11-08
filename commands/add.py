# Copyright 2025
# Author: Gurpreet Singh

from utils.bcolors import bcolors 
from utils.contacts_helpers import *

CONTACTS_FILENAME="contacts.yaml"
CONTACTS_KEY_FILENAME="contacts_key.key"

def add():
    name = input("  Enter Contact Full Name: ")
    email = input("  Enter Contact Email Address: ")
    
    match contacts_exist():
        case 1:
            key = load_key()
            contacts = read_contacts(key)

            # Get public key from CA and add it here
                
            contacts[email] = name
            write_contacts(key, contacts)
            print("Contact Added.")
        
        case 0:
            print(f"{bcolors.FAIL} Encryption key is missing for the data!{bcolors.ENDC}")
        
        case -1:

            # Get Public key from CA and add it here
            contact_obj = {email:name}
            key = create_key()
            write_contacts(key, contact_obj)
            print("Contact Added.") 
    
