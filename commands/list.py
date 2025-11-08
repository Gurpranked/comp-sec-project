# Copyright 2025
# Author: Gurpreet Singh

import yaml
from utils.contacts_helpers import read_contacts, contacts_exist, load_key
from add import add

def list():
    match contacts_exist():
        
        # Contacts exist, make the necessary checks
        case 1:
            # Obtain the key
            key = load_key()
            contacts = read_contacts(key)
            
            # Find some way to determine if the contact is active
            print("Case 1")

        # Contacts encryption key missing
        case 0:
           print(f"{bcolors.FAIL} Encryption key is missing for the data!{bcolors.ENDC}")
        
        # User has no contacts
        case -1:
            choice = input(f"{bcolors.BOLD} You currently have no contacts. Would you like to add them?(y/n){bcolors.ENDC}")
            choice = choice.lower()
            if (choice == 'y' or choice == 'yes'):
                add()
            else:
                print(f"{bcolors.BOLD}You have no contacts, nothing to show!{bcolors.ENDC}")
            
    
