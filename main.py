# Copyright 2025
# Author: Gurpreet Singh
from user_registration import user_registration

CREDS_FILENAME = "creds.yml"

def driver():
    accounts_exist = False
    if not accounts_exist:
        print("No users are registered on this client.")
        register = input("Do you want to register a new user (y/n)?")
        print()
        if (register == "y"):
            user_registration(CREDS_FILENAME)
            print("Exiting SecureDrop.")
            exit(0)


if __name__ == "__main__":
    driver()
