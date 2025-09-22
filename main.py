# Copyright 2025
# Author: Gurpreet Singh
from user_registration import user_registration

def driver():
    accounts_exist = False
    if not accounts_exist:
        register = input("Do you want to register a new user (y/n)?")
        if (register == "y"):
            user_registration()
            print("Exiting SecureDrop.")
            exit(1)


if __name__ == "__main__":
    driver()