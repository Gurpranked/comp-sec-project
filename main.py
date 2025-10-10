# Copyright 2025
# Author: Gurpreet Singh

from user_registration import user_registration
from getpass import getpass
from bcolors import bcolors
from login import user_login
from repl import start_repl
import os
CREDS_FILENAME = "creds.yml"

def driver():
	# User Credentials don't exist
	if not os.path.exists(CREDS_FILENAME):
		print("No users are registered on this client.")
		register = input("Do you want to register a new user (y/n)?")
		print()

		if (register == "y"):
			user_registration(CREDS_FILENAME)
		
		print("Exiting SecureDrop.")
		exit(0)
    
	# Login user
	else:
		email, name = user_login()
		start_repl()


if __name__ == "__main__":
	driver()
