# Copyright 2025
# Author: Gurpreet Singh

from getpass import getpass
from bcolors import bcolors
from hash import hash, hash_compare
import gc
import hashlib
import yaml
import os

def user_login():
	authenticated = False
	while not authenticated:
		email = input("Enter Email Address: ")
		pwd = getpass("Enter Password: ")
		if lookup_and_validate(email, pwd):
			authenticated = True
		else:
			print("Email and Password Combination Invalid.\n")


def lookup_and_validate(email: str, pwd: str):
	# Open credential file 
	with open('creds.yml', 'r') as f:
		user_creds = yaml.load(f, Loader=yaml.SafeLoader)
	
	# Perform a table lookup for the email (hashed)
	hashed_email = hash(email)
	
	if user_creds[hashed_email]:
		salt = user_creds[hashed_email]['salt']
		stored_pwd = user_creds[hashed_email]['pwd']
		if hash_compare(email, stored_pwd, salt):
			
			# Flush user credentials from memory 
			#del user_creds
			# Run garbage collector manually
			#gc.collect()

			return True
		else:
			# Flush user credentials from memory
			#del user_creds
			# Run garbage collector manually
			#gc.collect()

			return False
