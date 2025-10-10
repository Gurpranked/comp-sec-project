# Copyright 2025
# Author: Gurpreet Singh

from getpass import getpass
from bcolors import bcolors
from hash import hash, hash_compare
import gc
import hashlib
import yaml
import os

def lookup_and_validate(email: str, pwd: str):
	hashed_email = hash(email)

	# Open credential file 
	with open('creds.yml', 'r') as f:
		user_creds = yaml.load(f, Loader=yaml.SafeLoader)
	
		try:
			salt = eval(user_creds[hashed_email]['salt'])
			stored_pwd = user_creds[hashed_email]['pwd']
			return hash_compare(pwd, stored_pwd, salt)
		except KeyError:
			return False

def user_login():
	authenticated = False
	while authenticated == False:
		email = input("Enter Email Address: ")
		pwd = getpass("Enter Password: ")
		authenticated = lookup_and_validate(email, pwd)
		if (authenticated == False):	
			print("Email and Password Combination Invalid.\n")
	hashed_email = hash(email)	
	with open('creds.yml', 'r') as f:
		user_creds = yaml.load(f, Loader=yaml.SafeLoader)
		name = user_creds[hashed_email]['name']
	
	return (email, name)	
