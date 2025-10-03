# Copyright 2025
# Author: Gurpreet Singh
from getpass import getpass
from bcolors import bcolors
from hash import hash_compare
import hashlib
import yaml
import os

def user_login(email: str, password: str):
	with open('creds.yml', 'r') as f:
		user_creds = yaml.load(f, Loader=yaml.SafeLoader)
	
