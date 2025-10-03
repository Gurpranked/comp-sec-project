# Copyright 2025
# Author: Gurpreet Singh
from bcolors import bcolors
import hashlib
import yaml
import os

def hash(item: str, salt = None):
	if salt:
		item_salt = b'item' + salt
		hashed = hashlib.sha256(item_salt)
		return hashed.hexdigest()
	else:
		return hashlib.sha256(b'item').hexdigest()
 
def compare_hash(item: str, hashed_item: str, salt = None) -> bool:
	if salt:
		item_salt = b'item' + salt
		hashed = hashlib.sh256(item_salt)
		return (hashed.hexdigest() == hashed_item) 
	else:
		hashed = hashlib.sha256(item)
		return (hashed.hexdigest() == hashed_item)
			
