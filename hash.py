# Copyright 2025
# Author: Gurpreet Singh
from bcolors import bcolors
import hashlib
import yaml
import os

def hash(item, salt = None):
	if salt:
		hashed = hashlib.sha256(b'item' + b'salt')
		return hashed.hexdigest()
	else:
		return hashlib.sha256(b'item').hexdigest()
 
def hash_compare(item: str, hashed_item: str, salt = None) -> bool:
	return hashed_item == hash(item, salt)	

def generate_digest(message: str):
	return hashlib.sha256(message.encode()).hexdigest()

