import argparse
import sys
import os
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def encrypt(key_path, plain_file_path, enc_file_path):
	
	if not os.path.exists(key_path):
		raise FileNotFoundError(f"Key File '{key_path}' does not exist.")
	
	if not os.path.exists(plain_file_path):
		raise FileNotFoundError(f"Plaintext file '{plain_file_path}' does not exist.")
		
	recipient_key = RSA.importKey(open(key_path, "rb").read())
	session_key = get_random_bytes(16)

	# Encrypt Session key with public RSA key
	cipher_rsa = PKCS1_OAEP.new(recipient_key)
	enc_session_key = cipher_rsa.encrypt(session_key)

	# Encrypt the data with AES session key
	cipher_aes = AES.new(session_key, AES.MODE_EAX)
	ciphertext, tag = cipher_aes.encrypt_and_digest(open(plain_file_path, "rb").read())

	with open(enc_file_path, "wb") as f:
		f.write(enc_session_key)
		f.write(cipher_aes.nonce)
		f.write(tag)
		f.write(ciphertext)	
	 
	print("> Encryption Successful.")

def decrypt(key_path, enc_file_path, plain_file_path):
	if not os.path.exists(key_path):
		raise FileNotFoundError(f"Key File '{key_path}' does not exist.")
	if not os.path.exists(enc_file_path):
		raise FileNotFoundError(f"Plaintext file '{enc_file_path}' does not exist.")
    
	private_key = RSA.importKey(open(key_path, "rb").read())

	with open(enc_file_path, "rb") as f:
		enc_session_key = f.read(private_key.size_in_bytes())
		nonce = f.read(16)
		tag = f.read(16)
		ciphertext = f.read()
	
	# Decrypt the session key with private RSA key
	cipher_rsa = PKCS1_OAEP.new(private_key) 
	session_key = cipher_rsa.decrypt(enc_session_key)

	# Decrypt the data from the AES Session key
	cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
	try:
		message = cipher_aes.decrypt_and_verify(ciphertext, tag)
	except ValueError:
		print("The message was modified!")
		sys.exit(1)

	with open(plain_file_path, "wb") as f:
		f.write(message)

	print("> Decryption Successful.")

def main():
	parser=argparse.ArgumentParser(description='Encrypt or Decrypt ciphertext.')
	group=parser.add_mutually_exclusive_group(required=True)
	
	group.add_argument('--encrypt', metavar=('receiver-public-key', 'plaintext-file', 'encrypted-file'), nargs=3, help='Encrypt plaintext')

	group.add_argument('--decrypt', metavar=('receiver-private-key', 'encrypted-file', 'plaintext-file'), nargs=3, help='Decrypt ciphertext')

	args = parser.parse_args()
	
	if args.encrypt:
		try:
			encrypt(args.encrypt[0], args.encrypt[1], args.encrypt[2])
		except Exception as e:
			print(e)
	elif args.decrypt:
		try:
			decrypt(args.decrypt[0], args.decrypt[1], args.decrypt[2])
		except Exception as e:
			print(e)
	else:
		print("Invalid runtime arguments, use -h to get usage info.")


if __name__=="__main__":
	main()
