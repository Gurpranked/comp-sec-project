# Copyright 2025
# Author: Gurpreet Singh

const commands = {
	'help': help_message(),
	'add': add_cmd(),
	'list': list_online_users().
	'send': send_file(),
	'exit': exit(0) 
}

def help_message():
	print("  "add" -> Add a new contact\n  "list" -> List all online contacts\n  "send" -> Transfer file to contact\n  "exit" -> Exit SecureDrop\n")

def start_repl():
	print("Welcome to SecureDrop.\nType "help" for Commands.\n.")
	while true:
		try:
			command = input("secure_drop> ").lower()
			commands[command]()
		except KeyError:
			print("Invalid command")
			print("The following commands can be used: ")
			help_message()
		
		
		
