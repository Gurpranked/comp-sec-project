# Copyright 2025
# Author: Gurpreet Singh

from add import add

def help_message():
	print("  \"add\" -> Add a new contact\n  \"list\" -> List all online contacts\n  \"send\" -> Transfer file to contact\n  \"exit\" -> Exit SecureDrop\n")


def start_repl():
	commands = {
		"help": help_message,
                "add": add
	}	
	print("Welcome to SecureDrop.\nType \"help\" for Commands.\n")
	while True:
		command = input("secure_drop> ").lower()
		if (command == 'exit'):
			exit(0)	
		try:
			commands[command]()
		except KeyError:
			print("Invalid command")
			print("The following commands can be used: ")
			help_message()
		
		
		
