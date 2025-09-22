# Copyright 2025
# Author: Gurpreet Singh
from getpass import getpass
from bcolors import bcolors

def user_registration():
    full_name = input(f"{bcolors.BOLD}Enter Full Name: {bcolors.ENDC}")
    email = input(f"{bcolors.BOLD}Enter Email Address: {bcolors.ENDC}")
    password = ""
    password1 = "1"
    while not (password == password1):
        password = getpass(f"{bcolors.BOLD}Enter Password: {bcolors.ENDC}") 
        password1 = getpass(f"{bcolors.BOLD}Re-enter Password: {bcolors.ENDC}")
        if not (password == password1) :
            print(f"{bcolors.FAIL}Passwords don't match, try again{bcolors.ENDC}")

    print(f"{bcolors.OKGREEN}Passwords match.{bcolors.ENDC}")    

    # Something something user registered
