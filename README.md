# Intro to Computer Security

## Todo
- [x] Review the material for the project
- [x] Review the file transfer code 


## Milestone 1: User Registration
- [x] Implement User Registration **without** security controls
- [x] Leverage Python APIs and `crypt` library for salted hashes on passwords
- [ ] Assume CAs for digital certificates

## Milestone 2: User Login 
- [ ] Flush credentials from memory after program's exit

## Milestone 3: Adding Contacts
- [ ] No need for DB implementation, YAML, JSON adequate
- [ ] Prevent unauthorized access to data

## Milestone 4: Listing Contacts
- [ ] Display contact info only if user has added the contact, contact has reciprocated, contact is online on the network. 
- [ ] Implement without security at first, then add security at transport layer with TCP and UDP. Use Python's `socket`. 
- [ ] Use `pycryptodome` and `cryptography`
- [ ] Encrypt packets to prevent packet sniffing
- [ ] Implement a protocol for mutual authentication between the parties 
- [ ] Exchange unique and protected information between entities to enhance security without requiring reauth in subsequent steps.

## Milestone 5: Secure File Transfer
- [ ] Efficiently transfer large files. Verification of the file match must occur before the file is declared as transferred.
- [ ] Mitigate replay attacks by using sequence numbers, start with random seed on each client.


User Credentials
- Full Name
- Email Address
- Password
- Password salt
