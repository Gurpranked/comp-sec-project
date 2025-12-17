# Usage
1. Build the images: `docker-compose build`
2. Setup the PKI: `docker-compose up -d ca`
3. Start the repl: `uv run host_repl.py`

# Client Architecture
```
+--------------------------+
| Client Container         |
|   - Client and CA keys   |
|   - client logic         |
|   - TLS sockets          |
|__________________________|
         ^
         |  REPL sends commands
         |
+--------------------------+
| REPL Process (frontend) |
|  - No private keys       |
|  - No network access     |
|  - No crypto code        |
+--------------------------+
```
# Multi-client Architecture
```
+------------------------------+       +------------------------------+
| REPL Frontend (no crypto)    |       | REPL Frontend (no crypto)    |
+------------------------------+       +------------------------------+
           | IPC / exec                             | IPC / exec
           v                                        v
+------------------------------+       +------------------------------+
| Client Container A           | <---> | Client Container B           |
|  - Contact Certificates      |       |  - Contact Certificates      |
|  - TLS client/server         |       |  - TLS client/server         |
|  - File encryption           |       |  - File encryption           |
+------------------------------+       +------------------------------+
                \                  /
                 \                /
                  \              /
                   v            v
             +---------------------+
             |    CA Container     |
             |   (PGP Authority)   |
             +---------------------+
```
# Currently implemented
- Account creation process, REPL -> Container -> CA -> Container -> REPL
    - Add to local DB for REPL
    - Create and start approrpriate container
    - Register with CA
    - Respond to Container
    - Respond to REPL
- Account removal process, REPL -> Container -> CA -> Container -> REPL 
    - Execute command into container
    - Request removal from CA
    - CA produces and sends Challenge
    - Container solves and responds to challenge
    - CA removes record
    - Respond to REPL
    - REPL removes corresponding container
    - REPL removes record from local DB
- Login functionality
    - Check credentials against local information
    - Start corresponding container
- Logout functionality
    - Stop corresponding conatiner
    - Remove session records
## CA specifically
- CA functionality fully implemented
    - Get other user certificates
    - Register yourself
    - Remove yourself with challenge

- Add contacts
    - Req: `email`
    - REPL -> Container -> CA -> Container -> REPL
    - REPL requests container to lookup the email into CA
    - Obtain signed key and verify against CA public key
    - Store record into container
    - Respond to REPL
- Functionality to check if contacts are online
    - REPL -> Container -> REPL
    - REPL requests container to return all online containers
    - Container checks list and sequentially checks if each record is online
    - Container responds with list of online contacts
# To-do
- [ ] Send files to contacts
    - (REPL -> Container -> REPL) -> (Other container -> Other REPL)
    - REPL requests container to send a file to a contact
    - Container checks if contact is online
    - Container attempts to make connection to other container 
    - Other container pings it's REPL to notify of file transfer request
    - Contact accepts or denies
    - Container encrypts content with contact's public key
    - Send file
    - Contact obtains file into it's container
    - Container responds to REPL with success or failure

    - Other container 

