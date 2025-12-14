# Usage
1. Setup the PKI: `docker-compose up -d --build`
2. Start the repl: `uv run host_repl.py`

# Client Architecture
+--------------------------+
| Client Container         |
|   - gpg home             |
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

# Multi-client Architecture
+------------------------------+       +------------------------------+
| REPL Frontend (no crypto)    |       | REPL Frontend (no crypto)    |
+------------------------------+       +------------------------------+
           | IPC / exec                             | IPC / exec
           v                                        v
+------------------------------+       +------------------------------+
| Client Container A           | <---> | Client Container B           |
|  - GPG Keyring               |       |  - GPG Keyring               |
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

# Current Bugs
Failed communication to CA via CA communication functions within client container and `host_repl.py`
