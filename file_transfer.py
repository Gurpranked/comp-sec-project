import socket, threading, os

# === Standard TCP port for all peers ===
PORT = 1234

# === Start the receiver (server) in the background ===
def start_receiver():
    # This function handles each incoming file transfer
    def handle(conn):
        try:
            # Step 1: Receive mode (should be "SEND_FILE")
            mode = conn.recv(9).decode().strip()
            if mode != "SEND_FILE":
                print("[IGNORED] Invalid mode:", mode)
                return

            # Step 2: Receive the filename (sent as 1024 bytes)
            filename = conn.recv(1024).decode().strip()
            save_path = "received_" + filename  # Save with prefix
            print(f"[RECEIVING] Saving to: {save_path}")

            # Step 3: Receive file content in chunks
            with open(save_path, "wb") as f:
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break  # No more data
                    f.write(data)

            print(f"[DONE] File saved: {save_path}")

        except Exception as e:
            print(f"[ERROR] {e}")
        finally:
            conn.close()  # Always close the connection

    # This is the main listener that accepts incoming connections
    def server():
        with socket.socket() as s:
            s.bind(('', PORT))      # Bind to all network interfaces on the chosen port
            s.listen()              # Start listening for connections
            print(f"[LISTENING] on port {PORT}...")
            while True:
                conn, _ = s.accept()  # Accept a connection
                # Handle each connection in a new thread
                threading.Thread(target=handle, args=(conn,), daemon=True).start()

    # Start the server thread in background so the script can keep running
    threading.Thread(target=server, daemon=True).start()

# === Send a file to another peer ===
def send_file():
    # Ask user for the target peer's hostname or container name
    peer = input("Enter receiver hostname (e.g. CA, CB): ").strip()

    # Ask for the file to send
    filename = input("Enter filename to send: ").strip()

    # Check if file actually exists
    if not os.path.exists(filename):
        print("[ERROR] File not found.")
        return

    try:
        # Connect to the peer at the known port
        with socket.create_connection((peer, PORT), timeout=3) as s:
            # Step 1: Send the mode
            s.sendall(b"SEND_FILE")  # Send "SEND_FILE" as 9 bytes

            # Step 2: Send filename (padded to 1024 bytes)
            s.sendall(filename.encode().ljust(1024))

            # Step 3: Send the actual file content in chunks
            with open(filename, "rb") as f:
                while True:
                    chunk = f.read(1024)
                    if not chunk:
                        break  # EOF
                    s.sendall(chunk)

        print(f"[SENT] File '{filename}' sent to {peer}")

    except Exception as e:
        print(f"[FAILED] {e}")

# === Main execution ===
if __name__ == "__main__":
    start_receiver()              # Always start receiver first (listens in background)
    send_file()                   # Then prompt the user to send a file
    input("[INFO] Press Enter to exit...\n")  # Keep program alive so receiver can stay active

