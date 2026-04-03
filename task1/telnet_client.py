#!/usr/bin/env python3
"""
=============================================================
  TASK 1 — TELNET CLIENT (Plain Text Communication)
  Usage: python3 telnet_client.py
  Make sure telnet_server.py is running first!
=============================================================
"""

import socket
import threading
import sys
import time

HOST = "127.0.0.1"
PORT = 2323

def receive_thread(sock: socket.socket):
    """Continuously receive and print data from server."""
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                print("\n[Client] Server closed the connection.")
                sys.exit(0)
            sys.stdout.write(data.decode(errors="replace"))
            sys.stdout.flush()
        except OSError:
            break

def main():
    print(f"[Client] Connecting to {HOST}:{PORT} ...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((HOST, PORT))
        print(f"[Client] Connected!\n")
    except ConnectionRefusedError:
        print("[Client] ERROR: Could not connect. Is telnet_server.py running?")
        sys.exit(1)

    # Start a background thread to print server messages
    t = threading.Thread(target=receive_thread, args=(sock,), daemon=True)
    t.start()

    time.sleep(0.3)   # let banner arrive

    # ── Interactive loop ────────────────────────────────────
    try:
        while True:
            user_input = input()
            if not user_input and not t.is_alive():
                break
            sock.sendall((user_input + "\r\n").encode())
            if user_input.strip().lower() == "exit":
                time.sleep(0.3)
                break
    except (KeyboardInterrupt, EOFError):
        print("\n[Client] Disconnected by user.")
    finally:
        sock.close()
        print("[Client] Connection closed.")

if __name__ == "__main__":
    main()