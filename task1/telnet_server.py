#!/usr/bin/env python3
"""
=============================================================
  TASK 1 — TELNET SERVER (Plain Text Communication)
  Run this first, then run telnet_client.py in another terminal
  Usage: sudo python3 telnet_server.py
=============================================================
"""

import socket
import threading
import datetime

HOST = "127.0.0.1"
PORT = 2323          # Using 2323 so we don't need sudo (port 23 needs root)
BANNER = b"\r\n" + b"=" * 50 + b"\r\n"
BANNER += b"   TELNET LAB SERVER — Plain Text Demo\r\n"
BANNER += b"=" * 50 + b"\r\n"

# Simple user DB (plain text — this is the security problem!)
USERS = {
    "student": "password123",
    "admin":   "admin@123",
}

LOG_FILE = "server_log.txt"

def log(msg: str):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def handle_client(conn: socket.socket, addr):
    log(f"New connection from {addr}")
    try:
        # ── Send banner ──────────────────────────────────────
        conn.sendall(BANNER)
        conn.sendall(b"Login: ")
        username = conn.recv(256).decode(errors="replace").strip()

        conn.sendall(b"Password: ")
        password = conn.recv(256).decode(errors="replace").strip()

        log(f"AUTH ATTEMPT  user='{username}'  pass='{password}'")

        # ── Authenticate ─────────────────────────────────────
        if USERS.get(username) == password:
            conn.sendall(f"\r\nWelcome, {username}! Type 'help' for commands.\r\n".encode())
            log(f"LOGIN SUCCESS  user='{username}'")
        else:
            conn.sendall(b"\r\nInvalid credentials. Goodbye.\r\n")
            log(f"LOGIN FAILED  user='{username}'")
            conn.close()
            return

        # ── Command loop ──────────────────────────────────────
        while True:
            conn.sendall(b"\r\n$ ")
            data = conn.recv(1024)
            if not data:
                break
            cmd = data.decode(errors="replace").strip()
            log(f"CMD from {username}: '{cmd}'")

            if cmd == "":
                continue
            elif cmd == "help":
                resp = (
                    "\r\nAvailable commands:\r\n"
                    "  whoami   — show logged-in user\r\n"
                    "  secret   — show secret data (sent in PLAIN TEXT)\r\n"
                    "  time     — show current server time\r\n"
                    "  echo     — echo a message\r\n"
                    "  exit     — disconnect\r\n"
                )
            elif cmd == "whoami":
                resp = f"\r\n{username}\r\n"
            elif cmd == "secret":
                resp = (
                    "\r\n[SECRET DATA — visible in packet capture!]\r\n"
                    "  DB Password : supersecret_db_pass\r\n"
                    "  API Key     : sk-1234567890abcdef\r\n"
                    "  Card Number : 4111-1111-1111-1111\r\n"
                )
            elif cmd == "time":
                resp = f"\r\nServer time: {datetime.datetime.now()}\r\n"
            elif cmd.startswith("echo "):
                resp = f"\r\n{cmd[5:]}\r\n"
            elif cmd == "exit":
                conn.sendall(b"\r\nGoodbye!\r\n")
                log(f"LOGOUT  user='{username}'")
                break
            else:
                resp = f"\r\nUnknown command: '{cmd}'. Type 'help'.\r\n"

            conn.sendall(resp.encode())

    except (ConnectionResetError, BrokenPipeError):
        log(f"Client {addr} disconnected abruptly.")
    finally:
        conn.close()
        log(f"Connection closed: {addr}")

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(10)
    log(f"Telnet server started on {HOST}:{PORT}")
    log(f"Connect with:  telnet {HOST} {PORT}")
    log(f"Or run:        python3 telnet_client.py")
    print("-" * 50)

    try:
        while True:
            conn, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        log("Server shutting down.")
    finally:
        server.close()

if __name__ == "__main__":
    main()