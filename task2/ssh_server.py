#!/usr/bin/env python3
"""
=============================================================
  TASK 2 — SSH SERVER (Encrypted Communication)
  Uses Paramiko to create a real SSH server
  
  Install: pip3 install paramiko --break-system-packages
  Usage:   python3 ssh_server.py
  Connect: ssh student@127.0.0.1 -p 2222
=============================================================
"""

import socket
import threading
import paramiko
import os
import datetime

HOST      = "127.0.0.1"
PORT      = 2222
HOST_KEY_FILE = "ssh_host_rsa_key"

# Same users as telnet server — but traffic will be ENCRYPTED
USERS = {
    "student": "password123",
    "admin":   "admin@123",
}

LOG_FILE = "ssh_server_log.txt"

def log(msg: str):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


# ── Generate host key if not present ────────────────────────
def get_host_key() -> paramiko.RSAKey:
    if os.path.exists(HOST_KEY_FILE):
        return paramiko.RSAKey(filename=HOST_KEY_FILE)
    log("Generating RSA host key (2048-bit)...")
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(HOST_KEY_FILE)
    log(f"Host key saved to {HOST_KEY_FILE}")
    return key


# ── SSH Server Interface ─────────────────────────────────────
class SSHServerInterface(paramiko.ServerInterface):
    def __init__(self):
        self.username = None
        self.event    = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        log(f"AUTH ATTEMPT  user='{username}'  pass='{password}'")
        if USERS.get(username) == password:
            self.username = username
            log(f"AUTH SUCCESS  user='{username}'")
            return paramiko.AUTH_SUCCESSFUL
        log(f"AUTH FAILED   user='{username}'")
        return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def get_allowed_auths(self, username):
        return "password"


# ── Client handler ───────────────────────────────────────────
def handle_ssh_client(client_sock: socket.socket, addr, host_key: paramiko.RSAKey):
    log(f"New connection from {addr}")

    try:
        transport = paramiko.Transport(client_sock)
        transport.add_server_key(host_key)

        server_iface = SSHServerInterface()
        transport.start_server(server=server_iface)

        # Wait for channel
        channel = transport.accept(timeout=20)
        if channel is None:
            log(f"No channel opened from {addr}")
            return

        server_iface.event.wait(10)
        username = server_iface.username or "unknown"

        # ── Send welcome banner ───────────────────────────────
        banner = (
            "\r\n" + "=" * 50 + "\r\n"
            f"  SSH LAB SERVER — Encrypted Demo\r\n"
            f"  Logged in as: {username}\r\n"
            "=" * 50 + "\r\n"
            "Type 'help' for commands.\r\n"
        )
        channel.send(banner)

        # ── Command loop ──────────────────────────────────────
        while True:
            channel.send("\r\n$ ")
            cmd_buf = b""

            while True:
                chunk = channel.recv(1)
                if not chunk:
                    return
                if chunk in (b"\r", b"\n"):
                    channel.send("\r\n")
                    break
                elif chunk == b"\x7f":  # backspace
                    if cmd_buf:
                        cmd_buf = cmd_buf[:-1]
                        channel.send(b"\b \b")
                else:
                    cmd_buf += chunk
                    channel.send(chunk)

            cmd = cmd_buf.decode(errors="replace").strip()
            log(f"CMD from '{username}': '{cmd}'")

            if cmd == "":
                continue
            elif cmd == "help":
                resp = (
                    "\r\nAvailable commands:\r\n"
                    "  whoami   — show logged-in user\r\n"
                    "  secret   — show secret data (ENCRYPTED in transit)\r\n"
                    "  time     — server time\r\n"
                    "  echo     — echo a message\r\n"
                    "  exit     — disconnect\r\n"
                )
            elif cmd == "whoami":
                resp = f"\r\n{username}\r\n"
            elif cmd == "secret":
                resp = (
                    "\r\n[SECRET DATA — encrypted in transit via SSH!]\r\n"
                    "  DB Password : supersecret_db_pass\r\n"
                    "  API Key     : sk-1234567890abcdef\r\n"
                    "  Card Number : 4111-1111-1111-1111\r\n"
                    "\r\n  (Packet capture shows ONLY encrypted bytes)\r\n"
                )
            elif cmd == "time":
                resp = f"\r\nServer time: {datetime.datetime.now()}\r\n"
            elif cmd.startswith("echo "):
                resp = f"\r\n{cmd[5:]}\r\n"
            elif cmd == "exit":
                channel.send("\r\nGoodbye!\r\n")
                log(f"LOGOUT  user='{username}'")
                break
            else:
                resp = f"\r\nUnknown command: '{cmd}'. Type 'help'.\r\n"

            channel.send(resp)

    except Exception as e:
        log(f"Error handling {addr}: {e}")
    finally:
        try:
            transport.close()
        except Exception:
            pass
        client_sock.close()
        log(f"Connection closed: {addr}")


def main():
    host_key = get_host_key()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(10)

    log(f"SSH server started on {HOST}:{PORT}")
    log(f"Connect with:  ssh student@{HOST} -p {PORT}  (pass: password123)")
    log(f"Or run:        python3 ssh_client.py")
    print("-" * 50)

    try:
        while True:
            client_sock, addr = server_sock.accept()
            t = threading.Thread(
                target=handle_ssh_client,
                args=(client_sock, addr, host_key),
                daemon=True
            )
            t.start()
    except KeyboardInterrupt:
        log("SSH server shutting down.")
    finally:
        server_sock.close()

if __name__ == "__main__":
    main()