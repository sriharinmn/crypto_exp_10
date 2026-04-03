#!/usr/bin/env python3
"""
=============================================================
  TASK 2 — SSH CLIENT (Encrypted Communication)
  Connects to ssh_server.py using Paramiko
  
  Install: pip3 install paramiko --break-system-packages
  Usage:   python3 ssh_client.py
=============================================================
"""

import paramiko
import sys
import socket

HOST     = "127.0.0.1"
PORT     = 2222
USERNAME = "student"
PASSWORD = "password123"


def main():
    print(f"\n[SSH Client] Connecting to {HOST}:{PORT} as '{USERNAME}'...")

    try:
        # ── Create transport ─────────────────────────────────
        sock = socket.create_connection((HOST, PORT))
        transport = paramiko.Transport(sock)
        transport.start_client()

        # ── Skip host key verification for lab ───────────────
        # (in production, always verify!)
        transport.get_remote_server_key()
        print("[SSH Client] Server key received (not verified — lab mode)")

        # ── Authenticate ─────────────────────────────────────
        transport.auth_password(USERNAME, PASSWORD)
        if not transport.is_authenticated():
            print("[SSH Client] Authentication FAILED.")
            sys.exit(1)
        print("[SSH Client] Authenticated successfully!\n")

        # ── Open interactive shell channel ───────────────────
        channel = transport.open_session()
        channel.get_pty()
        channel.invoke_shell()

        import threading
        import select
        import termios
        import tty

        # Read from server and print
        def read_server():
            while True:
                try:
                    if channel.recv_ready():
                        data = channel.recv(4096)
                        if not data:
                            print("\n[SSH Client] Server closed connection.")
                            break
                        sys.stdout.write(data.decode(errors="replace"))
                        sys.stdout.flush()
                except Exception:
                    break

        t = threading.Thread(target=read_server, daemon=True)
        t.start()

        # Send user input to server
        import time
        time.sleep(0.5)

        try:
            # Try raw terminal mode (works in real terminals)
            old_settings = termios.tcgetattr(sys.stdin)
            tty.setraw(sys.stdin.fileno())
            raw_mode = True
        except Exception:
            raw_mode = False

        try:
            while True:
                if raw_mode:
                    r, _, _ = select.select([sys.stdin], [], [], 0.05)
                    if r:
                        ch = sys.stdin.read(1)
                        if ch == "\x03":  # Ctrl+C
                            break
                        channel.send(ch)
                else:
                    # Fallback: line-by-line input
                    try:
                        line = input()
                        channel.send(line + "\r\n")
                        if line.strip() == "exit":
                            break
                        time.sleep(0.2)
                    except EOFError:
                        break
        finally:
            if raw_mode:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)

    except paramiko.AuthenticationException:
        print("[SSH Client] Authentication failed.")
    except paramiko.SSHException as e:
        print(f"[SSH Client] SSH error: {e}")
    except ConnectionRefusedError:
        print(f"[SSH Client] Cannot connect. Is ssh_server.py running on port {PORT}?")
    except Exception as e:
        print(f"[SSH Client] Error: {e}")
    finally:
        try:
            transport.close()
        except Exception:
            pass
        print("\n[SSH Client] Disconnected.")

if __name__ == "__main__":
    main()