#!/usr/bin/env python3
"""
=============================================================
  NETWORK SECURITY LAB — MASTER SETUP & RUN SCRIPT
  
  Run this to install all dependencies and see instructions.
  Usage: python3 setup.py
=============================================================
"""

import subprocess
import sys
import os

PACKAGES = [
    "flask",
    "flask-jwt-extended",
    "paramiko",
    "scapy",
]

def install(pkg):
    print(f"  Installing {pkg}...")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", pkg, "--break-system-packages", "-q"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        print(f"  ✓ {pkg} installed")
    else:
        print(f"  ✗ {pkg} failed: {result.stderr.strip()[:100]}")

def check_tshark():
    result = subprocess.run(["which", "tshark"], capture_output=True)
    if result.returncode == 0:
        print("  ✓ tshark found")
    else:
        print("  ✗ tshark NOT found. Install: sudo apt install tshark")

def main():
    print("\n" + "=" * 60)
    print("  NETWORK SECURITY LAB — Setup")
    print("=" * 60)

    print("\n[1] Installing Python packages...")
    for pkg in PACKAGES:
        install(pkg)

    print("\n[2] Checking tshark...")
    check_tshark()

    print("\n" + "=" * 60)
    print("  HOW TO RUN THE LAB")
    print("=" * 60)

    print("""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  TASK 1 — TELNET (Plain Text)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Terminal 1 — Start packet capture:
    cd task1_telnet
    python3 capture_and_analyze.py capture 2323 telnet.pcap lo
    (Press Ctrl+C after step 3 to stop)

  Terminal 2 — Start the Telnet server:
    cd task1_telnet
    python3 telnet_server.py

  Terminal 3 — Run the Telnet client:
    cd task1_telnet
    python3 telnet_client.py
    > (login: student / password123)
    > whoami
    > secret
    > exit

  Terminal 1 — Stop capture (Ctrl+C), then analyze:
    python3 capture_and_analyze.py analyze telnet.pcap 2323

  EXPECTED: You will see USERNAME, PASSWORD, COMMANDS in plain text!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  TASK 2 — SSH (Encrypted)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Terminal 1 — Start packet capture:
    cd task2_ssh
    python3 ../task1_telnet/capture_and_analyze.py capture 2222 ssh.pcap lo

  Terminal 2 — Start the SSH server:
    cd task2_ssh
    python3 ssh_server.py

  Terminal 3 — Run the SSH client:
    cd task2_ssh
    python3 ssh_client.py
    > whoami
    > secret
    > exit

  Terminal 1 — Stop capture (Ctrl+C), then analyze:
    python3 ../task1_telnet/capture_and_analyze.py analyze ssh.pcap 2222

  EXPECTED: Only encrypted binary — NO readable text!

  Compare both side by side:
    python3 ../task1_telnet/capture_and_analyze.py compare telnet.pcap ssh.pcap

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  TASK 3 — JWT Web Application
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  cd task3_jwt
  python3 app.py

  Open browser: http://localhost:5000
  
  Steps to test:
  1. Register a user (try role=admin for full access)
  2. Login → observe JWT token in 3-part format
  3. Click "GET /protected" — works with token
  4. Use Token Decoder tab to inspect the JWT
  5. Click "Logout" → token is revoked
  6. Try "GET /protected" again → 401 (token revoked)
  7. Try "Fake Token" → 422 (invalid)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  DEFAULT CREDENTIALS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Telnet/SSH server users:
    student / password123
    admin   / admin@123
""")

if __name__ == "__main__":
    main()