#!/usr/bin/env python3
"""
=============================================================
  TASK 1 — PACKET CAPTURE & ANALYZER
  
  Step 1: Run this script to capture packets (needs scapy)
          python3 capture_and_analyze.py capture
  
  Step 2: In another terminal, run the server & client:
          python3 telnet_server.py
          python3 telnet_client.py
  
  Step 3: Press Ctrl+C here to stop capture, then analyze:
          python3 capture_and_analyze.py analyze telnet_capture.pcap
  
  OR use tshark directly:
          sudo tshark -i lo -f "tcp port 2323" -w telnet_capture.pcap
          sudo tshark -i lo -f "tcp port 22"   -w ssh_capture.pcap
=============================================================
"""

import sys
import os
import subprocess
import datetime

# ── Try importing scapy ──────────────────────────────────────
try:
    from scapy.all import rdpcap, TCP, Raw, IP, wrpcap, sniff
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    print("[!] Scapy not found. Install: pip3 install scapy --break-system-packages")


# ════════════════════════════════════════════════════════════
#  SECTION 1 — LIVE CAPTURE using Scapy
# ════════════════════════════════════════════════════════════

def live_capture(port: int, output_file: str, interface: str = "lo"):
    """Capture packets live using Scapy and save to pcap."""
    if not SCAPY_OK:
        sys.exit(1)

    captured = []

    def packet_callback(pkt):
        if TCP in pkt and (pkt[TCP].sport == port or pkt[TCP].dport == port):
            captured.append(pkt)
            if Raw in pkt:
                direction = "→ SERVER" if pkt[TCP].dport == port else "← CLIENT"
                try:
                    text = pkt[Raw].load.decode(errors="replace").strip()
                    if text:
                        ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
                        print(f"  [{ts}] {direction:10s} | {repr(text)}")
                except Exception:
                    pass

    print(f"\n{'='*60}")
    print(f"  LIVE CAPTURE — Interface: {interface} | Port: {port}")
    print(f"  Saving to: {output_file}")
    print(f"  Press Ctrl+C to stop")
    print(f"{'='*60}\n")

    try:
        sniff(
            iface=interface,
            filter=f"tcp port {port}",
            prn=packet_callback,
            store=False
        )
    except KeyboardInterrupt:
        print(f"\n[*] Capture stopped. {len(captured)} packets captured.")

    if captured:
        wrpcap(output_file, captured)
        print(f"[*] Saved to: {output_file}")
    else:
        print("[!] No packets captured.")


# ════════════════════════════════════════════════════════════
#  SECTION 2 — PCAP ANALYSIS using Scapy
# ════════════════════════════════════════════════════════════

def analyze_pcap(pcap_file: str, port: int = None):
    """
    Read a pcap file and extract all plaintext data.
    Shows clearly what an attacker can see from Telnet vs SSH.
    """
    if not SCAPY_OK:
        sys.exit(1)

    if not os.path.exists(pcap_file):
        print(f"[!] File not found: {pcap_file}")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  PCAP ANALYZER — {pcap_file}")
    print(f"{'='*60}\n")

    packets = rdpcap(pcap_file)
    print(f"[*] Total packets loaded : {len(packets)}")

    # ── Collect stats ────────────────────────────────────────
    tcp_count    = 0
    payload_pkts = []
    ports_seen   = set()

    for pkt in packets:
        if TCP in pkt:
            tcp_count += 1
            ports_seen.add(pkt[TCP].sport)
            ports_seen.add(pkt[TCP].dport)
            if Raw in pkt:
                payload_pkts.append(pkt)

    print(f"[*] TCP packets          : {tcp_count}")
    print(f"[*] Packets with payload : {len(payload_pkts)}")
    print(f"[*] Ports seen           : {sorted(ports_seen)}\n")

    if not payload_pkts:
        print("[!] No payload data found in this pcap.")
        return

    # ── Determine target port ────────────────────────────────
    if port is None:
        # Auto-detect: pick the most common non-ephemeral port
        from collections import Counter
        low_ports = [p for p in ports_seen if p < 1024]
        port = low_ports[0] if low_ports else list(ports_seen)[0]
        print(f"[*] Auto-detected server port: {port}\n")

    # ── Extract and classify payloads ────────────────────────
    print(f"{'─'*60}")
    print(f"  PACKET-BY-PACKET PAYLOAD DUMP")
    print(f"{'─'*60}")

    client_text = ""
    server_text = ""
    is_encrypted = False

    for i, pkt in enumerate(payload_pkts, 1):
        raw  = pkt[Raw].load
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport

        direction = "CLIENT → SERVER" if dport == port else "SERVER → CLIENT"
        src_ip    = pkt[IP].src if IP in pkt else "?"
        dst_ip    = pkt[IP].dst if IP in pkt else "?"

        # Try to decode as text
        try:
            decoded = raw.decode("utf-8", errors="replace")
            printable = "".join(
                c for c in decoded
                if c.isprintable() or c in "\r\n\t"
            ).strip()
        except Exception:
            printable = ""

        hex_preview = raw.hex()[:48] + ("..." if len(raw) > 24 else "")

        print(f"\n  Packet #{i:03d} | {direction}")
        print(f"  Src: {src_ip}:{sport}  →  Dst: {dst_ip}:{dport}")
        print(f"  Size   : {len(raw)} bytes")
        print(f"  Hex    : {hex_preview}")

        if printable:
            print(f"  TEXT   : {repr(printable)}")
            if dport == port:
                client_text += printable + " "
            else:
                server_text += printable + " "
        else:
            # Check for SSH/TLS indicators
            if raw[:4] in (b'\x00\x00\x00', b'SSH-') or raw[0:1] in (b'\x16', b'\x15', b'\x14'):
                is_encrypted = True
            print(f"  TEXT   : [ENCRYPTED / BINARY — cannot read]")

    # ── Final Summary ────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  ANALYSIS SUMMARY")
    print(f"{'='*60}")

    if is_encrypted or not (client_text or server_text):
        print("\n  ✅ RESULT: DATA IS ENCRYPTED")
        print("  This looks like SSH or TLS traffic.")
        print("  An attacker capturing this sees ONLY gibberish.")
        print("  Credentials and commands are NOT recoverable.")
    else:
        print("\n  ⚠️  RESULT: DATA IS IN PLAIN TEXT (Telnet)")
        print("  An attacker capturing this network traffic can see:\n")
        if client_text:
            print(f"  Client sent  : {client_text.strip()}")
        if server_text:
            print(f"  Server sent  : {server_text.strip()[:300]}")
        print("\n  ❌ CONCLUSION: Telnet is INSECURE. Use SSH instead.")

    print(f"\n{'='*60}\n")


# ════════════════════════════════════════════════════════════
#  SECTION 3 — TSHARK WRAPPER (alternative to Scapy capture)
# ════════════════════════════════════════════════════════════

def tshark_capture(port: int, output_file: str, interface: str = "lo", duration: int = 30):
    """Run tshark as a subprocess."""
    cmd = [
        "tshark",
        "-i", interface,
        "-f", f"tcp port {port}",
        "-w", output_file,
        "-a", f"duration:{duration}"
    ]
    print(f"\n[*] Running: {' '.join(cmd)}")
    print(f"[*] Capturing for {duration} seconds on port {port}...")
    print(f"[*] Connect your client now!\n")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 5)
        if result.returncode == 0:
            print(f"[✓] Saved to: {output_file}")
        else:
            print(f"[!] tshark error: {result.stderr}")
    except FileNotFoundError:
        print("[!] tshark not found. Install: sudo apt install tshark")
    except subprocess.TimeoutExpired:
        print("[!] tshark timed out.")


def tshark_read(pcap_file: str):
    """Use tshark to print a summary of a pcap file."""
    print(f"\n[*] tshark summary of {pcap_file}:\n")
    try:
        result = subprocess.run(
            ["tshark", "-r", pcap_file, "-T", "fields",
             "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst",
             "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "tcp.len",
             "-e", "data.text"],
            capture_output=True, text=True
        )
        print(result.stdout or "(no output)")
        if result.stderr:
            print(f"[stderr] {result.stderr[:200]}")
    except FileNotFoundError:
        print("[!] tshark not found.")


# ════════════════════════════════════════════════════════════
#  SECTION 4 — SSH OBSERVATION HELPER
# ════════════════════════════════════════════════════════════

def compare_telnet_vs_ssh(telnet_pcap: str, ssh_pcap: str):
    """Side-by-side comparison of Telnet vs SSH pcap payloads."""
    print(f"\n{'='*60}")
    print(f"  COMPARISON: TELNET vs SSH")
    print(f"{'='*60}")

    for label, pcap_file in [("TELNET", telnet_pcap), ("SSH", ssh_pcap)]:
        if not os.path.exists(pcap_file):
            print(f"\n  [{label}] File not found: {pcap_file} — skipping")
            continue

        pkts = rdpcap(pcap_file)
        payload_pkts = [p for p in pkts if Raw in p and TCP in p]
        total_bytes  = sum(len(p[Raw].load) for p in payload_pkts)
        readable     = []

        for p in payload_pkts:
            try:
                t = p[Raw].load.decode("utf-8", errors="replace")
                t = "".join(c for c in t if c.isprintable()).strip()
                if t:
                    readable.append(t)
            except Exception:
                pass

        print(f"\n  ── {label} ({pcap_file}) ──────────────────────")
        print(f"     Total packets    : {len(pkts)}")
        print(f"     Payload packets  : {len(payload_pkts)}")
        print(f"     Total bytes      : {total_bytes}")
        print(f"     Readable strings : {len(readable)}")
        if readable:
            print(f"     Sample data      : {readable[:3]}")
            print(f"     ⚠️  INSECURE — plaintext visible!")
        else:
            print(f"     ✅ SECURE — no readable data (encrypted)")


# ════════════════════════════════════════════════════════════
#  MAIN — CLI Interface
# ════════════════════════════════════════════════════════════

def print_help():
    print("""
USAGE:
  python3 capture_and_analyze.py <command> [args]

COMMANDS:
  capture  [port] [outfile] [iface]   — Live capture with Scapy
  tshark   [port] [outfile] [iface]   — Live capture with tshark
  analyze  <pcap_file> [port]         — Analyze a saved pcap file
  read     <pcap_file>                — tshark text summary
  compare  <telnet.pcap> <ssh.pcap>   — Side-by-side comparison

EXAMPLES:
  # Capture telnet (port 2323) on loopback
  python3 capture_and_analyze.py capture 2323 telnet.pcap lo

  # Capture SSH (port 22) on loopback
  python3 capture_and_analyze.py capture 22 ssh.pcap lo

  # Analyze captured file
  python3 capture_and_analyze.py analyze telnet.pcap 2323

  # Compare both
  python3 capture_and_analyze.py compare telnet.pcap ssh.pcap

  # Using tshark instead of Scapy for capture
  python3 capture_and_analyze.py tshark 2323 telnet.pcap lo
""")

def main():
    args = sys.argv[1:]

    if not args or args[0] in ("help", "--help", "-h"):
        print_help()
        return

    cmd = args[0]

    if cmd == "capture":
        port      = int(args[1])  if len(args) > 1 else 2323
        outfile   = args[2]       if len(args) > 2 else "telnet_capture.pcap"
        interface = args[3]       if len(args) > 3 else "lo"
        live_capture(port, outfile, interface)

    elif cmd == "tshark":
        port      = int(args[1])  if len(args) > 1 else 2323
        outfile   = args[2]       if len(args) > 2 else "capture.pcap"
        interface = args[3]       if len(args) > 3 else "lo"
        tshark_capture(port, outfile, interface)

    elif cmd == "analyze":
        if len(args) < 2:
            print("[!] Usage: analyze <pcap_file> [port]")
            return
        pcap = args[1]
        port = int(args[2]) if len(args) > 2 else None
        analyze_pcap(pcap, port)

    elif cmd == "read":
        if len(args) < 2:
            print("[!] Usage: read <pcap_file>")
            return
        tshark_read(args[1])

    elif cmd == "compare":
        if len(args) < 3:
            print("[!] Usage: compare <telnet.pcap> <ssh.pcap>")
            return
        compare_telnet_vs_ssh(args[1], args[2])

    else:
        print(f"[!] Unknown command: {cmd}")
        print_help()

if __name__ == "__main__":
    main()