from scapy.all import sniff, TCP, IP
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import threading
import subprocess
import time

# Configuration Constants
RENEW_TIME = 60 * 10         # Time window to reset state (10 minutes)
MAX_ATTEMPTS = 10            # Max unique ports to trigger blocking
MAX_WORKERS = 100            # Number of concurrent threads

# Shared State
PacketDict = defaultdict(lambda: {'ports': set(), 'timestamp': None})
lock = threading.Lock()
executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)


# IP Block/Unblock Functions
def verify_block(src_ip):
    res = subprocess.run(["iptables", "-L", "-v", "-n"], capture_output=True, text=True)
    return src_ip in res.stdout

def block_ip(src_ip):
    if verify_block(src_ip):
        print(f"[+] IP {src_ip} is already blocked.")
        return
    print(f"[!] Blocking IP {src_ip}")
    subprocess.run(["iptables", "-A", "OUTPUT", "-d", src_ip, "-j", "DROP"])

def unblock_ip(src_ip):
    if not verify_block(src_ip):
        print(f"[+] IP {src_ip} is not currently blocked.")
        return
    print(f"[~] Unblocking IP {src_ip}")
    subprocess.run(["iptables", "-D", "OUTPUT", "-d", src_ip, "-j", "DROP"])


# Packet Processing Logic
def checkpacket(packet):
    if not packet.haslayer(TCP) or not packet.haslayer(IP):
        return
    if not packet[TCP].flags & 0x02:  # Only SYN packets
        return

    src_ip = packet[IP].src
    dest_port = packet[TCP].dport

    with lock:
        data = PacketDict[src_ip]

        # If timestamp expired, reset data
        current_time = time.time()
        if data["timestamp"] and data["timestamp"] + RENEW_TIME < current_time:
            print(f"[~] Resetting data for IP {src_ip}")
            data["ports"].clear()
            data["timestamp"] = current_time
            unblock_ip(src_ip)

        # Initialize timestamp if not set
        if data["timestamp"] is None:
            data["timestamp"] = current_time

        # Record the destination port
        data["ports"].add(dest_port)
        print(f"[>] IP {src_ip} attempted port {dest_port} (seen {len(data['ports'])})")

        # Check for blocking condition
        if len(data["ports"]) > MAX_ATTEMPTS:
            print(f"[X] IP {src_ip} exceeded port scan limit. Blocking.")
            block_ip(src_ip)


# Threaded Packet Entry Point
def process_packet(packet):
    executor.submit(checkpacket, packet)


# Main Loop
if __name__ == "__main__":
    print("🔍 Starting SYN Flood Detection Firewall...")
    try:
        sniff(filter="tcp", prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\n🛑 Stopping... Cleaning up.")
        executor.shutdown(wait=True)
