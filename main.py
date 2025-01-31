from scapy.all import sniff,TCP,IP
from collections import defaultdict
import os
import subprocess
import time
import threading

RENEW_TIME = 60 * 10
MAX_ATTEMPTS = 10
PacketDict = defaultdict(lambda: {'ports': set(), 'timestamp': None})


def verify_block(src_ip):
    res = subprocess.run(["iptables", "-L", "-v", "-n"], capture_output=True,text=True)
    is_blocked = src_ip in res.stdout
    return is_blocked

def unblock_ip(src_ip):
    if not verify_block(src_ip):
        print(f"IP {src_ip} is not in BlockedIPs. No action taken.")
        return
    
    print(f"Unblocking {src_ip}...")
    subprocess.run(["iptables", "-D", "OUTPUT", "-d" , src_ip ,"-j" ,"DROP"])


def block_ip(src_ip):
    if verify_block(src_ip):
        print(f"IP {src_ip} is already blocked. No action taken.")
        return 
    print(f"Blocking {src_ip}...")
    subprocess.run(["iptables", "-A", "OUTPUT", "-d" , src_ip, "-j", "DROP"]) # To block all outgoing responses to a specific IP


def checkpacket(packet):
    if not packet[TCP].flags & 0x02: # 0x02 is the SYN flag
        return
          
    src_ip = packet[IP].src
    dest_port = packet[TCP].dport
    
    if src_ip not in PacketDict:
        print(f"New IP {src_ip} detected. Adding port {dest_port}")
        PacketDict[src_ip]["ports"].add(dest_port)
        PacketDict[src_ip]["timestamp"] = time.time()
        return
    
    if src_ip in PacketDict:

        if PacketDict[src_ip]["timestamp"] + RENEW_TIME < time.time():
            print(f"Time expired for IP {src_ip}. Renewing ports data.")
            PacketDict[src_ip]["ports"].clear()
            PacketDict[src_ip]["timestamp"] = time.time()
            unblock_ip(src_ip)
            return 
        
        print(f"IP: {src_ip} tried to access {dest_port}")
        PacketDict[src_ip]["ports"].add(dest_port)
        if len(PacketDict[src_ip]["ports"]) > 10:
            print(f"IP {src_ip} exceeded the port limit. Blocking the IP.")
            block_ip(src_ip)

    
def process_packet(packet):
    # Handle each packet in a separate thread
    thread = threading.Thread(target=checkpacket, args=(packet,))
    thread.start()
    
if __name__ == "__main__":
    print("Starting packet sniffing...")
    sniff(filter="tcp", prn=process_packet, store=False)


    
