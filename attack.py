from scapy.all import IP, TCP, send
import random
import requests
# Target IP and port to flood
target_ip = "172.19.45.90"  # Replace with your target IP

def send_http_request(ip, port):
    url = f"http://{ip}:{port}/"
    try:
        response = requests.get(url)
        print(f"Sent GET request to {url}. Status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error sending request to {url}: {e}")

# Send SYN packets
for target_port in range(1, 1023):
    for _ in range(1):

    # Create IP and TCP layers
        ip = IP(dst=target_ip)
        tcp = TCP(dport=target_port, flags="S", seq=1)
   
       # Send the packet
        send_http_request(target_ip, target_port)
        #send(ip/tcp, verbose=False)
        print(f"Sent SYN packet to {target_ip}:{target_port}")










    
