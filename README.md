## PortShield: A SYN Flood Protection Firewall

This script is designed to monitor network traffic for potential **SYN Flood attacks** and block malicious IPs by inspecting incoming **SYN packets**. SYN Flood attacks are a form of **Denial of Service (DoS)** attack where attackers send a large number of SYN packets to overwhelm a system’s resources.

### 3-Way Handshake Overview

The **3-Way Handshake** is the process that establishes a TCP connection between a client and server:
![3-Way Handshake.png](https://github.com/user-attachments/assets/db256268-69c0-4aa6-83c3-4aff068b938a)

1. **SYN**: The client sends a SYN packet to initiate the connection.
2. **SYN-ACK**: The server responds with a SYN-ACK to acknowledge the request.
3. **ACK**: The client sends an ACK to complete the handshake, establishing the connection.

### How SYN Packets Are Abused by Hackers
Hackers can manipulate SYN packets to launch a SYN Flood attack:

1. **SYN Flood**: The attacker sends numerous SYN packets, often with spoofed source IPs. The target server responds with SYN-ACK but never receives the final ACK, leaving connections half-open and consuming system resources. This can crash the server or cause it to become unresponsive.

2. **SYN attacks** also reveal open ports on your server. When an attacker sends SYN packets to your IP address and receives a SYN-ACK response, they can infer that a port is open and reachable. Once they know which ports are exposed, these can be targeted for further attacks, such as buffer overflow or Brute Force attempts.

By detecting and blocking suspicious IPs based on excessive SYN packets, this firewall not only prevents system resource exhaustion but also limits the exposure of open ports that could later be exploited.

This Python script uses **Scapy** and **iptables** to monitor TCP connections and block IP addresses exhibiting malicious behavior (e.g., multiple port access within a short time). It checks for SYN packets and blocks IPs that exceed a threshold of port attempts.

### Features:
- Monitor network traffic for incoming SYN packets.
- Block IP addresses that access multiple ports within a short time.
- Unblock IP addresses after a certain timeout.
- Utilizes **iptables** to manage firewall rules and block/unblock IPs.
- Customizable timeout and port threshold settings.

---

## Requirements
- **Python 3.x**
- **Scapy**: Used for sniffing network packets.
- **iptables**: Used to block/unblock IPs by adding/removing rules.
- **sudo privileges**: Required for modifying `iptables` rules.
- **requests**: For HTTP requests.

### Install Dependencies
1. **Clone the repo**:
    ```bash
    git clone https://github.com/Danish811/PortShield.git
    ```
1. **Install necessary Python packages**:
    ```bash
    pip install scapy requests
    ```

2. **Ensure `iptables` is installed** (most Linux distros come with it by default):
    ```bash
    sudo apt install iptables
    ```

---

## Configuration

### Default settings:
- **RENEW_TIME**: 600 seconds (10 minutes). The timeout after which blocked IPs can be unblocked.
- **MAX_ATTEMPTS**: 10 attempts, after which the IP is blocked.

You can modify these variables to customize the script’s behavior.

---

## How It Works

1. **Packet sniffing**: The script listens for incoming SYN packets on all TCP connections.
   
2. **Blocking IP**: If an IP makes attempts to access more than 10 ports within `RENEW_TIME`, that IP is blocked using `iptables`. The outgoing traffic to/from that IP will be dropped.

3. **Unblocking IP**: If the IP's activity falls below the threshold (i.e., after `RENEW_TIME`), it will be unblocked and allowed to send traffic again.

4. **Verifying if an IP is blocked**: The script can check if an IP is currently blocked by querying `iptables`.

---

## Running the Script

### 1. **Start the script**:

   Run the script using Python:

   ```bash
   python3 main.py
   ```

   The script will start monitoring TCP SYN packets and automatically block IPs that violate the port attempt rule.

### 2. **Permissions for `iptables`**:

   Since `iptables` requires root privileges to modify the firewall, ensure you have the necessary permissions.

   - Use `sudo` to run the script as root:
     ```bash
     sudo python3 main.py
     ```

---

## Customizing the Script

### **Variables**:
- **RENEW_TIME**: The time in seconds before the ports list is reset. Change it to adjust the unblocking interval.
- **MAX_ATTEMPTS**: The number of unique ports an IP can try to connect to before being blocked. You can modify this to your desired threshold.

### **Functions**:

- **block_ip(src_ip)**: Blocks the IP address by adding a rule to `iptables`.
- **unblock_ip(src_ip)**: Unblocks the IP address by removing the blocking rule from `iptables`.
- **verify_block(src_ip)**: Checks if the IP address is currently blocked.
- **display_rules()**: Prints out the current `iptables` rules for reference.

---

## Troubleshooting

- **Permission issues**: If you encounter `sudo: iptables: command not found`, make sure `iptables` is installed on your system.

    Install it via:
    ```bash
    sudo apt install iptables
    ```

- **KeyError when unblocking IP**: If you get an error like `KeyError: '172.19.32.1'`, it might mean that the IP is not in the `BlockedIPs` set. This can happen if the IP was not blocked in the first place. Ensure that the IP is present in `BlockedIPs` before trying to unblock it.

- **iptables errors**: If `iptables` reports errors like `No such file or directory`, ensure that `iptables` is properly installed and configured for your system. You might need to switch to `iptables-legacy` if you're using a distribution that defaults to `nftables`.

---

