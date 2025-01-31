Linux commands:

# Show all packets
sudo tcpdump -i eth0

# Show packets with SYN flags
tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0'
The reason you can't simply check pkt[TCP].flags == 'S', is that pkt[TCP].flags is an integer, not a string. The TCP flags field is a bitwise combination of multiple flags, not a single-character string.

# Add iptables rule
iptables -A INPUT -s <ip> -j DROP

# Delete iptables rule
iptables -D INPUT -s <ip> -j DROP

# List out iptables rules
iptables -L -n -v

# Flush all iptables rules
iptables -F
