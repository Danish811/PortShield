Linux commands:
sudo tcpdump -i eth0

The reason you can't simply check pkt[TCP].flags == 'S', is that pkt[TCP].flags is an integer, not a string. The TCP flags field is a bitwise combination of multiple flags, not a single-character string.

