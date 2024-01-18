#!/usr/bin/python3
from scapy.all import *

# Scapy Spoofing

ID = 1001
len1 = 16
len2 = 16
len3 = 16
## First Fragment

payload = "A" * len1

udp = UDP(sport=7070, dport=9090)
udp.len = 8 + len1 + len2 + len3 -8
ip = IP(src="1.2.3.4", dst="10.0.2.15") 
ip.id = ID
ip.frag = 0
ip.flags = 1
pkt1 = ip/udp/payload
pkt1[UDP].chksum = 0

## Second Fragment

payload = "B" * len2

ip.frag = 2
ip.flags = 1
ip.proto = 17
pkt2 = ip/payload

## Third Fragment

payload = "C" * len3

ip.frag = 4
ip.flags = 0
ip.proto = 17
pkt3 = ip/payload


send(pkt1,verbose=0)
send(pkt2,verbose=0)
send(pkt3,verbose=0)

print("Finish Sending Packets!")