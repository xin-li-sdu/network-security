#!/usr/bin/env python3
from scapy.all import *

# Construct the DNS header and payload
name = 'aaaaa.example.com'
Qdsec = DNSQR(qname=name)
# Anssec = DNSRR(rrname=name, type='A', rdata='1.1.2.2', ttl=259200)
dns = DNS(id=0xAAAA, qr=0,
          qdcount=1, qd=Qdsec)

# Construct the IP, UDP headers, and the entire packet
ip = IP(dst='10.9.0.53', src='10.9.0.5', chksum=0)
udp = UDP(dport=53, sport=12345, chksum=0)
pkt = ip/udp/dns

# Save the packet to a file
with open('ip_req.bin', 'wb') as f:
    f.write(bytes(pkt))