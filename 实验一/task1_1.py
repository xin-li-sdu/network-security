#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
    return pkt.summary()
    #pkt.show()
#pkt = sniff(iface = 'br-fd88467e4c1d',filter='icmp', prn=print_pkt)
#pkt = sniff(filter='icmp', prn=print_pkt)
#pkt = sniff(filter='tcp and src host 10.0.2.12 and dst port 23', prn=print_pkt)
pkt = sniff(filter='net 128.230.0.0/16', prn=print_pkt)
print(pkt)
