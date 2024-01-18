#!/usr/bin/python3
from scapy.all import *

def Traceroute(dst, ttl = 30):
    ans, unans = sr(IP(dst = dst,ttl = (1,ttl)) / ICMP())
    for ttl, ip in ans:
        print(ttl.ttl, ip.src)
        
Traceroute('baidu.com')
