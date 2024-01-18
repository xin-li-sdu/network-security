from scapy.all import *
ip = IP(src='10.0.2.3', dst='192.168.60.5')
send(ip)

ip = IP(src='192.168.60.4', dst='192.168.60.5')
send(ip)

ip = IP(src='1.2.3.4', dst='192.168.60.5')
send(ip)
