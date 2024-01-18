from scapy.all import *

def spoof(pkt):
    ip = pkt[IP]
    ip.src,ip.dst = pkt[IP].dst,pkt[IP].src
    
    icmp = pkt[ICMP]
    icmp.type = 0
    del pkt[ICMP].chksum
    
    new_pkt = ip/icmp
    print(new_pkt.summary())
    new_pkt.show()
    send(new_pkt)
    
pkt = sniff(filter = 'icmp[icmptype]==icmp-echo and src host 10.0.2.4', prn = spoof)
