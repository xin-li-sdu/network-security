from scapy.all import*
Qdsec = DNSQR(qname='QwQ.example.com')
dns = DNS(id=0xAAAA, qr=0, qdcount=1, ancount=0, nscount=0,
arcount=0, qd=Qdsec)
ip = IP(dst='10.9.0.53', src='10.9.0.5')
udp = UDP(dport=53, sport=33333, chksum=0)
request = ip/udp/dns
send(request)