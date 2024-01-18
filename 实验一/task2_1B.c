#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
/* This function will be invoked by pcap for each captured packet.
    We can process each packet inside the function.
*/
void got_packet(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet)
{
    u_short* eth_type = (u_short*)(packet+12);//eth type
    u_char * ip_head = (u_char*)(packet+14);
    if(ntohs(*eth_type) == 0x0800){// 0x0800 is IPv4 type
    	struct in_addr* src_ip =  (struct in_addr*) (ip_head + 12);
    	struct in_addr* dst_ip =  (struct in_addr*) (ip_head + 16);
    	printf("From: %s\n", inet_ntoa(*src_ip));   
    	printf("  To: %s\n", inet_ntoa(*dst_ip));
    	printf("\n");  
    }
}
int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
//    char filter_exp[] = "icmp and src host 10.0.2.4 and dst host 10.0.2.15";
    char filter_exp[] = "tcp and dst portrange 10-100";
    bpf_u_int32 net;
    
    // Step 1: Open live pcap session on NIC with name eth3.
    //         Students need to change "eth3" to the name found on their own
    //         machines (using ifconfig). The interface to the 10.9.0.0/24
    //         network has a prefix "br-" (if the container setup is used).
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    
    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) !=0) {
    }
    
    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);
    
    pcap_close(handle); //Close the handle
    return 0;
}

