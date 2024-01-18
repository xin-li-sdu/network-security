#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
/* Ethernet header */
struct ethheader {
    unsigned char  ether_dhost[6]; /* destination host address */
    unsigned char  ether_shost[6]; /* source host address */
    unsigned short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4, //IP header length
                       iph_ver:4; //IP version
    unsigned char      iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag:3, //Fragmentation flags
                       iph_offset:13; //Flags offset
    unsigned char      iph_ttl; //Time to Live
    unsigned char      iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct  in_addr    iph_sourceip; //Source IP address
    struct  in_addr    iph_destip;   //Destination IP address
};
/* TCP header */
typedef unsigned int tcp_seq;

struct sniff_tcp {
	unsigned short th_sport;	/* source port */
	unsigned short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	unsigned char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	unsigned char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	unsigned short th_win;		/* window */
	unsigned short th_sum;		/* checksum */
	unsigned short th_urp;		/* urgent pointer */
};



/* This function will be invoked by pcap for each captured packet.
    We can process each packet inside the function.
*/
void got_packet(unsigned char *args, const struct pcap_pkthdr *header,
    const unsigned char *packet)
{
    struct ethheader* eth = (struct ethheader*) packet;
    if(ntohs(eth->ether_type) == 0x0800){// 0x0800 is IPv4 type
        struct ipheader* ip = (struct ipheader*) (packet+sizeof(*eth));
    	    /* determine protocol */
        switch(ip->iph_protocol) {                                 
            case IPPROTO_TCP:{
                struct sniff_tcp* tcp = (struct sniff_tcp*)(packet + sizeof(*eth) + sizeof(*ip)); 

                int payload_len = ntohs(ip->iph_len) - (sizeof(*ip) + TH_OFF(tcp)*4);
                __u_char *payload = (__u_char*) (packet + sizeof(*eth) + sizeof(*ip) + TH_OFF(tcp)*4);
                if(payload_len != 0){
                    printf("From: %s, port:%d \n", inet_ntoa(ip->iph_sourceip),ntohs(tcp->th_sport));   
                    printf("  To: %s, port:%d\n", inet_ntoa(ip->iph_destip),ntohs(tcp->th_dport));
                    printf("\n"); 
                    printf("Payload:\n");
                    for(int i = 0; i < payload_len; i ++){
                        // if(isprint(payload[i])){
                            printf("%c",payload[i]);
                        // }
                    }
                    printf("\n____________________________________________\n");
                }
                return;
            }
            default:
                printf("   Protocol: others\n\n");
                return;
        }
    }
}
int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
//    char filter_exp[] = "icmp and src host 10.0.2.4 and dst host 10.0.2.15";
    char filter_exp[] = "tcp";
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

