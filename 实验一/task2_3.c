#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

/* ICMP Header  */
struct icmpheader {
  unsigned char icmp_type; // ICMP message type
  unsigned char icmp_code; // Error code
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int icmp_id;     //Used for identifying request
  unsigned short int icmp_seq;    //Sequence number
};

void send_to(struct ipheader* ip){
    int sd;
    struct sockaddr_in sin;
    /* Create a raw socket with IP protocol. The IPPROTO_RAW parameter
    * tells the sytem that the IP header is already included;
    * this prevents the OS from adding another IP header. */
    sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sd < 0) {
        perror("socket() error"); exit(-1);
    }
    int enable = 1;
    setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    sin.sin_family = AF_INET;
    sin.sin_addr = ip->iph_destip;

    // Note: you should pay attention to the network/host byte order.
    /* Send out the IP packet.
    * ip_len is the actual size of the packet. */
    if(sendto(sd, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto() error"); exit(-1);
    }
}

static uint16_t compute_checksum(const unsigned char *buf, size_t size) {
    size_t i;
    uint64_t sum = 0;

    for (i = 0; i < size; i += 2) {
        sum += *(uint16_t *)buf;
        buf += 2;
    }
    if (size - i > 0) {
        sum += *(uint8_t *)buf;
    }

    while ((sum >> 16) != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return (uint16_t)~sum;
}

void spoof(struct ipheader* ip){
    unsigned char buf[1024];
    memset(buf, 0, 1024);
    memcpy(buf, ip, ntohs(ip->iph_len));
    struct ipheader* ip_new = (struct ipheader*) buf;
    struct icmpheader* icmp_new = (struct icmpheader*) (buf + ip->iph_ihl * 4);

    ip_new->iph_sourceip = ip->iph_destip;
    ip_new->iph_destip = ip->iph_sourceip;
    ip_new->iph_ttl = 20;

    icmp_new->icmp_type = 0;
    // icmp_new->icmp_chksum = icmp_new->icmp_chksum;
    icmp_new->icmp_chksum = 0;
    icmp_new->icmp_chksum = compute_checksum((const unsigned char*)icmp_new, ntohs(ip_new->iph_len) - sizeof(*ip));
    printf("seq = %d, checksum = %x\n",icmp_new->icmp_seq, icmp_new->icmp_chksum);
    
    send_to(ip_new);
}

void sniff(unsigned char *args, const struct pcap_pkthdr *header,
    const unsigned char *packet)
{
    struct ethheader* eth = (struct ethheader*) packet;
    if(ntohs(eth->ether_type) == 0x0800){// 0x0800 is IPv4 type
        struct ipheader* ip = (struct ipheader*) (packet+sizeof(*eth));
    	    /* determine protocol */
        switch(ip->iph_protocol) {                                 
            case IPPROTO_ICMP:{
                struct icmpheader* icmp = (struct icmpheader*)(packet + sizeof(*eth) + sizeof(*ip)); 
                if(icmp->icmp_type == 8){
                    printf("From: %s\n", inet_ntoa(ip->iph_sourceip));   
                    printf("  To: %s\n\n", inet_ntoa(ip->iph_destip));
                    spoof(ip);
                }
                return;
            }
            default:
                // printf("   Protocol: others\n\n");
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
    char filter_exp[] = "icmp[icmp_type] = 8";
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
    pcap_loop(handle, -1, sniff, NULL);
    
    pcap_close(handle); //Close the handle
    return 0;
}