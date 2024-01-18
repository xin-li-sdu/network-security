#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

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

static uint16_t compute_checksum(const char *buf, size_t size) {
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

int main(){
    char buffer[2048]; // You can change the buffer size
    memset(buffer, 0, 2048);
    
    // Here you can construct the IP packet using buffer[]
    // - construct the IP header ...
    struct ipheader *ip = (struct ipheader *)buffer;
	ip->iph_ver=4;
	ip->iph_ihl=5;
    ip->iph_ttl = 20;
    ip->iph_sourceip.s_addr = inet_addr("10.0.2.4");
    ip->iph_destip.s_addr = inet_addr("110.242.68.66");
    ip->iph_protocol = IPPROTO_ICMP;

    /* This data structure is needed when sending the packets
    * using sockets. Normally, we need to fill out several
    * fields, but for raw sockets, we only need to fill out
    * this one field */

    // - construct the TCP/UDP/ICMP header ...
    struct icmpheader* icmp = (struct icmpheader*) (buffer + sizeof(*ip));
    icmp->icmp_type = 8;//ICMP_ECHO
    // icmp->icmp_code = 0;
    icmp->icmp_chksum = 0;
    icmp->icmp_chksum = compute_checksum((const char*) icmp, sizeof(*icmp));

    // - fill in the data part if needed ...
    
    ip->iph_len = htons(sizeof(*icmp) + sizeof(*ip));

    send_to(ip);
}