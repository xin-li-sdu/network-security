#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
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
/* UDP Header */
struct udpheader
{
  u_int16_t udp_sport;           /* source port */
  u_int16_t udp_dport;           /* destination port */
  u_int16_t udp_ulen;            /* udp length */
  u_int16_t udp_sum;             /* udp checksum */
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

int main(){
    char buffer[2048]; // You can change the buffer size
    memset(buffer, 0, 2048);
    
    // Here you can construct the IP packet using buffer[]
    // - construct the IP header ...
    struct ipheader *ip = (struct ipheader *)buffer;
	ip->iph_ver=4;
	ip->iph_ihl=5;
    ip->iph_ttl = 20;
    ip->iph_sourceip.s_addr = inet_addr("1.1.1.1");
    ip->iph_destip.s_addr = inet_addr("10.0.2.4");
    ip->iph_protocol = IPPROTO_UDP;

    /* This data structure is needed when sending the packets
    * using sockets. Normally, we need to fill out several
    * fields, but for raw sockets, we only need to fill out
    * this one field */

    // - construct the TCP/UDP/ICMP header ...
    struct udpheader *udp = (struct udpheader *)(buffer + sizeof(*ip));
    udp->udp_sport = htons(12345);
    udp->udp_dport = htons(8080);
    // udp->udp_sum = 0;

    // - fill in the data part if needed ...
    char *payload = (char*) (buffer + sizeof(struct ipheader) + sizeof(struct udpheader));
    const char* msg = "Test spoof. OwO";
    memcpy(payload, msg, strlen(msg));
    udp->udp_ulen = htons(sizeof(*udp) + strlen(msg));
    udp->udp_sum = 0;
    ip->iph_len = htons(sizeof(*udp) + strlen(msg) + sizeof(*ip));

    send_to(ip);
}