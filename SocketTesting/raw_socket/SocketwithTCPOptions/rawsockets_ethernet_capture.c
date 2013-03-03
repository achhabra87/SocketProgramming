#define __USE_BSD	
#include <sys/socket.h>	
#include <netinet/in.h>	
#include <netinet/ip.h>
#include <arpa/inet.h>
#define __FAVOR_BSD	
#include <netinet/tcp.h>
 
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
 
#include <unistd.h>
#include <time.h>
#include <sys/types.h>

#include <signal.h> 
#include <fcntl.h> 
#include <unistd.h> 
#include <netdb.h>
#include <stdio.h> 


//#include <pcap_lib.h>
#include <pcap.h>
//#include <stdio.h>
//#include <string.h>
//#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
//#include <sys/socket.h>
//#include <netinet/in.h>
//#include <arpa/inet.h>







/*
 *
 * Expression			Description
 * ----------			-----------
 * ip					Capture all IP packets.
 * tcp					Capture only TCP packets.
 * tcp port 80			Capture only TCP packets with a port equal to 80.
 * ip host 10.1.2.3		Capture all IP packets to or from host 10.1.2.3.
 *
 ****************************************************************************
 *
 */
#define PRINTHEADER 0

char buffer[1024]; /* receve buffer */ 
#define APP_NAME		"sniffex"
#define APP_DESC		"Sniffer example using libpcap"
#define APP_COPYRIGHT	"Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."



/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
//#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
print_app_banner(void);

void
print_app_usage(void);

/*
 * app name/banner
 */
void
print_app_banner(void)
{

	printf("%s - %s\n", APP_NAME, APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	printf("%s\n", APP_DISCLAIMER);
	printf("\n");

return;
}

/*
 * print help text
 */
void
print_app_usage(void)
{

	printf("Usage: %s [interface]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");

return;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;
	memcpy(&buffer,packet,sizeof(buffer));
	
	printf("\nPacket number %d:\n", count);
	count++;

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	const u_char *ptr;

	int i;
	ptr = ethernet->ether_dhost;
    	i = ETHER_ADDR_LEN;
	printf(" Ethernet Header\n");
    	printf(" Destination Address:  ");
    	do{
        	printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
    	}while(--i>0);
   	 printf("\n");

    	ptr = ethernet->ether_shost;
    	i = ETHER_ADDR_LEN;
    	printf(" Source Address:  ");
    	do{
        	printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
    	}while(--i>0);
    	printf("\n");






	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

#if PRINTHEADER
	/* print source and destination IP addresses */
	printf("IP Header\n");
	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));
	printf("       Type: %d\n", IP_V(ip));
	printf("   TTL     : %d\n", ip->ip_ttl);
	printf("   CheckSum: 0x%x\n", ntohs(ip->ip_sum));
	
	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		default:
			printf("   Protocol: unknown\n");
			return;
	}
	
	/*OK, this packet is TCP.*/
	
	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	printf("TCP Header\n");
	printf("   Src port: %d\n", ntohs(tcp->th_sport));
	printf("   Dst port: %d\n", ntohs(tcp->th_dport));
	
	printf("   Sequence: %u\n", tcp->th_seq);
	printf("   Ack     : %u\n",tcp->th_ack);
	printf("   DataOff : 0x%x\n", tcp->th_offx2);
	printf("   Urgt Ptr: 0x%x\n", ntohs(tcp->th_urp));
	printf("   Window  : 0x%x\n", ntohs(tcp->th_win));
	printf("   ChkSm   : 0x%x\n", ntohs(tcp->th_sum));


	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	if (size_payload > 0) {
		printf("   Payload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload);
	}
	else
	{
		printf("   Payload not printed\n");
	}
#endif
return;
}

int main_pcap()
{

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "ip";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 1;			/* number of packets to capture */

	 /*find a capture device if not specified on command-line */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n",
		    errbuf);
		exit(EXIT_FAILURE);
	}
	//}
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}




struct tcp_options
{
  u_int8_t op0;
  u_int8_t op1;
  u_int8_t op2;
  u_int8_t op3;
  u_int8_t op4;
  u_int8_t op5;
  u_int8_t op6;
  u_int8_t op7;
  u_int8_t op8;
  u_int8_t op9;
  u_int8_t op10;
  u_int8_t op11;
  u_int8_t op12;
  u_int8_t op13;
  u_int8_t op14;
  u_int8_t op15;
  u_int8_t op16;
  u_int8_t op17;
  u_int8_t op18;
  u_int8_t op19;
};



//MAC Destination of Google.com

#define MY_DEST_MAC0	0x52
#define MY_DEST_MAC1	0x54
#define MY_DEST_MAC2	0x00
#define MY_DEST_MAC3	0x12
#define MY_DEST_MAC4	0x35
#define MY_DEST_MAC5	0x02
 

//525400123502


#define DEFAULT_IF	"eth0"
#define BUF_SIZ		1024
char pheader[1024];
//char buffer[1024]; /* receve buffer */ 


uint16_t  csum (uint16_t * addr, int len)
{
  int nleft = len;
  uint32_t sum = 0;
  uint16_t *w = addr;
  uint16_t answer = 0;

  while( nleft > 1 ) {
    sum += *w++;
    nleft -= 2;
  }
  if (nleft == 1) {
    *(unsigned char *)  (&answer) = *(unsigned char *) w;
    sum += answer;
  }
  sum = (sum >> 16)+(sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;
  return (answer);
}

void printbuffer(char *buffer);
uint16_t ip_checksum(const void *buf, size_t hdr_len)
{
         unsigned long sum = 0;
         const uint16_t *ip1;
 
         ip1 = buf;
         while (hdr_len > 1)
         {
                 sum += *ip1++;
                 if (sum & 0x80000000)
                         sum = (sum & 0xFFFF) + (sum >> 16);
                 hdr_len -= 2;
         }
 
         while (sum >> 16)
                 sum = (sum & 0xFFFF) + (sum >> 16);
 
        return(~sum);
}





int main(int argc, char *argv[])
{
	int sockfd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	
	int tx_len = 0;
	char sendbuf[BUF_SIZ];

	struct ether_header *eh = (struct ether_header *) sendbuf;
	struct ip *iph = (struct ip *) (sendbuf + sizeof(struct ether_header));
	struct tcphdr *tcph = (struct tcphdr *) (sendbuf + sizeof (struct ip) + sizeof(struct ether_header));
  	struct tcp_options *tcpopt = (struct tcp_options *) (sendbuf + sizeof(struct ether_header)+sizeof(struct ip) + sizeof(struct tcphdr));



	struct ether_header *recv_eh = (struct ether_header *) buffer;
	struct ip *recv_iph = (struct ip *) (buffer + sizeof(struct ether_header));
	struct tcphdr *recv_tcph = (struct tcphdr *) (buffer +sizeof(struct ip) + sizeof(struct ether_header));
  	struct tcp_options *recv_tcpopt = (struct tcp_options *) (buffer + sizeof(struct ether_header)+sizeof(struct ip) + sizeof(struct tcphdr));




	struct sockaddr_ll socket_address;
	struct sockaddr_ll recv_socket_address;
	char ifName[IFNAMSIZ];

	char src_ip[17];
	char dst_ip[17];	
	// Source IP address
	snprintf(src_ip,16,"%s","10.0.2.15");  //default
	snprintf(dst_ip,16,"%s","74.125.228.66");  //google
	//snprintf(dst_ip,16,"%s","209.2.227.225");
	//snprintf(dst_ip,16,"%s","74.108.85.43"); // Desitnation
	//snprintf(ds_ip,16,"%s","127.0.0.1"); // Desitnation
	
	short dst_port=80;
	short th_sport=36573;


	short tcp_flags=TH_SYN;
	short pig_ack=0;

	/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);
 
	/* Open RAW socket to send on */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
	    perror("socket");
	}
 
	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
	    perror("SIOCGIFINDEX");
	/* Get the MAC address of the interface to send on */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
	    perror("SIOCGIFHWADDR");
 
	/* Construct the Ethernet header */
	memset(sendbuf, 0, BUF_SIZ);
	/* Ethernet header */
	eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];



	eh->ether_dhost[0] = MY_DEST_MAC0;
	eh->ether_dhost[1] = MY_DEST_MAC1;
	eh->ether_dhost[2] = MY_DEST_MAC2;
	eh->ether_dhost[3] = MY_DEST_MAC3;
	eh->ether_dhost[4] = MY_DEST_MAC4;
	eh->ether_dhost[5] = MY_DEST_MAC5;




	/* Ethertype field */
	eh->ether_type = htons(ETH_P_IP);
	tx_len += sizeof(struct ether_header);
 
	/* Packet data */
	/*
	sendbuf[tx_len++] = 0xde;
	sendbuf[tx_len++] = 0xad;
	sendbuf[tx_len++] = 0xbe;
	sendbuf[tx_len++] = 0xef;
	*/ 

	/* Index of the network device */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	/* Address length*/
	socket_address.sll_halen = ETH_ALEN;
	/* Destination MAC */
	socket_address.sll_addr[0] = MY_DEST_MAC0;
	socket_address.sll_addr[1] = MY_DEST_MAC1;
	socket_address.sll_addr[2] = MY_DEST_MAC2;
	socket_address.sll_addr[3] = MY_DEST_MAC3;
	socket_address.sll_addr[4] = MY_DEST_MAC4;
	socket_address.sll_addr[5] = MY_DEST_MAC5;




	recv_socket_address.sll_ifindex = if_idx.ifr_ifindex;
	/* Address length*/
	recv_socket_address.sll_halen = ETH_ALEN;
	/* Destination MAC */
	recv_socket_address.sll_addr[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	recv_socket_address.sll_addr[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	recv_socket_address.sll_addr[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	recv_socket_address.sll_addr[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	recv_socket_address.sll_addr[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	recv_socket_address.sll_addr[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
 


 


	// IP Headaer
	struct sockaddr_in servaddr;
	servaddr.sin_family = AF_INET;
	inet_pton(AF_INET, dst_ip,&servaddr.sin_addr);
	iph->ip_hl = 5;
	iph->ip_v = 4;
	iph->ip_tos = 0;
	iph->ip_len = htons(sizeof (struct ip) + sizeof (struct tcphdr) + 8 +6 +6);
	//iph->ip_len =sizeof (struct ip) + sizeof (struct tcphdr) + 8 +6 +6;
	int iplen=sizeof (struct ip) + sizeof (struct tcphdr) + 8 +6 +6;
	//iph->ip_len = htons(sizeof (struct ip)) ;
	/* data size = 0, but tcp using option flags */
	iph->ip_id = htons (0);
	iph->ip_off = 0;
	iph->ip_ttl = 64;
	iph->ip_p = 6;
	iph->ip_sum = 0;
	//OLD WAY iph->ip_src.s_addr = inet_addr (src_ip);/* source ip  */
	inet_pton(AF_INET, src_ip, &(iph->ip_src));
	iph->ip_dst.s_addr = servaddr.sin_addr.s_addr;	
	//iph->ip_dst=inet_addr("192.168.0.111");
	tx_len+=sizeof (struct ip);

	iph->ip_sum = csum ((uint16_t *) (iph), iplen);
	


  	int tcphdr_size = sizeof(struct tcphdr);
	//TCP Header
	tcph->th_sport = htons (th_sport); /* source port */
	tcph->th_dport = htons (dst_port); /* destination port */
	tcph->th_seq = htonl(55);
	tcph->th_ack = htonl(pig_ack);/* in first SYN packet, ACK is not present */
	// tcph->th_off = sizeof(struct tcphdr)/4; /* data position in the packet */
	// Special chirico adjustment to give 2x32
	tcph->th_off = 7+2+1 ;
	//tcph->th_off = 7+1 ;

	tcph->th_flags = tcp_flags; /* initial connection request */
	tcph->th_win = htons (65535); /* */
	tcph->th_sum = 0; /* we will compute it later */
	tcph->th_urp = 0;
	if (tcphdr_size % 4 != 0) /* takes care of padding to 32 bits */
	tcphdr_size = ((tcphdr_size % 4) + 1) * 4;
	fprintf(stderr,"tcphdr_size %d\n",tcphdr_size);
	tcphdr_size=40;
	fprintf(stderr,"tcphdr_size %d\n",tcphdr_size);
	tx_len+=sizeof(struct tcphdr);



	// seting SACK permited = true
      tcpopt->op0=0x04;
	  tcpopt->op1=0x02;
	// Setting maximum segment size 16396 -> for localhost
	tcpopt->op2=0x02;
	tcpopt->op3=0x04; 
	tcpopt->op4=0x40;
	tcpopt->op5=0X0C;



	// Setting maximum segment size 1460 -> for localhost
	tcpopt->op2=0x02;
	tcpopt->op3=0x04; 
	tcpopt->op4=0x05;
	tcpopt->op5=0Xb4;
	
	// Time Stamp
	//08 0a 00 34 b3 96 00 34 b2 f2
	tcpopt->op6=0x08;
	tcpopt->op7=0x0a;
	tcpopt->op8=0x00;
	tcpopt->op9=0x34;
	tcpopt->op10=0xb3;
	tcpopt->op11=0x96;
	tcpopt->op12=0x00;
	tcpopt->op13=0x34;
	tcpopt->op14=0xb2;
	tcpopt->op15=0xf2;
	// NOP
	tcpopt->op16=0x01;


	// Window Scaling WS=7
	tcpopt->op17=0x03;
     tcpopt->op18=0x03;
	tcpopt->op19=0x07;
/*	
	// seting SACK permited = true
	tcpopt->op0=0x04;
	tcpopt->op1=0x02;
	// Setting maximum segment size 16396 -> for localhost
	tcpopt->op2=0x02;
	tcpopt->op3=0x04; 
	tcpopt->op4=0x40;
	tcpopt->op5=0X0C;

	tcpopt->op16=0x01;


	tcpopt->op6=0x03;
	tcpopt->op7=0x03;
	tcpopt->op8=0x07;
*//*
	// Window Scaling WS=7
	tcpopt->op17=0x03;
	tcpopt->op18=0x03;
	tcpopt->op19=0x07;
*/
	tx_len+=sizeof(struct tcp_options);
	
	memset(pheader,0x0,sizeof(pheader));
	memcpy(&pheader,&(iph->ip_src.s_addr),4);
	memcpy(&pheader[4],&(iph->ip_dst),4);
	pheader[8]=0; // just to underline this zero byte specified by rfc
	pheader[9]=(u_int16_t)iph->ip_p;
	pheader[10]=(u_int16_t)(tcphdr_size & 0xFF00)>>8;
	pheader[11]=(u_int16_t)(tcphdr_size & 0x00FF);

	memcpy(&pheader[12], tcph, sizeof(struct tcphdr));
	memcpy(&pheader[12+ sizeof(struct tcphdr)], tcpopt, sizeof(struct tcp_options));


	tcph->th_sum = csum ((uint16_t *) (pheader),tcphdr_size+12);
 	//iph->ip_sum = csum ((uint16_t *) (iph), iplen>>1);
	//iph->ip_sum= 0xb9c2;
	//iph->ip_sum=ip_checksum(iph,iplen);
	
	//uint16_t ip_checksum
	int one = 1;
	const int *val = &one;

	/* Send packet */
	if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
	    printf("Send SYN failed\n");

	// seting NOP NOP
	tcpopt->op0=0x00;
	tcpopt->op1=0x00;

	// Time Stamp
	//08 0a 00 34 b3 96 00 34 b2 f2
	/*
	tcpopt->op2=recv_tcpopt->op6;
	tcpopt->op3=recv_tcpopt->op7;
	tcpopt->op4=recv_tcpopt->op8;
	tcpopt->op5=recv_tcpopt->op9;
	tcpopt->op6=recv_tcpopt->op10;
	tcpopt->op7=recv_tcpopt->op11;
	tcpopt->op8=recv_tcpopt->op12;
	tcpopt->op9=recv_tcpopt->op13;
	tcpopt->op10=recv_tcpopt->op14;
	tcpopt->op11=recv_tcpopt->op15;
	*/
	tcpopt->op2=0x00;
	tcpopt->op3=0x00;
	tcpopt->op4=0x00;
	tcpopt->op5=0x00;
	tcpopt->op6=0x00;
	tcpopt->op7=0x00;
	tcpopt->op8=0x00;
	tcpopt->op9=0x00;
	tcpopt->op10=0x00;
	tcpopt->op11=0x00;
		tcpopt->op12=0x00;
	tcpopt->op13=0x00;
	tcpopt->op14=0x00;
	tcpopt->op15=0x00;
	tcpopt->op16=0x00;
	tcpopt->op17=0x00;
	tcpopt->op18=0x00;
	tcpopt->op19=0x00;






	int dd = main_pcap();
	//printbuffer(buffer);

	printf("   Ack     :0x%x\n",ntohl(recv_tcph->th_ack));
	tcph->th_seq = htonl(ntohl(tcph->th_seq)+1);
	tcph->th_ack = htonl(ntohl(recv_tcph->th_seq)+1);
	iph->ip_id=htons(ntohl(iph->ip_id)+1);
	iph->ip_len=htons(sizeof (struct ip) + sizeof (struct tcphdr));
	tcph->th_off = 5;
	tcph->th_flags = 0x10;
	//tcph->th_win = htons (32896+128);
	tcph->th_win = htons(ntohs(recv_tcph->th_win));

	
	iph->ip_sum = csum ((uint16_t *) (iph), (sizeof (struct ip) + sizeof (struct tcphdr)));
	iph->ip_sum =0x0140;
	if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
	    printf("Send ACK failed\n");
	else
	{
		printf("sent\n");
	}






	


	return 0;
}




void printbuffer(char *buffer)
{


	struct ether_header *eh = (struct ether_header *) buffer;
	struct ip *ip = (struct ip *) (buffer + sizeof(struct ether_header));
	struct tcphdr *tcp = (struct tcphdr *) (buffer + sizeof(struct ip) + sizeof(struct ether_header));
  	struct tcp_options *tcpopt = (struct tcp_options *) (buffer + sizeof(struct ether_header)+sizeof(struct ip) + sizeof(struct tcphdr));


	int i;
	const u_char *ptr;
	ptr = eh->ether_dhost;
    	i = ETHER_ADDR_LEN;
	printf(" Ethernet Header\n");
    	printf(" Destination Address:  ");
    	do{
        	printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
    	}while(--i>0);
   	 printf("\n");

    	ptr = eh->ether_shost;
    	i = ETHER_ADDR_LEN;
    	printf(" Source Address:  ");
    	do{
        	printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
    	}while(--i>0);
    	printf("\n");


	
	// print source and destination IP addresses 
	printf("IP Header\n");
	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	 


	printf("   TTL     : %d\n", ip->ip_ttl);
	printf("   CheckSum: 0x%x\n", ntohs(ip->ip_sum));




		printf("TCP Header\n");
	printf("   Src port: %d\n", ntohs(tcp->th_sport));
	printf("   Dst port: %d\n", ntohs(tcp->th_dport));

	printf("   Sequence:0x%x\n", ntohl(tcp->th_seq));
	printf("   Ack     :0x%x\n",ntohl(tcp->th_ack));
	printf("   DataOx2: 0x%x\n", tcp->th_x2);
	printf("   DataOff : 0x%x\n", tcp->th_off);
	printf("   Urgt Ptr: 0x%x\n", ntohs(tcp->th_urp));
	printf("   Window  : 0x%x\n", ntohs(tcp->th_win));
	printf("   ChkSm   : 0x%x\n", ntohs(tcp->th_sum));
	printf("   Flags   : 0x%x\n", tcp->th_flags);

}
