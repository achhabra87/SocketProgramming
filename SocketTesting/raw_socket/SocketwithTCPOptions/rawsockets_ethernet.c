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
 
#define DEFAULT_IF	"eth0"
#define BUF_SIZ		1024
char pheader[1024];
char buffer[1024]; /* receve buffer */ 


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
	snprintf(dst_ip,16,"%s","74.125.228.66");  //default
	short dst_port=80;
	short th_sport=56573;
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
	tcph->th_seq = htonl(0);
	tcph->th_ack = htonl(pig_ack);/* in first SYN packet, ACK is not present */
	// tcph->th_off = sizeof(struct tcphdr)/4; /* data position in the packet */
	// Special chirico adjustment to give 2x32
	tcph->th_off = 7+2+1 ;
	//tcph->th_off = 7+1 ;

	tcph->th_flags = tcp_flags; /* initial connection request */
	tcph->th_win = htons (32896); /* */
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

	
	/* tcpopt->op0=4;   sackOK 
	tcpopt->op1=2;
	*/
	memcpy(&pheader[12], tcph, sizeof(struct tcphdr));
	memcpy(&pheader[12+ sizeof(struct tcphdr)], tcpopt, sizeof(struct tcp_options));


	tcph->th_sum = csum ((uint16_t *) (pheader),tcphdr_size+12);
 	//iph->ip_sum = csum ((uint16_t *) (iph), iplen>>1);
	//iph->ip_sum= 0xb9c2;
	//iph->ip_sum=ip_checksum(iph,iplen);
	
	//uint16_t ip_checksum
	int one = 1;
	const int *val = &one;
	
	/*
	if(setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, val, sizeof(one))<0)
	{	
		printf("setsockopt failed!\n");
	}
	*/





	
	/* Send packet */
	if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
	    printf("Send SYN failed\n");

	
	struct sockaddr_in serveraddr;

	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family      = AF_INET;
	serveraddr.sin_port        = htons(dst_port);
	serveraddr.sin_addr.s_addr = inet_addr(dst_ip);
	//serveraddr.sin_port        = htons(th_sport);
	//serveraddr.sin_addr.s_addr = inet_addr(src_ip);
	int    serveraddrlen = sizeof(serveraddr);


	int rc = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
	
	if (rc < 0)
	{
	perror("recvfrom() failed");
	}


	// no need to accept(), just recvfrom():













	//recv(sockfd, buffer, sizeof(buffer), 0); //receving packet
	//printbuffer(buffer);


	printf("   Ack     :0x%x\n",ntohl(recv_tcph->th_ack));
	tcph->th_seq = htonl(31337+1);
	tcph->th_ack = htonl(ntohl(recv_tcph->th_seq)+1);
	iph->ip_id=iph->ip_id+1;
	iph->ip_len=52;
	tcph->th_off = 7+1;
	tcph->th_flags = 0x10;
	//tcph->th_win = htons (32896+128);
	tcph->th_win = htons(ntohs(recv_tcph->th_win));

	// seting NOP NOP
	tcpopt->op0=0x01;
	tcpopt->op1=0x01;

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
	
	if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
	    printf("Send ACK failed\n");






	


	return 0;
}




void printbuffer(char *buffer)
{


	struct ether_header *eh = (struct ether_header *) buffer;
	struct ip *ip = (struct ip *) (buffer + sizeof(struct ether_header));
	struct tcphdr *tcp = (struct tcphdr *) (buffer + sizeof(struct ip) + sizeof(struct ether_header));
  	struct tcp_options *tcpopt = (struct tcp_options *) (buffer + sizeof(struct ether_header)+sizeof(struct ip) + sizeof(struct tcphdr));


	
	// print source and destination IP addresses 
	printf("IP Header\n");
	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	 


	printf("   TTL     : %d\n", ip->ip_ttl);
	printf("   CheckSum: 0x%x\n", ntohs(ip->ip_sum));




		printf("TCP Header\n");
	printf("   Src port: %d\n", ntohs(tcp->th_sport));
	printf("   Dst port: %d\n", ntohs(tcp->th_dport));

	printf("   Sequence:0x%x\n", ntohs(tcp->th_seq));
	printf("   Ack     :0x%x\n",ntohs(tcp->th_ack));
	printf("   DataOx2: 0x%x\n", tcp->th_x2);
	printf("   DataOff : 0x%x\n", tcp->th_off);
	printf("   Urgt Ptr: 0x%x\n", ntohs(tcp->th_urp));
	printf("   Window  : 0x%x\n", ntohs(tcp->th_win));
	printf("   ChkSm   : 0x%x\n", ntohs(tcp->th_sum));
	printf("   Flags   : 0x%x\n", tcp->th_flags);

}
