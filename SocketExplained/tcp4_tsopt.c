/*  Copyright (C) 2011  P.D. Buchan (pdbuchan@yahoo.com)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

// Send an IPv4 TCP packet via raw socket at the link layer (ethernet frame).
// Need to have destination MAC address.
// Values set for SYN packet with two TCP options: set maximum
// segment size, and provide TCP timestamp.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()

#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket()
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_TCP
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#define __FAVOR_BSD           // Use BSD format of tcp header
#include <netinet/tcp.h>      // struct tcphdr
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>

#include <errno.h>            // errno, perror()
#include <pcap.h>
#include <sys/time.h>
// Define some constants.
#define IP4_HDRLEN 20         // IPv4 header length
#define TCP_HDRLEN 20         // TCP header length, excludes options data

//3502
#define MAC_ADDR0 0x52
#define MAC_ADDR1 0x54
#define MAC_ADDR2 0x00
#define MAC_ADDR3 0x12
#define MAC_ADDR4 0x35
#define MAC_ADDR5 0x02



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









// Function prototypes
unsigned short int checksum (unsigned short int *, int);
unsigned short int tcp4_checksum (struct ip, struct tcphdr, unsigned char *, int);

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_payload(const u_char *payload, int len);
void print_hex_ascii_line(const u_char *payload, int len, int offset);
void print_app_banner(void);
void print_app_usage(void);
int main_pcap(void);
void printbuffer(char *buffer);


int
main (int argc, char **argv)
{
  int i, c, status, frame_length, sd, bytes, *ip_flags, nopt, *opt_len, buf_len;
  char *interface, *target, *src_ip, *dst_ip;
  struct ip iphdr;
  struct tcphdr tcphdr;
  unsigned char *tcp_flags, *src_mac, *dst_mac, *ether_frame;
  unsigned char **options, *opt_buffer;
  struct addrinfo hints, *res;
  struct sockaddr_in *ipv4;
  struct sockaddr_ll device;
  struct ifreq ifr;
  void *tmp;

// Allocate memory for various arrays.

  tmp = (unsigned char *) malloc (6 * sizeof (unsigned char));
  if (tmp != NULL) {
    src_mac = tmp;
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array 'src_mac'.\n");
    exit (EXIT_FAILURE);
  }
  memset (src_mac, 0, 6 * sizeof (unsigned char));

  tmp = (unsigned char *) malloc (6 * sizeof (unsigned char));
  if (tmp != NULL) {
    dst_mac = tmp;
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array 'dst_mac'.\n");
    exit (EXIT_FAILURE);
  }
  memset (dst_mac, 0, 6 * sizeof (unsigned char));

  tmp = (unsigned char *) malloc (IP_MAXPACKET * sizeof (unsigned char));
  if (tmp != NULL) {
    ether_frame = tmp;
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array 'ether_frame'.\n");
    exit (EXIT_FAILURE);
  }
  memset (ether_frame, 0, IP_MAXPACKET * sizeof (unsigned char));

  tmp = (char *) malloc (40 * sizeof (char));
  if (tmp != NULL) {
    interface = tmp;
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array 'interface'.\n");
    exit (EXIT_FAILURE);
  }
  memset (interface, 0, 40 * sizeof (char));

  tmp = (char *) malloc (40 * sizeof (char));
  if (tmp != NULL) {
    target = tmp;
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array 'target'.\n");
    exit (EXIT_FAILURE);
  }
  memset (target, 0, 40 * sizeof (char));

  tmp = (char *) malloc (16 * sizeof (char));
  if (tmp != NULL) {
    src_ip = tmp;
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array 'src_ip'.\n");
    exit (EXIT_FAILURE);
  }
  memset (src_ip, 0, 16 * sizeof (char));

  tmp = (char *) malloc (16 * sizeof (char));
  if (tmp != NULL) {
    dst_ip = tmp;
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array 'dst_ip'.\n");
    exit (EXIT_FAILURE);
  }
  memset (dst_ip, 0, 16 * sizeof (char));

  tmp = (int *) malloc (4 * sizeof (int));
  if (tmp != NULL) {
    ip_flags = tmp;
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array 'ip_flags'.\n");
    exit (EXIT_FAILURE);
  }
  memset (ip_flags, 0, 4 * sizeof (int));

  tmp = (unsigned char *) malloc (16 * sizeof (unsigned char));
  if (tmp != NULL) {
    tcp_flags = tmp;
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array 'tcp_flags'.\n");
    exit (EXIT_FAILURE);
  }
  memset (tcp_flags, 0, 4 * sizeof (unsigned char));

  tmp = (int *) malloc (10 * sizeof (int));
  if (tmp != NULL) {
    opt_len = tmp;
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array 'opt_len'.\n");
    exit (EXIT_FAILURE);
  }
  memset (opt_len, 0, 10 * sizeof (int));

  tmp = (unsigned char **) malloc (10 * sizeof (unsigned char *));
  if (tmp != NULL) {
    options = tmp;
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array 'options'.\n");
    exit (EXIT_FAILURE);
  }
  for (i=0; i<10; i++) {
    tmp = (unsigned char *) malloc (40 * sizeof (unsigned char));
    if (tmp != NULL) {
      options[i] = tmp;
      memset (options[i], 0, 40 * sizeof (unsigned char));
    } else {
      fprintf (stderr, "ERROR: Cannot allocate memory for array 'options'.\n");
      exit (EXIT_FAILURE);
    }
  }

  tmp = (unsigned char *) malloc (40 * sizeof (unsigned char));
  if (tmp != NULL) {
    opt_buffer = tmp;
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array 'opt_buffer'.\n");
    exit (EXIT_FAILURE);
  }
  memset (opt_buffer, 0, 40 * sizeof (unsigned char));

// Interface to send packet through.
  strcpy (interface, "eth0");
 //strcpy (interface, "lo");

// Submit request for a socket descriptor to lookup interface.
  if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    perror ("socket() failed to get socket descriptor for using ioctl() ");
    exit (EXIT_FAILURE);
  }

// Use ioctl() to lookup interface and get MAC address.
  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
    perror ("ioctl() failed to get source MAC address ");
    return (EXIT_FAILURE);
  }
  close (sd);

// Copy source MAC address.
  memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6);

// Report source MAC address to stdout.
  printf ("MAC address for interface %s is ", interface);
  for (i=0; i<5; i++) {
    printf ("%02x:", src_mac[i]);
  }
  printf ("%02x\n", src_mac[5]);

// Resolve interface index.
  if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
    perror ("if_nametoindex() failed to obtain interface index ");
    exit (EXIT_FAILURE);
  }
  printf ("Index for interface %s is %i\n", interface, device.sll_ifindex);

// Set destination MAC address: you need to fill these out
  dst_mac[0] = MAC_ADDR0;
  dst_mac[1] = MAC_ADDR1;
  dst_mac[2] = MAC_ADDR2;
  dst_mac[3] = MAC_ADDR3;
  dst_mac[4] = MAC_ADDR4;
  dst_mac[5] = MAC_ADDR5;

// Source IPv4 address: you need to fill this out
  strcpy (src_ip, "10.0.2.15");

// Destination URL or IPv4 address
  //strcpy (target, "www.google.com");
	//strcpy (target, "74.125.228.66");
	//strcpy (target, "127.0.0.1");
	//strcpy (target, "74.125.228.4"); //Google.com
	//strcpy (target, "206.190.36.45"); //yahoo.com
	strcpy (target, "173.252.110.27"); //facebook.com

// Fill out hints for getaddrinfo().
  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

// Resolve target using getaddrinfo().
  if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
    exit (EXIT_FAILURE);
  }
  ipv4 = (struct sockaddr_in *) res->ai_addr;
  tmp = &(ipv4->sin_addr);
  inet_ntop (AF_INET, tmp, dst_ip, 16);
  freeaddrinfo (res);

// Fill out sockaddr_ll.
  device.sll_family = AF_PACKET;
  memcpy (device.sll_addr, src_mac, 6);
  device.sll_halen = htons (6);

// Number of TCP options
  nopt = 3;

// First TCP option - Maximum segment size
  opt_len[0] = 0;
  options[0][0] = 2u; opt_len[0]++;  // Option kind 2 = maximum segment size
  options[0][1] = 4u; opt_len[0]++;  // This option kind is 4 bytes long
  options[0][2] = 0x1u; opt_len[0]++;  // Set maximum segment size to 0x100 = 256
  options[0][3] = 0x0u; opt_len[0]++;

// Second TCP option - Timestamp option
  opt_len[1] = 0;
  options[1][0] = 8u; opt_len[1]++;  // Option kind 8 = Timestamp option (TSOPT)
  options[1][1] = 10u; opt_len[1]++;  // This option is 10 bytes long
  options[1][2] = 0x2u; opt_len[1]++;  // Set the sender's timestamp (TSval) (4 bytes) (need SYN set to be valid)
  options[1][3] = 0x3u; opt_len[1]++;
  options[1][4] = 0x4u; opt_len[1]++;
  options[1][5] = 0x5u; opt_len[1]++;
  options[1][6] = 0x0u; opt_len[1]++;  // Set the echo timestamp (TSecr) (4 bytes) (need ACK set to be valid)
  options[1][7] = 0x0u; opt_len[1]++;
  options[1][8] = 0x0u; opt_len[1]++;
  options[1][9] = 0x0u; opt_len[1]++;



  opt_len[2] = 0;				//Sack permitted true
  options[2][0] = 4u; opt_len[2]++;  // 
  options[2][1] = 0x2u; opt_len[2]++;  //
/*	
  opt_len[3] = 0;				//WS=7
  options[3][0] = 3u; opt_len[3]++;  // 
  options[3][1] = 0x3u; opt_len[3]++;  // 
 options[3][2] = 0x7u; opt_len[3]++;
*/




// Copy all options into single options buffer.
  buf_len = 0;
  c = 0;  // index to opt_buffer
  for (i=0; i<nopt; i++) {
    memcpy (opt_buffer + c, options[i], opt_len[i]);
    c += opt_len[i];
    buf_len += opt_len[i];
  }

// Pad to the next 4-byte boundary.
  while ((buf_len%4) != 0) {
    opt_buffer[buf_len] = 0;
    buf_len++;
  }

// IPv4 header

// IPv4 header length (4 bits): Number of 32-bit words in header = 5
  //iphdr.ip_hl = IP4_HDRLEN / sizeof (unsigned long int);
	iphdr.ip_hl=5;
// Internet Protocol version (4 bits): IPv4
  iphdr.ip_v = 4;

// Type of service (8 bits)
  iphdr.ip_tos = 0;

// Total length of datagram (16 bits): IP header + TCP header + TCP options
  iphdr.ip_len = htons (IP4_HDRLEN + TCP_HDRLEN + buf_len);

// ID sequence number (16 bits): unused, since single datagram
  iphdr.ip_id = htons (0);

// Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

  // Zero (1 bit)
  ip_flags[0] = 0;

  // Do not fragment flag (1 bit)
  ip_flags[1] = 1;

  // More fragments following flag (1 bit)
  ip_flags[2] = 0;

  // Fragmentation offset (13 bits)
  ip_flags[3] = 0;

  iphdr.ip_off = htons ((ip_flags[0] << 15)
                      + (ip_flags[1] << 14)
                      + (ip_flags[2] << 13)
                      +  ip_flags[3]);

// Time-to-Live (8 bits): default to maximum value
  iphdr.ip_ttl = 255;

// Transport layer protocol (8 bits): 6 for TCP
  iphdr.ip_p = IPPROTO_TCP;

// Source IPv4 address (32 bits)
  inet_pton (AF_INET, src_ip, &(iphdr.ip_src));

// Destination IPv4 address (32 bits)
  inet_pton (AF_INET, dst_ip, &iphdr.ip_dst);

// IPv4 header checksum (16 bits): set to 0 when calculating checksum
  iphdr.ip_sum = 0;
  iphdr.ip_sum = checksum ((unsigned short int *) &iphdr, IP4_HDRLEN);

// TCP header

// Source port number (16 bits)
  tcphdr.th_sport = htons (36573);

// Destination port number (16 bits)
  tcphdr.th_dport = htons (80);

// Sequence number (32 bits)
  tcphdr.th_seq = htonl (0);

// Acknowledgement number (32 bits): 0 in first packet of SYN/ACK process
  tcphdr.th_ack = htonl (0);

// Reserved (4 bits): should be 0
  tcphdr.th_x2 = 0;

// Data offset (4 bits): size of TCP header + length of options, in 32-bit words
  tcphdr.th_off = (TCP_HDRLEN  + buf_len) / 4;

// Flags (8 bits)
  // FIN flag (1 bit)
  tcp_flags[0] = 0;
  // SYN flag (1 bit): set to 1
  tcp_flags[1] = 1;
  // RST flag (1 bit)
  tcp_flags[2] = 0;
  // PSH flag (1 bit)
  tcp_flags[3] = 0;
  // ACK flag (1 bit)
  tcp_flags[4] = 0;
  // URG flag (1 bit)
  tcp_flags[5] = 0;
  // ECE flag (1 bit)
  tcp_flags[6] = 0;
  // CWR flag (1 bit)
  tcp_flags[7] = 0;

  tcphdr.th_flags = 0;
  for (i=0; i<8; i++) {
    tcphdr.th_flags += (tcp_flags[i] << i);
  }

// Window size (16 bits)
  tcphdr.th_win = htons (65535);

// Urgent pointer (16 bits): 0 (only valid if URG flag is set)
  tcphdr.th_urp = htons (0);

// TCP checksum (16 bits)
  tcphdr.th_sum = tcp4_checksum (iphdr, tcphdr, opt_buffer, buf_len);

// Fill out ethernet frame header.

// Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + TCP header + TCP options)
  frame_length = 6 + 6 + 2 + IP4_HDRLEN + TCP_HDRLEN + buf_len;

// Destination and Source MAC addresses
  memcpy (ether_frame, dst_mac, 6);
  memcpy (ether_frame + 6, src_mac, 6);

// Next is ethernet type code (ETH_P_IP for IPv4).
// http://www.iana.org/assignments/ethernet-numbers
  ether_frame[12] = ETH_P_IP / 256;
  ether_frame[13] = ETH_P_IP % 256;

// Next is ethernet frame data (IPv4 header + TCP header).

// IPv4 header
  memcpy (ether_frame + 14, &iphdr, IP4_HDRLEN);
// TCP header
  memcpy (ether_frame + 14 + IP4_HDRLEN, &tcphdr, TCP_HDRLEN);
// TCP Options
  memcpy (ether_frame + 14 + IP4_HDRLEN + TCP_HDRLEN, opt_buffer, buf_len);




// Submit request for a raw socket descriptor.
  if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    perror ("socket() failed ");
    exit (EXIT_FAILURE);
  }

// Send SYN ethernet frame to socket.
  if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
    perror ("sendto() failed");
    exit (EXIT_FAILURE);
  }
  else
	{
		printf("SYN sent\n");
	}



struct ether_header *recv_eh = (struct ether_header *) buffer;
	struct ip *recv_iph = (struct ip *) (buffer + sizeof(struct ether_header));
	struct tcphdr *recv_tcph = (struct tcphdr *) (buffer +sizeof(struct ip) + sizeof(struct ether_header));
  	struct tcp_options *recv_tcpopt = (struct tcp_options *) (buffer + sizeof(struct ether_header)+sizeof(struct ip) + sizeof(struct tcphdr));

int ddd=main_pcap();







	printf("sending ACK\n");
	 memset (opt_buffer, 0, 40 * sizeof (unsigned char));
	 memset (ether_frame + 14,0,(frame_length-14)* sizeof (unsigned char));


// Number of TCP options
  nopt = 2;

// First TCP option - Maximum segment size
  opt_len[0] = 0;
  options[0][0] = 0x00; opt_len[0]++;  // NOP



// Second TCP option - Timestamp option
  opt_len[1] = 0;
  options[1][0] = 0x00; opt_len[1]++;  //NOP
 




// Copy all options into single options buffer.
  buf_len = 0;
  c = 0;  // index to opt_buffer
  for (i=0; i<nopt; i++) {
    memcpy (opt_buffer + c, options[i], opt_len[i]);
    c += opt_len[i];
    buf_len += opt_len[i];
  }

// Pad to the next 4-byte boundary.
  while ((buf_len%4) != 0) {
    opt_buffer[buf_len] = 0;
    buf_len++;
  }



	tcphdr.th_seq = htonl(ntohl(tcphdr.th_seq)+1);
	tcphdr.th_ack = htonl(ntohl(recv_tcph->th_seq));
	iphdr.ip_id=htons(ntohs(iphdr.ip_id)+1);
	iphdr.ip_len = htons (IP4_HDRLEN + TCP_HDRLEN + buf_len);
	tcphdr.th_off = (TCP_HDRLEN  + buf_len) / 4;
	tcphdr.th_flags = 0x10;//[ACK]
	// TCP checksum (16 bits)
	iphdr.ip_sum = 0;
	iphdr.ip_sum = checksum ((unsigned short int *) &iphdr, IP4_HDRLEN);
    tcphdr.th_sum = tcp4_checksum (iphdr, tcphdr, opt_buffer, buf_len);

	// Fill out ethernet frame header.

	// Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + TCP header + TCP options)
  frame_length = 6 + 6 + 2 + IP4_HDRLEN + TCP_HDRLEN + buf_len;

// IPv4 header
  memcpy (ether_frame + 14, &iphdr, IP4_HDRLEN);
// TCP header
  memcpy (ether_frame + 14 + IP4_HDRLEN, &tcphdr, TCP_HDRLEN);
// TCP Options
  memcpy (ether_frame + 14 + IP4_HDRLEN + TCP_HDRLEN, opt_buffer, buf_len);
printf("sending ACK......\n");
// Send ACK ethernet frame to socket.
  if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
    perror ("sendto() failed");
	printf("sending ACK failed\n");
    exit (EXIT_FAILURE);
  }
  else
	{
		printf("ACK sent\n");
	}



// Sending Get Request

//GET /\r\n
printf("sending GET /\n");
	 memset (opt_buffer, 0, 40 * sizeof (unsigned char));
	 memset (ether_frame + 14,0,(frame_length-14)* sizeof (unsigned char));


// Number of TCP options
  nopt = 1;


 
// Second TCP option - GET /\r\n\r\n
 //47 45 54 20 2f 0d 0a
    opt_len[0] = 0;
    options[0][0] = 0x47; opt_len[0]++;  //
	options[0][1] = 0x45; opt_len[0]++;  //
	options[0][2] = 0x54; opt_len[0]++;  //
	options[0][3] = 0x20; opt_len[0]++;  //
	options[0][4] = 0x2f; opt_len[0]++;  //
	options[0][5] = 0x0d; opt_len[0]++;  //
	options[0][6] = 0x0a; opt_len[0]++;  //
	options[0][7] = 0x0d; opt_len[0]++;  //
	options[0][8] = 0x0a; opt_len[0]++;  //

// Copy all options into single options buffer.
  buf_len = 0;
  c = 0;  // index to opt_buffer
  for (i=0; i<nopt; i++) {
    memcpy (opt_buffer + c, options[i], opt_len[i]);
    c += opt_len[i];
    buf_len += opt_len[i];
  }
/*
// Pad to the next 4-byte boundary.
  while ((buf_len%4) != 0) {
    opt_buffer[buf_len] = 0;
    buf_len++;
  }
*/


	//tcphdr.th_seq = htonl(ntohl(tcphdr.th_seq)+1);
	iphdr.ip_id=htons(ntohs(iphdr.ip_id)+1);
	iphdr.ip_len = htons (IP4_HDRLEN + TCP_HDRLEN + buf_len);
	tcphdr.th_off = (TCP_HDRLEN ) / 4;
	tcphdr.th_flags = 0x18;//[PSH,ACK]



	// TCP checksum (16 bits)
	iphdr.ip_sum = 0;
	iphdr.ip_sum = checksum ((unsigned short int *) &iphdr, IP4_HDRLEN);
    tcphdr.th_sum = tcp4_checksum (iphdr, tcphdr, opt_buffer, buf_len);

	// Fill out ethernet frame header.

	// Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + TCP header + TCP options)
  frame_length = 6 + 6 + 2 + IP4_HDRLEN + TCP_HDRLEN + buf_len;

// IPv4 header
  memcpy (ether_frame + 14, &iphdr, IP4_HDRLEN);
// TCP header
  memcpy (ether_frame + 14 + IP4_HDRLEN, &tcphdr, TCP_HDRLEN);
// TCP Options
  memcpy (ether_frame + 14 + IP4_HDRLEN + TCP_HDRLEN, opt_buffer, buf_len);





// Send GET /request ethernet frame to socket.
  if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
    perror ("sendto() failed");
	printf("sending GET / failed\n");
    exit (EXIT_FAILURE);
  }
  else
	{
		printf("GET / sent\n");
	}




// Close socket descriptor.
  close (sd);

// Free allocated memory.
  free (src_mac);
  free (dst_mac);
  free (ether_frame);
  free (interface);
  free (target);
  free (src_ip);
  free (dst_ip);
  free (ip_flags);
  free (tcp_flags);
  free (opt_len);
  for (i=0; i<10; i++) {
    free (options[i]);
  }
  free (options);
  free (opt_buffer);

  return (EXIT_SUCCESS);
}

// Checksum function
unsigned short int
checksum (unsigned short int *addr, int len)
{
  int nleft = len;
  int sum = 0;
  unsigned short int *w = addr;
  unsigned short int answer = 0;

  while (nleft > 1) {
    sum += *w++;
    nleft -= sizeof (unsigned short int);
  }

  if (nleft == 1) {
    *(unsigned char *) (&answer) = *(unsigned char *) w;
    sum += answer;
  }

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  answer = ~sum;
  return (answer);
}

// Build IPv4 TCP pseudo-header and call checksum function.
unsigned short int
tcp4_checksum (struct ip iphdr, struct tcphdr tcphdr, unsigned char *options, int opt_len)
{
  unsigned short int svalue;
  char buf[IP_MAXPACKET], cvalue;
  char *ptr;
  int chksumlen = 0;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (32 bits)
  memcpy (ptr, &iphdr.ip_src.s_addr, sizeof (iphdr.ip_src.s_addr));
  ptr += sizeof (iphdr.ip_src.s_addr);
  chksumlen += sizeof (iphdr.ip_src.s_addr);

  // Copy destination IP address into buf (32 bits)
  memcpy (ptr, &iphdr.ip_dst.s_addr, sizeof (iphdr.ip_dst.s_addr));
  ptr += sizeof (iphdr.ip_dst.s_addr);
  chksumlen += sizeof (iphdr.ip_dst.s_addr);

  // Copy zero field to buf (8 bits)
  *ptr = 0; ptr++;
  chksumlen += 1;

  // Copy transport layer protocol to buf (8 bits)
  memcpy (ptr, &iphdr.ip_p, sizeof (iphdr.ip_p));
  ptr += sizeof (iphdr.ip_p);
  chksumlen += sizeof (iphdr.ip_p);

  // Copy TCP length to buf (16 bits)
  svalue = htons (sizeof (tcphdr) + opt_len);
  memcpy (ptr, &svalue, sizeof (svalue));
  ptr += sizeof (svalue);
  chksumlen += sizeof (svalue);

  // Copy TCP source port to buf (16 bits)
  memcpy (ptr, &tcphdr.th_sport, sizeof (tcphdr.th_sport));
  ptr += sizeof (tcphdr.th_sport);
  chksumlen += sizeof (tcphdr.th_sport);

  // Copy TCP destination port to buf (16 bits)
  memcpy (ptr, &tcphdr.th_dport, sizeof (tcphdr.th_dport));
  ptr += sizeof (tcphdr.th_dport);
  chksumlen += sizeof (tcphdr.th_dport);

  // Copy sequence number to buf (32 bits)
  memcpy (ptr, &tcphdr.th_seq, sizeof (tcphdr.th_seq));
  ptr += sizeof (tcphdr.th_seq);
  chksumlen += sizeof (tcphdr.th_seq);

  // Copy acknowledgement number to buf (32 bits)
  memcpy (ptr, &tcphdr.th_ack, sizeof (tcphdr.th_ack));
  ptr += sizeof (tcphdr.th_ack);
  chksumlen += sizeof (tcphdr.th_ack);

  // Copy data offset to buf (4 bits) and
  // copy reserved bits to buf (4 bits)
  cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
  memcpy (ptr, &cvalue, sizeof (cvalue));
  ptr += sizeof (cvalue);
  chksumlen += sizeof (cvalue);

  // Copy TCP flags to buf (8 bits)
  memcpy (ptr, &tcphdr.th_flags, sizeof (tcphdr.th_flags));
  ptr += sizeof (tcphdr.th_flags);
  chksumlen += sizeof (tcphdr.th_flags);

  // Copy TCP window size to buf (16 bits)
  memcpy (ptr, &tcphdr.th_win, sizeof (tcphdr.th_win));
  ptr += sizeof (tcphdr.th_win);
  chksumlen += sizeof (tcphdr.th_win);

  // Copy TCP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy urgent pointer to buf (16 bits)
  memcpy (ptr, &tcphdr.th_urp, sizeof (tcphdr.th_urp));
  ptr += sizeof (tcphdr.th_urp);
  chksumlen += sizeof (tcphdr.th_urp);

  // Copy TCP options to buf (variable length, but in 32-bit chunks)
  memcpy (ptr, options, opt_len);
  ptr += opt_len;
  chksumlen += opt_len;

  return checksum ((unsigned short int *) buf, chksumlen);
}



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

