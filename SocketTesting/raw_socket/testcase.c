#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#define TCP_HDRLEN 20 



unsigned short IPcsum(unsigned short *buf, int len)
{
        unsigned long sum;
        for(sum=0; len>0; len--)
                sum += *buf++;

        sum = (sum >> 16) + (sum &0xffff);
        sum += (sum >> 16);
        return (unsigned short)(~sum);
}

main()

{

int tcp_socket;
	int one = 1;
	const int *val = &one;

struct sockaddr_in peer;

struct send_tcp
   {
      struct iphdr ip;
      struct tcphdr tcp;
		char payload[40];
   } packet;

/* The above makes a struct called "packet" which will be the packet we
construct. Below are all the lines we use to actually build this packet.
See RFCs 791 and 793 for more info on the fields here and what they
mean. */



packet.ip.version = 4; /* version of IP used */
packet.ip.ihl = 5; /* Internet Header Length (IHL) */
packet.ip.tos = 0; /* Type Of Service (TOS) */
packet.ip.tot_len = htons(40); /* total length of the IP datagram */
packet.ip.id = 1; /* identification */
packet.ip.frag_off = 0; /* fragmentation flag */
packet.ip.ttl = 255; /* Time To Live (TTL) */
packet.ip.protocol = IPPROTO_TCP; /* protocol used (TCP in this case) */
packet.ip.check = 14536; /* IP checksum */
packet.ip.saddr = inet_addr("1.2.3.4"); /* source address */
packet.ip.daddr = inet_addr("127.0.0.1"); /* destination address */

packet.tcp.source = htons(2000); /* source port */
packet.tcp.dest = htons(80); /* destination port */
packet.tcp.seq = 1; /* sequence number */
packet.tcp.ack_seq = 2; /* acknowledgement number */
//packet.tcp.doff = 5; /* data offset */
packet.tcp.doff = 5; /* data offset */
packet.tcp.res1 = 0; /* reserved for future use (must be 0) */
packet.tcp.fin = 0; /* FIN flag */
packet.tcp.syn = 1; /* SYN flag */
packet.tcp.rst = 0; /* RST flag */
packet.tcp.psh = 0; /* PSH flag */
packet.tcp.ack = 0; /* ACK flag */
packet.tcp.urg = 0; /* URG flag */
packet.tcp.res2 = 0;  /* reserved (must be 0) */
packet.tcp.window = htons(512); /* window */
packet.tcp.check = 8889; /* TCP checksum */
packet.tcp.urg_ptr = 0; /* urgent pointer */
packet.payload[0]='G';
packet.payload[1]='e';
packet.payload[2]='t';
packet.payload[3]='\0';
int int_size=sizeof(int);
int char_size=sizeof("GET\0");
packet.tcp.doff=packet.tcp.doff+ (char_size/4);
printf("int_size=%d char_size = %d \n",int_size,char_size);

packet.ip.check = IPcsum((unsigned short *) packet, (sizeof(struct iphdr) + sizeof(struct tcphdr)));


/* That's got the packet formed. Now we go on making the "peer" struct
just as usual. */

peer.sin_family = AF_INET;
peer.sin_port = htons(80);
//din.sin_family = AF_INET;
peer.sin_addr.s_addr = inet_addr("127.0.0.1");

tcp_socket = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);

	if(tcp_socket < 0)

	{

	   perror("socket() error");

	  // exit(-1);

	}
	else
	{
		printf("socket()-SOCK_RAW and tcp protocol is OK.\n");
	}


	if(setsockopt(tcp_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
	{
		perror("setsockopt() error");
		//exit(-1);
	}
	else
	   printf("setsockopt() is OK\n");


sendto(tcp_socket, &packet, sizeof(packet), 0, (struct sockaddr *)&peer,
  sizeof(peer));

/* the 0 is for the flags */

close(tcp_socket);

}
