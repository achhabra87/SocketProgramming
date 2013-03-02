#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#define TCP_HDRLEN 20 
// Packet length
#define PCKT_LEN 8192





unsigned short IPcsum(unsigned short* buf, int len)
{
        unsigned long sum;
        for(sum=0; len>0; len--)
                sum += *buf++;

        sum = (sum >> 16) + (sum &0xffff);
        sum += (sum >> 16);
        return (unsigned short)(~sum);
}




struct send_tcp
   {
		u_int32_t Maximum_Segment_Size;
		u_int32_t Selective_Acknowledgements_SACK;
		u_int32_t Window_Scaling;
		u_int32_t Nop;
		u_int32_t Timestamps;
		
   } tcp_options;

#define MAXBUF  1024


main()

{
char buffer[MAXBUF];
int tcp_socket, bytes_read;
	int one = 1;
	const int *val = &one;

struct sockaddr_in peer;


/* The above makes a struct called "packet" which will be the packet we
construct. Below are all the lines we use to actually build this packet.
See RFCs 791 and 793 for more info on the fields here and what they
mean. */
	printf("Size of options %lu",sizeof(tcp_options));

	char packet[PCKT_LEN];
	// The size of the headers

	struct iphdr *ip = (struct iphdr *) packet;
	struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct iphdr));
	//struct tcp_options *tcpopt = (struct tcp_options *) (packet + sizeof(struct iphdr) + sizeof(struct tcphdr));
	//char *payload = (u_char *)(packet + sizeof(struct iphdr) + sizeof(struct tcphdr));



ip->version = 4; /* version of IP used */
ip->ihl = 5; /* Internet Header Length (IHL) */
ip->tos = 0; /* Type Of Service (TOS) */
ip->tot_len = htons(40); /* total length of the IP datagram */
ip->id = 0; /* identification */
ip->frag_off = 0; /* fragmentation flag */
ip->ttl = 255; /* Time To Live (TTL) */
ip->protocol = IPPROTO_TCP; /* protocol used (TCP in this case) */
ip->check = 14536; /* IP checksum */
ip->saddr = inet_addr("1.2.3.4"); /* source address */
ip->daddr = inet_addr("127.0.0.1"); /* destination address */
//ip->saddr = inet_addr("10.0.2.15"); /* source address */
//ip->daddr = inet_addr("209.2.214.222"); /* destination address */
//ip->daddr = inet_addr("google.com"); /* destination address */



tcp->source = htons(39763); /* source port */
tcp->dest = htons(80); /* destination port */
tcp->seq = 1; /* sequence number */
tcp->ack_seq = 0; /* acknowledgement number */
//tcp->tcp.doff = 5; /* data offset */
tcp->doff = 5; /* data offset */
tcp->res1 = 0; /* reserved for future use (must be 0) */
tcp->fin = 0; /* FIN flag */
tcp->syn = 1; /* SYN flag */
tcp->rst = 0; /* RST flag */
tcp->psh = 0; /* PSH flag */
tcp->ack = 0; /* ACK flag */
tcp->urg = 0; /* URG flag */
tcp->res2 = 0;  /* reserved (must be 0) */
tcp->window = htons(32792); /* window */
tcp->check = 8889; /* TCP checksum */
tcp->urg_ptr = 0; /* urgent pointer */
/*
payload[0]='G';
payload[1]='e';
payload[2]='t';
payload[3]='\0';
int int_size=sizeof(int);
int char_size=sizeof("GET\0");
tcp->doff=tcp->doff+ (char_size/4);
printf("int_size=%d char_size = %d \n",int_size,char_size);
*/
//tcphdr.th_sum = tcp4_checksum (iphdr, tcphdr, (unsigned char *) payload, payloadlen);

ip->check = IPcsum((unsigned short*) packet, (sizeof(struct iphdr) + sizeof(struct tcphdr)));

/* That's got the packet formed. Now we go on making the "peer" struct
just as usual. */

peer.sin_family = AF_INET;
peer.sin_port = htons(80);
//din.sin_family = AF_INET;
peer.sin_addr.s_addr = inet_addr("127.0.0.1");
//peer.sin_addr.s_addr = ip->saddr;

tcp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	if(tcp_socket < 0)
	{
	   perror("socket() error");

	  // exit(-1);
	}
	else
	{
		printf("socket()-SOCK_RAW and tcp protocol is OK.\n");
	}


	int maxseg = 534;
/*
	if(setsockopt(tcp_socket, IPPROTO_IP, TCPOPT_MAXSEG, (char*)&maxseg,sizeof(maxseg)) == -1){
		perror(NULL);
		//exit(-1);
	}
	else{
		printf("TCP MAX SEG\n");
	}
*/


	
	//if(setsockopt(tcp_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)


int i=0;

while(1){
sendto(tcp_socket, &packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&peer,
  sizeof(peer));
printf("sending packets %d\n",i);
i++;
}

    do
    {
        bzero(buffer, sizeof(buffer));
        bytes_read = recv(tcp_socket, buffer, sizeof(buffer), 0);
        if ( bytes_read > 0 )
            printf("%s", buffer);
    }
    while ( bytes_read > 0 );





/* the 0 is for the flags */

close(tcp_socket);

}
