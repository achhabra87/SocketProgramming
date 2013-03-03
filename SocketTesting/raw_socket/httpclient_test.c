/* http-client.c
 *
 * Copyright (c) 2000 Sean Walton and Macmillan Publishers.  Use may be in
 * whole or in part in accordance to the General Public License (GPL).
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
*/

/*****************************************************************************/
/*** http-client.c                                                         ***/
/***                                                                       ***/
/*** This program shows what the HTTP server sends to the client.  First,  ***/
/*** it opens a TCP socket to the server.  Then, it sends the request      ***/
/*** "GET <resource> HTTP/1.0\n\n" (the second newline is needed for the   ***/
/*** "message-end" message.  Lastly it prints out the reply.               ***/
/*****************************************************************************/

#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define MAXBUF  1024
void PANIC(char *msg);
#define PANIC(msg)  {perror(msg); abort();}

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


int main(int Count, char *Strings[])
{   int sockfd, bytes_read;
    struct sockaddr_in dest;
    char buffer[MAXBUF];

	char packet[PCKT_LEN];
	struct iphdr *ip = (struct iphdr *) packet;
	struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct iphdr));
	char* payload = (u_char *)(packet + sizeof(struct iphdr) + sizeof(struct tcphdr));


	
	
	ip->version = 4; /* version of IP used */
	ip->ihl = 5; /* Internet Header Length (IHL) */
	ip->tos = 0; /* Type Of Service (TOS) */
	ip->tot_len = htons(40); /* total length of the IP datagram */
	ip->id = 1; /* identification */
	ip->frag_off = 0; /* fragmentation flag */
	ip->ttl = 255; /* Time To Live (TTL) */
	ip->protocol = IPPROTO_TCP; /* protocol used (TCP in this case) */
	ip->check = 14536; /* IP checksum */
	ip->saddr = inet_addr("1.2.3.4"); /* source address */
	ip->daddr = inet_addr(Strings[1]); /* destination address */
	//ip->saddr = inet_addr("10.0.2.15"); /* source address */
	//ip->daddr = inet_addr("209.2.214.222"); /* destination address */
	//ip->daddr = inet_addr("google.com"); /* destination address */
	ip->check = IPcsum((unsigned short*) packet, (sizeof(struct iphdr) + sizeof(struct tcphdr)));

	tcp->source = htons(2000); /* source port */
	tcp->dest = htons(80); /* destination port */
	tcp->seq = 1; /* sequence number */
	tcp->ack_seq = 2; /* acknowledgement number */
	//packet.tcp.doff = 5; /* data offset */
	tcp->doff = 5; /* data offset */
	tcp->res1 = 0; /* reserved for future use (must be 0) */
	tcp->fin = 0; /* FIN flag */
	tcp->syn = 1; /* SYN flag */
	tcp->rst = 0; /* RST flag */
	tcp->psh = 0; /* PSH flag */
	tcp->ack = 0; /* ACK flag */
	tcp->urg = 0; /* URG flag */
	tcp->res2 = 0;  /* reserved (must be 0) */
	tcp->window = htons(512); /* window */
	tcp->check = 8889; /* TCP checksum */
	tcp->urg_ptr = 0; /* urgent pointer */
	int char_size=sizeof("GET / HTTP/1.0\n\n");
	tcp->doff=tcp->doff+ (char_size/4);



    /*---Make sure we have the right number of parameters---*/
    if ( Count != 3 )
        printf("usage: testport <IP-addr> <send-msg>\n");
    if ( (sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) < 0 )
        printf("Socket");
		int one = 1;
	const int *val = &one;

    /*---Initialize server address/port struct---*/
    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(80); /*default HTTP Server port */
    if ( inet_addr(Strings[1], &dest.sin_addr.s_addr) == 0 )
        printf("Error in destination address%s",Strings[1]);

    /*---Connect to server---*/
    if ( connect(sockfd, (struct sockaddr*)&dest, sizeof(dest)) != 0 )
        printf("Connect");

    sprintf(buffer, "GET %s HTTP/1.0\n\n", Strings[2]);

	if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
	{
		perror("setsockopt() error");
		//exit(-1);
	}
	else{
	   printf("setsockopt() is OK\n");}

	memcpy(payload, "GET / HTTP/1.0\n\n",sizeof("GET / HTTP/1.0\n\n"));

    send(sockfd, packet, sizeof(packet), 0);

    /*---While there's data, read and print it---*/
    do
    {
        bzero(buffer, sizeof(buffer));
        bytes_read = recv(sockfd, buffer, sizeof(buffer), 0);
        if ( bytes_read > 0 )
            printf("%s", buffer);
    }
    while ( bytes_read > 0 );

    /*---Clean up---*/
    close(sockfd);
    return 0;
}

