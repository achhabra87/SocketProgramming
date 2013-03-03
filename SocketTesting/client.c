/*
** client.c -- a stream socket client demo
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#define __FAVOR_BSD
#include <sys/socket.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>

#define PORT "3490" // the port client will be connecting to 

#define MAXDATASIZE 100 // max number of bytes we can get at once 

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

#define TCPSYN_LEN 20
#define MAXBYTES2CAPTURE 2048

/* Pseudoheader (Used to compute TCP checksum. Check RFC 793) */
typedef struct pseudoheader {
  u_int32_t src;
  u_int32_t dst;
  u_char zero;
  u_char protocol;
  u_int16_t tcplen;
} tcp_phdr_t;

typedef unsigned short u_int16;
typedef unsigned long u_int32;



int main(int argc, char *argv[])
{
    int sockfd, numbytes;  
    char buf[MAXDATASIZE];
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];
	
	// From TCP library
	char packet[ sizeof(struct tcphdr) +1 ]; 
	struct tcphdr tcpheader;

	u_int32_t seq;
	u_int16_t src_prt, dst_prt;

	src_prt=6; 
	dst_prt=5;
	seq=1;
	
	/* TCP Header */   
	
	
	tcpheader.th_seq = seq;        /* Sequence Number                         */
	tcpheader.th_ack = htonl(1);   /* Acknowledgement Number                  */
	tcpheader.th_x2 = 0;           /* Variable in 4 byte blocks. (Deprecated) */
	tcpheader.th_off = 5;		  /* Segment offset (Lenght of the header)   */
	tcpheader.th_flags = 1;   /* TCP Flags. We set the Reset Flag        */
	//tcpheader.th_win = htons(4500) + rand()%1000;/* Window size               */
	tcpheader.th_urp = 0;          /* Urgent pointer.                         */
	tcpheader.th_sport = src_prt;  /* Source Port                             */
	tcpheader.th_dport = dst_prt;  /* Destination Port                        */
	tcpheader.th_sum=0;            /* Checksum. (Zero until computed)         */
	










	

    if (argc != 2) {
        fprintf(stderr,"usage: client hostname\n");
        exit(1);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(argv[1], PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("client: socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("client: connect");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "client: failed to connect\n");
        return 2;
    }

	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),s, sizeof s);
	printf("client: connecting to %s\n", s);

	freeaddrinfo(servinfo); // all done with this structure

	int buffersize=sizeof(struct tcphdr)+1;	
	char clientpacketsend[buffersize];
	memcpy(&clientpacketsend,&tcpheader,sizeof(struct tcphdr));
	// process data
	
	char clientpacketrecv[buffersize];
	struct tcphdr *clientrecvheader=(struct tcphdr *)clientpacketrecv;
	struct tcphdr *clientsendheader=(struct tcphdr *)clientpacketsend;


	
	//struct tcphdr *header=(struct tcphdr *)clientsendheader;

	/*Connection Establishment Three Way handshake*/
	/*Connection Establishment*/ /*Starts here*/
	printf("TCP client: sending connect request\n");
	/*	
	if (send(sockfd, "Hello, world!", 13, 0) == -1){
                perror("TCP Client send");
            close(sockfd);
	}*/
	
	if (send(sockfd,clientpacketsend, sizeof(struct tcphdr)+1, 0) == -1){
		perror("TCP Client send");close(sockfd);}
	else{	printf("TCP client: SYN Sent \n");}

	
    if ((numbytes = recv(sockfd, clientpacketrecv, buffersize, 0)) == -1) {
        perror("recv");exit(1);}
	printf("TCP client: SYN+ACK Recieved ACK= %d, SYN= %d\n",clientrecvheader->th_ack,clientrecvheader->th_seq);


	clientsendheader->th_ack=clientrecvheader->th_seq;
	clientsendheader->th_seq=clientrecvheader->th_seq+1;
	
	if (send(sockfd, clientpacketsend, sizeof(struct tcphdr)+1, 0) == -1){
		perror("TCP Client send");close(sockfd);}
	/*Connection Establishment*/ /*End here*/
	


    buf[numbytes] = '\0';

    //printf("client: received '%s'\n",buf);

    close(sockfd);

    return 0;
};
