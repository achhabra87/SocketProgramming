createmessage(char * buffer,char **argv){

int flags = 0, c, numtries=90;
  char src_ip[17];
  char dst_ip[17];
  short dst_port=80;
  short th_sport=56573;
  short tcp_flags=TH_SYN;
  short pig_ack=0;
	short pig_seq=31337;
  //struct ether_header *eh = (struct ether_header *) sendbuf;
  struct ip *iph = (struct ip *) datagram;
  struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
  struct tcp_options *tcpopt = (struct tcp_options *) (datagram + sizeof(struct ip) + sizeof(struct tcphdr));
  struct sockaddr_in servaddr;
  memset(datagram, 0, 4096); /* zero out the buffer */

  fprintf(stderr,"sizeof (struct ip)= %lu\n",sizeof(struct ip));//fprintf(stderr,"sizeof (struct ip)= %d\n",sizeof(struct ip));


  inet_pton(AF_INET, dst_ip,&servaddr.sin_addr);
  int tcphdr_size = sizeof(struct tcphdr);

  iph->ip_hl = 5;
  iph->ip_v = 4;
  iph->ip_tos = 0x10;
  iph->ip_len = sizeof (struct ip) + sizeof (struct tcphdr) + 8 +6 +6; /* data size = 0, but tcp using option flags */
  iph->ip_id = htons (31337);
  iph->ip_off = 0;
  iph->ip_ttl = 250;
  iph->ip_p = 6;
  iph->ip_sum = 0;
  //OLD WAY iph->ip_src.s_addr = inet_addr (src_ip);/* source ip  */
  inet_pton(AF_INET, src_ip, &(iph->ip_src));
  iph->ip_dst.s_addr = servaddr.sin_addr.s_addr;

  tcph->th_sport = htons (th_sport); /* source port */
  tcph->th_dport = htons (dst_port); /* destination port */
  tcph->th_seq = htonl(31337);
  tcph->th_ack = htonl(pig_ack);/* in first SYN packet, ACK is not present */
  tcph->th_x2 = 0;
  // tcph->th_off = sizeof(struct tcphdr)/4; /* data position in the packet */
  // Special chirico adjustment to give 2x32
  tcph->th_off = 7+2+1 ;
//tcph->th_off = 7+1 ;

  fprintf(stderr,"Data offset %d  sizeof(struct tcphdr)=%lu\n",tcph->th_off,sizeof(struct tcphdr));
	//fprintf(stderr,"Data offset %d  sizeof(struct tcphdr)=%d\n",tcph->th_off,sizeof(struct tcphdr));
  /*
#  define TH_FIN        0x01
#  define TH_SYN        0x02
#  define TH_RST        0x04
#  define TH_PUSH       0x08
#  define TH_ACK        0x10
#  define TH_URG        0x20




  */



  tcph->th_flags = tcp_flags; /* initial connection request */
  tcph->th_win = htons (32896); /* */
  tcph->th_sum = 0; /* we will compute it later */
  tcph->th_urp = 0;
  if (tcphdr_size % 4 != 0) /* takes care of padding to 32 bits */
    tcphdr_size = ((tcphdr_size % 4) + 1) * 4;
  fprintf(stderr,"tcphdr_size %d\n",tcphdr_size);
  tcphdr_size=40;
  fprintf(stderr,"tcphdr_size %d\n",tcphdr_size);

  memset(pheader,0x0,sizeof(pheader));
  memcpy(&pheader,&(iph->ip_src.s_addr),4);
  memcpy(&pheader[4],&(iph->ip_dst.s_addr),4);
  pheader[8]=0; // just to underline this zero byte specified by rfc
  pheader[9]=(u_int16_t)iph->ip_p;
  pheader[10]=(u_int16_t)(tcphdr_size & 0xFF00)>>8;
  pheader[11]=(u_int16_t)(tcphdr_size & 0x00FF);

  /* tcpopt->op0=4;   sackOK 
     tcpopt->op1=2;
  */
  memcpy(&pheader[12], tcph, sizeof(struct tcphdr));
  memcpy(&pheader[12+ sizeof(struct tcphdr)], tcpopt, sizeof(struct tcp_options));

  //fprintf(stderr,"12+sizeof(struct tcphdr)= %d    %d\n",12+sizeof(struct tcphdr),sizeof(struct tcp_options));
  fprintf(stderr,"12+sizeof(struct tcphdr)= %lu    %lu\n",12+sizeof(struct tcphdr),sizeof(struct tcp_options));
  /* This is an example of setting SackOK we need to set it in the
     header for checksum and in the actual data.  This should only get
     sent when using SYN? */

  //pheader[32]=4;
  //  pheader[33]=2;

    //datagram[40]=4;
    //datagram[41]=2;



    fprintf(stderr,"********** %d %d\n",tcpopt->op0,datagram[40]);
    fprintf(stderr,"********** %d %d\n",tcpopt->op1,datagram[41]);


    fprintf(stderr,"csum size is %d\n",tcphdr_size+12);



     

  tcph->th_sum = csum ((uint16_t *) (pheader),tcphdr_size+12);


  //  iph->ip_sum = csum ((unsigned short *) datagram, iph->ip_len >> 1);

}
