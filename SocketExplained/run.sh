#!/bin/bash

#$dest_ip = "127.0.0.1"
#$soure_ip ="127.0.0.1"
#If you want to set the geSackOK
#gcc -o tx rawsockets_IP.c
#sudo ./tx -S 10.0.2.15 -D 74.125.228.66 -P 80 -N 1 -b 1
#sudo ./rawsockets -s soure_ip -d dest_ip -p 80 -n 1 -w 4 -x 2
sudo iptables -t filter -I OUTPUT -p tcp --sport 36573 --tcp-flags RST RST -j DROP
gcc -o tx tcp4_tsopt.c -lpcap
sudo ./tx


