#!/bin/bash

#$dest_ip = "127.0.0.1"
#$soure_ip ="127.0.0.1"
#If you want to set the SackOK
gcc -o tx rawsockets_IP.c
sudo ./tx -S 127.0.0.1 -D 127.0.0.1 -P 80 -N 1 -b 1
#sudo ./rawsockets -s soure_ip -d dest_ip -p 80 -n 1 -w 4 -x 2



