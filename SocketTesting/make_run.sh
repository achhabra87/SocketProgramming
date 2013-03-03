#!/bin/bash

pid="$(pidof server)"
echo $pid
kill -9 $pid
a="$(gcc -o server server.c)"
echo $a
b="$(gcc -o client client.c)"
echo $b

./server &
sleep 1
./client localhost
sleep 1

pid="$(pidof server)"
echo $pid
kill -9 $pid
