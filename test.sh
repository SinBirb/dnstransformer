#!/bin/bash

tcp_port=53100
udp_port=54321

# connecting to local name server on port 53
./dnstransformer -vvvus $tcp_port -p 53 127.0.0.1 |& tee server.log &
pid1=$!
sleep 1
./dnstransformer -vvvuc $tcp_port -p $udp_port 127.0.0.1 |& tee client.log &
pid2=$!
sleep 1
dig @127.0.0.1 -p $udp_port cloud.com
dig @127.0.0.1 -4p $udp_port $(head -n10 top-1000.domains.list | tr '\n' ' ')
kill $pid1
kill $pid2
