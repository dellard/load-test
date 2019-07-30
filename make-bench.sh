#!/usr/bin/env bash
#
# This material is funded in part by a grant from the United States
# Department of State. The opinions, findings, and conclusions stated
# herein are those of the authors and do not necessarily reflect
# those of the United States Department of State.
#
# Copyright 2016 - Raytheon BBN Technologies Corp.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you
# may not use this file except in compliance with the License.
#
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.

# This is an example of how to construct heavy workload traces to replay,
# by duplicating traces and then adding them together

# The input pcap is assumed to contain traffic between a
# single client and a single server.
#
INPUT_PCAP=pcaps/decoy-https-100.pcap

# We need to know how many flows there are so we know how
# many new ephemeral ports we need to fake.
#
FLOWS_PER_PCAP=100

# The IP of the client and the server in the original PCAP file
#
CLIENT_IN_IP=10.0.0.10
SERVER_IN_IP=10.0.20.11

# The IP of the client and the server in the output PCAP file
# (which might be replayed on a different subnet, or for different
# hosts.  The default is to leave them unchanged, but you can
# override them here.
#
CLIENT_OUT_IP=10.0.0.32
SERVER_OUT_IP=10.0.1.32

OUTPUT_SERVER_PCAP=out-server.pcap
OUTPUT_CLIENT_PCAP=out-client.pcap

# How many copies of the input to create.
COPY_CNT=10

TMPDIR=./scratch

# if the output IPs haven't been set, set them to their
# defaults
#
if [ -z "$CLIENT_OUT_IP" ]; then
    CLIENT_OUT_IP=$CLIENT_IN_IP
fi

if [ -z "$SERVER_OUT_IP" ]; then
    SERVER_OUT_IP=$SERVER_IN_IP
fi

# pcap_addr rewrite rules for HTTPS and HTTP
#
R_HTTPS="$CLIENT_IN_IP:$SERVER_IN_IP:0:443/$CLIENT_OUT_IP:$SERVER_OUT_IP:0:443"
R_HTTP="$CLIENT_IN_IP:$SERVER_IN_IP:0:80/$CLIENT_OUT_IP:$SERVER_OUT_IP:0:80"

mkdir -p $TMPDIR
rm -f $TMPDIR/*.pcap

CNT=0
while [ $CNT -lt $COPY_CNT ]; do
    OFFSET=$(echo "$CNT * 0.05" | bc -l)
    EPHEM=$((50000 + (CNT * $FLOWS_PER_PCAP)))

    ./pcap_shift -b $OFFSET -o $TMPDIR/T-$CNT.pcap $INPUT_PCAP

    # rewrite addresses from client:server to lhost0-0:rhost0-0
    # on the router0 subnet of the softall10g testbed.
    # (We would use lhost0-1:rhost0-1 for the router1 subnet.)
    #
    ./pcap_addr -o $TMPDIR/TA-$CNT.pcap -i $TMPDIR/T-$CNT.pcap -e $EPHEM \
	    "$R_HTTPS" "$R_HTTP"

    # Split the trace into client->server and server->client
    # traces, which can be replayed from different nodes in
    # the network.
    #
    # Note: this can't be done until AFTER the address-rewriting step,
    # because pcap_addr addresses are defined in terms of the
    # client->server direction.  (this could be fixed, but it
    # hasn't been yet)
    #
    tcpdump -r $TMPDIR/TA-$CNT.pcap -w $TMPDIR/TA-server-$CNT.pcap \
	    src $SERVER_OUT_IP
    tcpdump -r $TMPDIR/TA-$CNT.pcap -w $TMPDIR/TA-client-$CNT.pcap \
	    dst $SERVER_OUT_IP

    CNT=$((CNT + 1))
done

# Weave together the rewritten files
#
# Note that pcap_weave can only handle a limited number of input files,
# so if the number of files is very large then you'll need to combine
# them as subsets rather than doing them all at once.

./pcap_weave -o $OUTPUT_SERVER_PCAP $TMPDIR/TA-server-*.pcap
./pcap_weave -o $OUTPUT_CLIENT_PCAP $TMPDIR/TA-client-*.pcap

echo -n "client stats: "
./find_rate.sh $OUTPUT_CLIENT_PCAP
echo -n "server stats: "
./find_rate.sh $OUTPUT_SERVER_PCAP

