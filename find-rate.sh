#!/bin/sh
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

# given a pcap file, figure out how much data was occupying
# the link by the packets in the file.  Note that this
# does not take into account "direction", so if you are
# only interested in packets in one direction then you should
# filter the pcap file before passing it in.
#
# This assumes that the pcap file contains the Ethernet headers,
# and that the packets appear in the file in chronological order
# (so we can find the elapsed time by considering only the first
# and last packets).
#

if [ -z $1 ]; then
    echo "ERROR: $0: no input pcap provided"
    exit 1
fi

INFILE=$1

PKTS_AND_BYTES=$(tcpdump -r "${INFILE}" -n -tt -e | \
	awk '{print $9}' | sed -e 's/://' | \
	awk '{c+=1; s+=$1}; END{print c, s}')
echo $PKTS_AND_BYTES
PKTCOUNT=$(echo $PKTS_AND_BYTES | awk '{print $1}')
BYTECOUNT=$(echo $PKTS_AND_BYTES | awk '{print $2}')

FIRSTLAST=$(tcpdump -r "${INFILE}" -tt | \
	awk 'NR==1{print $1}; END{print $1}')

STARTTIME=$(echo $FIRSTLAST | awk '{print $1}')
ENDTIME=$(echo $FIRSTLAST | awk '{print $2}')
ELAPSED=$(echo "$ENDTIME - $STARTTIME" | bc -l)

BITCOUNT=$(echo "8 * $BYTECOUNT" | bc -l)
BITRATE=$(echo "$BITCOUNT / $ELAPSED" | bc -l)

echo "$INFILE pkts $PKTCOUNT bytes $BYTECOUNT bits $BITCOUNT elapsed $ELAPSED b/s $BITRATE"
