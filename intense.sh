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


# The input pcap has approximately 120 connections per second,
# all to 10.0.20.11 (from 10.0.20.12).
INCAP=pcaps/decoy-https-1200.pcap
EPHEM_INCR=120
ORIG_DA=10.0.20.11
ORIG_SA=10.0.20.12

# We want to make COPIES of the input pcap, between source 10.0.2.35
# and destination 10.0.3.34.
COPIES=100
DA=10.0.3.34
SA=10.0.2.35

SCRATCHDIR=./tmp
DSTCAP="$SCRATCHDIR/DSTCAP.pcap"

CNT=0
ALLOUTS=""
EPHEM=50000

mkdir -p "${SCRATCHDIR}"
if [ ! -d "${SCRATCHDIR}" ]; then
    echo "Error: cannot access scratch directory"
    exit 1
fi

# Isolate the forward packets; these are the only ones we'll duplicate
#

tcpdump -r "${INCAP}" -w "${DSTCAP}" tcp and dst "${ORIG_DA}"

# Next, create each of the time-shifted copies, with their
# ephemeral ports rewritten
#
while [ $CNT -lt $COPIES ]; do
    off=$(printf 0.%.3d $CNT)
    echo "($off)"

    tmp="${SCRATCHDIR}/T-tmp.pcap"
    out="${SCRATCHDIR}/T-$off.pcap"

    ./pcap_shift -b "$off" -o "$tmp" "${DSTCAP}"
    echo ./pcap_shift -b "$off" -o "$tmp" "${DSTCAP}"

    ./pcap_addr -i "$tmp" -o "$out" -e $EPHEM \
	${ORIG_SA}:${ORIG_DA}:0:443/${SA}:${DA}:0:443
    echo ./pcap_addr -i "$tmp" -o "$out" -e $EPHEM \
	${ORIG_SA}:${ORIG_DA}:0:443/${SA}:${DA}:0:443

    ALLOUTS="$ALLOUTS $out"

    CNT=$((CNT + 1))
    EPHEM=$((EPHEM + EPHEM_INCR))
    rm -f "${tmp}"

done

echo ALLOUTS $ALLOUTS

# And finally weave them all back together:
#
./pcap_weave -o OUT-$COPIES.pcap $ALLOUTS

