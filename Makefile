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

# Makefile for pcap_shift and pcap_weave; tested on Ubuntu 12.04.
# No attempt has been made to make this portable to other platforms
# yet.

PROGS		= $(SHIFT) $(WEAVE)

SHIFT		= pcap_shift
WEAVE		= pcap_weave

SHIFT_SRC	= in_pkts.c shift.c
SHIFT_OBJ	= $(SHIFT_SRC:.c=.o)

WEAVE_SRC	= in_pkts.c weave.c
WEAVE_OBJ	= $(WEAVE_SRC:.c=.o)

CFLAGS	= -Wall -g
LIBS	= -lpcap -lm

default:	$(PROGS)

$(WEAVE): $(WEAVE_OBJ)
	$(CC) -o $@ $(WEAVE_OBJ) $(LIBS)

$(SHIFT): $(SHIFT_OBJ)
	$(CC) -o $@ $(SHIFT_OBJ) $(LIBS)

clean:
	rm -f $(PROGS) $(SHIFT_OBJ) $(WEAVE_OBJ)
