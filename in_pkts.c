/*
 * This material is funded in part by a grant from the United States
 * Department of State. The opinions, findings, and conclusions stated
 * herein are those of the authors and do not necessarily reflect
 * those of the United States Department of State.
 *
 * Copyright 2016 - Raytheon BBN Technologies Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <pcap/pcap.h>

#include "in_pkts.h"

in_pkts_t *create_in_pkts(pcap_t *in_pcap)
{
    in_pkts_t *new;

    if (!in_pcap) {
	return NULL;
    }

    new = malloc(sizeof(in_pkts_t));
    if (new == NULL) {
	return NULL;
    }

    new->in_pcap = in_pcap;
    new->peeked = 0;
    new->last_valid = 0;
    new->last_data = NULL;

    return new;
}

int peek_pkt(in_pkts_t *in)
{

    if (!in->last_valid) {
	in->last_rc = pcap_next_ex(in->in_pcap,
		&(in->last_hdr), &(in->last_data));
	if (in->last_rc != 1) {
	    return in->last_rc;
	}
	in->last_valid = 1;

	if (!in->peeked) {
	    in->peeked = 1;
	    in->base_in_time = in->last_hdr->ts;
	}
    }
    return in->last_rc;
}

int skip_pkt(in_pkts_t *in)
{

    in->last_valid = 0;
    return 0;
}
