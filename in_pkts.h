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

#ifndef _IN_PKTS_H_
#define _IN_PKTS_H_

typedef struct {
    pcap_t *in_pcap;
    struct timeval base_in_time;

    /*
     * If peeked is non-zero, then this means that we've read
     * at least one packet from in_pcap, and have used this
     * to set the base_in_time.  If not, then the base_in_time
     * is nonsense.
     */

    int peeked;

    /* if last_valid is non-zero, then last_rc is the
     * return value of the most recent call to pcap_next_ex
     * in in_pcap, last_hdr contains the most recent hdr,
     * and last_data contains the most recent data read
     * from in_pcap.  If last_valid is zero, then these
     * fields are undefined.
     */

    int last_valid;
    int last_rc;
    struct pcap_pkthdr *last_hdr;
    const u_char *last_data;
} in_pkts_t;

/*
 * Create a in_pkts_t structure for the given pcap_t source
 */
extern in_pkts_t *create_in_pkts(pcap_t *in_pcap);

/*
 * Peek at the current packet.  Note that this will repeatedly
 * look at the same packet over and over again; it will not
 * read the *next* packet until skip_pkt has been called
 */
extern int peek_pkt(in_pkts_t *in);

/*
 * discard the currently peek'd packet, if any
 */
extern int skip_pkt(in_pkts_t *in);

#endif /* _IN_PKTS_H_ */
