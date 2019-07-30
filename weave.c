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

int weave_time(in_pkts_t **ins, unsigned int in_cnt, pcap_dumper_t *out)
{
    unsigned int i;
    int *stati = (int *) malloc(in_cnt * sizeof(int)); /* TODO: check */

    /*
     * Note use of magic numbers; pcap_next_ex returns 1 if successful,
     * negative for failures, and 0 for live capture that has timed
     * out (which should never happen because we're not doing live
     * capture)
     */
    for (i = 0; i < in_cnt; i++) {
	stati[i] = 1; /* nothing went wrong in the past... */
    }

    for (;;) {
	int earliest;

	/*
	 * For each in_pkts that hasn't experienced an error, try
	 * to peek at the next pkt.  (If unsuccessful, we won't
	 * consider this in_pkts again)
	 */
	for (i = 0; i < in_cnt; i++) {
	    if (stati[i] == 1) {
		stati[i] = peek_pkt(ins[i]);
	    }
	}

	/* find the earliest time.  Unfortunately, the earliest
	 * actual time is a valid time, so we can't use it as a
	 * sentinel.  Instead, use the index of the in_pkts_t with
	 * the earliest time as the marker, and use a sentinel
	 * of -1.
	 */

	earliest = -1;

	for (i = 0; i < in_cnt; i++) {
	    if (stati[i] == 1) {
		if (earliest == -1) {
		    earliest = i;
		}
		else if (timercmp(&(ins[i]->last_hdr->ts),
			    &(ins[earliest]->last_hdr->ts), <)) {
		    earliest = i;
		}
	    }
	}

	if (earliest != -1) {
	    in_pkts_t *in = ins[earliest];
	    pcap_dump((u_char *) out, in->last_hdr, in->last_data);
	    skip_pkt(in);
	}
	else {
	    break;
	}
    }

    return 0; /* meaningless */
}

typedef struct {
    char *out_fname;
    char **in_fnames;
    int in_fnames_cnt;
} options_t;

/*
 * MAX_IN_PKTS is arbitrary, but seems reasonable.
 */

#define MAX_IN_PKTS		(100)
#define DEFAULT_OUTFILE		("out.pcap")

void usage(char *progname)
{
    printf("usage: %s [-h] [-o outfile] infile1 .. infileN\n", progname);
    printf("\n");
    printf("Combine the given input files, sorted by timestamp order\n");
    printf("\n");
    printf("-h           Print usage message and exit\n");
    printf("-o outfile   Write the new pcap file to the given file\n");
    printf("\n");
    printf("    The default outfile is %s.\n", DEFAULT_OUTFILE);
    printf("    There must be at least one input file, and fewer than %d\n",
	    MAX_IN_PKTS);
}

int parse_args(options_t *options, int argc, char **argv)
{
    int opt;
    extern int optind;
    extern char *optarg;

    options->out_fname = DEFAULT_OUTFILE;

    while ((opt = getopt(argc, argv, "ho:")) != EOF) {
	switch (opt) {
	    case 'h':
		usage(argv[0]);
		exit(0);
	    case 'o':
		options->out_fname = optarg;
		break;
	    default:
		usage(argv[0]);
		return -5;
	}
    }

    options->in_fnames = argv + optind;
    options->in_fnames_cnt = argc - optind;

    if (options->in_fnames_cnt == 0) {
	printf("error: no input files provided\n");
	usage(argv[0]);
	return -2;
    }
    else if (options->in_fnames_cnt > MAX_IN_PKTS) {
	printf("error: max of %d input files permitted\n", MAX_IN_PKTS);
	usage(argv[0]);
	return -3;
    }

    return 0;
}

int main(int argc, char **argv)
{
    options_t options;
    pcap_dumper_t *out = NULL;
    pcap_t *out_pcap = NULL;
    in_pkts_t *in_pkts[MAX_IN_PKTS];
    int rc;
    int i;

    rc = parse_args(&options, argc, argv);
    if (rc) {
	exit(rc);
    }

    for (i = 0; i < options.in_fnames_cnt; i++) {
	pcap_t *in_pcap = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];

	in_pcap = pcap_open_offline(options.in_fnames[i], errbuf);
	if (!in_pcap) {
	    printf("error: could not open [%s] for input\n", options.in_fnames[i]);
	    exit(1);
	}
	in_pkts[i] = create_in_pkts(in_pcap);
    }

    out_pcap = pcap_open_dead(DLT_EN10MB, 65536);
    out = pcap_dump_open(out_pcap, options.out_fname);
    if (!out) {
	printf("error: could not open [%s] for output\n", options.out_fname);
	exit(1);
    }

    weave_time(in_pkts, i, out);

    pcap_dump_close(out);

    exit(0);
}
