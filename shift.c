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

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <pcap/pcap.h>

#include "in_pkts.h"

/*
 * Copy the packets from in to out, setting their timestamps to
 * be relative to the given offset (i.e. a timestamp that has the
 * same value as offset will be replaced with a zero timestamp)
 */
int rel_time(in_pkts_t *in, pcap_dumper_t *out, struct timeval offset)
{
    struct timeval base;
    int rc;

    rc = peek_pkt(in);
    if (rc != 1) {
	return rc;
    }

    timersub(&(in->base_in_time), &offset, &base);

    for (;;) {
	rc = peek_pkt(in);
	if (rc != 1) {
	    break;
	}

	skip_pkt(in);

	timersub(&(in->last_hdr->ts), &base, &(in->last_hdr->ts));
	pcap_dump((u_char *) out, in->last_hdr, in->last_data);
    }

    return 0; /* ?? */
}

#define DEFAULT_OUTFILE		("out.pcap")
#define DEFAULT_BASETIME	(0.0)

typedef struct {
    char *in_fname;
    char *out_fname;
    struct timeval base_time;
} options_t;

void usage(char *progname)
{
    printf("usage: %s [-h] [-b basetime] [-o outfile] infile\n", progname);
    printf("\n");
    printf("-h           Print usage message and exit\n");
    printf("-b basetime  Rewrite timestamps to begin at the given\n");
    printf("             basetime (given in seconds)\n");
    printf("-o outfile   Write the new pcap file to the given file\n");
    printf("\n");
    printf("    The basetime must be >= 0.0.\n");
    printf("    The default basetime is %f.\n", DEFAULT_BASETIME);
    printf("    The default outfile is %s.\n", DEFAULT_OUTFILE);
}

int parse_args(options_t *options, int argc, char **argv)
{
    int opt;
    double basetime = DEFAULT_BASETIME;
    extern int optind;
    extern char *optarg;
    double sec, fsec;

    options->out_fname = DEFAULT_OUTFILE;

    while ((opt = getopt(argc, argv, "hb:o:")) != EOF) {
	switch (opt) {
	    case 'h':
		usage(argv[0]);
		exit(0);

	    case 'b': {
		char *endptr;

		basetime = strtod(optarg, &endptr);
		if (*endptr) {
		    usage(argv[0]);
		    return -3;
		}
		if (basetime < 0.0) {
		    usage(argv[0]);
		    return -4;
		}
		break;
	    }
	    case 'o':
		options->out_fname = optarg;
		break;
	    default:
		usage(argv[0]);
		return -5;
	}
    }

    sec = (long) basetime;
    fsec = basetime - sec;

    options->base_time.tv_sec = sec;
    options->base_time.tv_usec = (unsigned int)
	    (fsec * 1000000.0);

    if (optind == argc) {
	printf("error: no input file provided\n");
	usage(argv[0]);
	return -1;
    }
    else if (optind != (argc - 1)) {
	printf("error: more than one input file provided\n");
	usage(argv[0]);
	return -2;
    }
    else {
	options->in_fname = argv[optind];
    }

    return 0;
}

int main(int argc, char **argv)
{
    pcap_dumper_t *out = NULL;
    pcap_t *out_pcap = NULL;
    pcap_t *in_pcap = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    in_pkts_t *in_pkts;
    options_t options;
    int rc;

    rc = parse_args(&options, argc, argv);
    if (rc != 0) {
	exit(rc);
    }

    in_pcap = pcap_open_offline(options.in_fname, errbuf);
    if (!in_pcap) {
	printf("error: could not open [%s] for input\n", options.in_fname);
	exit(1);
    }

    in_pkts = create_in_pkts(in_pcap);
    if (!in_pkts) {
	printf("error: could not create input pkts struct\n");
	exit(1);
    }

    out_pcap = pcap_open_dead(DLT_EN10MB, 65536);
    out = pcap_dump_open(out_pcap, options.out_fname);
    if (!out) {
	printf("error: could not open [%s] for output\n", options.out_fname);
	exit(1);
    }

    rel_time(in_pkts, out, options.base_time);

    pcap_dump_close(out);

    exit(0);
}
