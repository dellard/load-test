
# load-test

Tools to create network loads by editing/combining PCAP files to create
fake flows that correctly mimic the original flows.

For example, a trace of a single flow can be duplicated to create a copy
of the flow that has the same contents, but uses a different ephermal
port, and possibly different source and destination IP addresses and
destination port.  This copy can be shifted in time to start earlier or
later than the original flow.  Using this mechanism, a small trace from
a 100Mb link can be used to create a realistic 100Gb workload that can
be played back with tcprelay or a similar tool.

See the HOWTO.txt for examples, and read the individual scripts for more
detail.

## Building

```
make
```

This leaves the executables in the current directory.  This is nothing
fancy.  There is no install target right now.

## Notes

 * These scripts have only been tested and used on Ubuntu 16.04, and there
   may be dependencies on this OS.  Portability fixes are welcome.
 * The Makefile assumes that a basic gcc setup,
   libpcap, and the libpcap development packages have been installed.
 * The `pcap_addr` script assumes Python 2.7.  It should be ported to 
   Python 3.
