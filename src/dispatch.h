#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>
#include "analysis.h"

void dispatch(struct pcap_pkthdr *header, 
              const unsigned char *packet,
              int verbose);

#endif
