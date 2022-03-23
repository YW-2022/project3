#include "sniff.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>
#include <netinet/if_ether.h>
#include <signal.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "dispatch.h"

extern int g_nums_arp;
extern int g_nums_syn;
extern int g_nums_ips;
extern int g_nums_black;

#include "vecs.h"
my_vector vector;

// Compare with the value of vector. 
// If exits, it means that the IP is duplicated. ---- Do nothing.
// If not, it means that it is a new differenct IP.  ---- AppendMyVector().
int IsContainValue(long vals)
{
  return AppendMyVector(&vector,vals);
}

// Print the intrusion detection report.
void printResult(int a){
  printf("Intrusion Detection Report:\n");
  printf("%d SYN packets detected from %d different IPs (syn attack)\n",g_nums_syn,g_nums_ips);
  printf("%d ARP responses (cache poisoning)\n",  g_nums_arp);
  printf("%d URL Blacklist violations\n", g_nums_black);
  exit(0); 
}

// pcap_handler callback()
void sniff_callback(int verbose, const struct pcap_pkthdr *pheader,

	    const u_char *packet){
      // Parsing parameters using dispatch()

      dispatch((struct pcap_pkthdr *)pheader, packet, verbose);
}

// Application main sniffing loop
void sniff(char *interface, int verbose) {

  char errbuf[PCAP_ERRBUF_SIZE];

	// Initialize the vector object
	InitMyVector(&vector);

  // When capture the control+c keyboard message, it will run the printResult function
  signal(SIGINT, &printResult);

  pcap_t *pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);
  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  } else {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }
  struct pcap_pkthdr header;
  const unsigned char *packet;

  // pcap_loop: message loop, used to monitor and process network requests sent. 
  // pcap_loop() processes packets from a live capture or ''savefile'' until 
  // cnt packets are processed, the end of the ''savefile'' is reached when reading from a ''savefile''. 
  pcap_loop(pcap_handle,-1,sniff_callback, verbose);
  
}

// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length) {
  unsigned int i;
  static unsigned long pcount = 0;
  // Decode Packet Header
  struct ether_header *eth_header = (struct ether_header *) data;
  printf("\n\n === PACKET %ld HEADER ===", pcount);
  printf("\nSource MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_shost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_dhost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nType: %hu\n", eth_header->ether_type);
  printf(" === PACKET %ld DATA == \n", pcount);
  // Decode Packet Data (Skipping over the header)
  int data_bytes = length - ETH_HLEN;
  const unsigned char *payload = data + ETH_HLEN;
  const static int output_sz = 20; // Output this many bytes at a time
  while (data_bytes > 0) {
    int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    // Print data in raw hexadecimal form
    for (i = 0; i < output_sz; ++i) {
      if (i < output_bytes) {
        printf("%02x ", payload[i]);
      } else {
        printf ("   "); // Maintain padding for partial lines
      }
    }
    printf ("| ");
    // Print data in ascii form
    for (i = 0; i < output_bytes; ++i) {
      char byte = payload[i];
      if (byte > 31 && byte < 127) {
        // Byte is in printable ascii range
        printf("%c", byte);
      } else {
        printf(".");
      }
    }
    printf("\n");
    payload += output_bytes;
    data_bytes -= output_bytes;
  }
  pcount++;
}
