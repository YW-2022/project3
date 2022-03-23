#include "analysis.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "sniff.h"

// Count the number of ARP, SYN, IP, Blacklist URL
extern int g_nums_arp;
extern int g_nums_syn;
extern int g_nums_ips;
extern int g_nums_black;

// Struct of ARP packet
struct struct_arp_packet {

	struct	arphdr ea_hdr;	/* fixed-size header */
	uint8_t arp_sha[ETH_ALEN];  /* sender hardware address */
	uint8_t arp_spa[4];  /* sender protocol address */
	uint8_t arp_tha[ETH_ALEN];  /* target hardware address */
	uint8_t arp_tpa[4];  /* target protocol address */
};


// analyse()
void analyse(struct pcap_pkthdr *header,
             const unsigned char *packet,
             int verbose) {

  struct ether_header *linklayer = (struct ether_header *)packet;

  // Location of IP = Packet + SIZE_ETHERNET = Packet + 14
  struct iphdr *iplayer = (struct iphdr *) (packet+14);

  // Location of TCP = Packet + SIZE_ETHERNET + {IP header length}
  struct tcphdr *tcplayer = (struct tcphdr *) (packet+14 + iplayer->ihl*4);

    

  // SYN flooding attack
  // If SYN bit is set to 1 and all other flag bits are set to 0 ---- SYN attack
  // If SYN is true
  if(tcplayer->syn){

      // If URG, ACK, PSH, RST, FIN are false
      if(!(tcplayer->urg && tcplayer->ack && tcplayer->psh && tcplayer->rst && tcplayer->fin)){

        // Number of SYN plus one
        g_nums_syn = g_nums_syn + 1;

        // Record different IPs
        // If the vector does not contain the ip
        if(IsContainValue(iplayer->saddr) == 0){

          // The number of IPs plus one
          g_nums_ips = g_nums_ips + 1; 

        }
      }
  }

  // ARP cache poisoning
  // If the same MAC address but different IP addresses are detected, it means an ARP attack is taking place. 
  // The ntohs() function converts the unsigned short integer netshort from network byte order to host byte order.
  // If the ether_type = ARP
  if(ntohs(linklayer->ether_type) == ETHERTYPE_ARP){

      // Define an unsigned char *linkPackets
      const unsigned char *linkPackets = packet + ETH_HLEN;

      // Define a struct *arp_Packet
      struct struct_arp_packet *arp_Packet = (struct struct_arp_packet *) linkPackets;
      struct arphdr *arp_Header = (struct arphdr *) &arp_Packet->ea_hdr;
      if(ntohs(arp_Header->ar_op) == ARPOP_REPLY){

        // The number of ARP plus one
        g_nums_arp = g_nums_arp +1;

      }
  }

  // Blacklisted URLs
  // The ntohs() function converts the unsigned short integer netshort from network byte order to host byte order.
  // If the ether_type = IP
  if(ntohs(linklayer->ether_type) == ETHERTYPE_IP){

        // Define an unsigned char *ip
        const unsigned char *ip = packet + ETH_HLEN + (4*iplayer->ihl);

        // Define a char *http
        const char *http = (char *) (ip+(4*tcplayer->doff));

        // Define a int variable and assign a value
        int num_str = header->len - ((sizeof(struct ether_header) + 4*(iplayer->ihl)+4*(tcplayer->doff)));
      
        // If the variable greater than 0
        if(num_str > 0){

        // Define an unsigned char *new_string and use malloc to allocate memory
        unsigned char *new_string = malloc(sizeof(char)*(num_str+1));

        // Define variables outside the loop
        int i;
        // The ntohs() function converts the unsigned short integer netshort from network byte order to host byte order.
        // If the port number = 80
        if((ntohs(tcplayer->dest) == 80)){
          for (i = 0; i < num_str; i++)
          {
            char c = (char) http[i];
            new_string[i] = c;
          }
          new_string[num_str] = '\0';
        } 

        // Store source IP address and destination IP address.
        // INET_ADDRSTRLEN: Length of the string form for IP.
        // Define the char array
        char ipSaddr[INET_ADDRSTRLEN];
        char ipDaddr[INET_ADDRSTRLEN];

        // inet_ntop - convert IPv4 and IPv6 addresses from binary to text form
        inet_ntop(AF_INET, &(iplayer->saddr), ipSaddr, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(iplayer->daddr), ipDaddr, INET_ADDRSTRLEN);

        // Check blacklist   
        // strstr() - The function char *strstr() function finds the first occurrence of the substring needle in the string haystack.
        if (strstr((const char *)new_string, "www.google.co.uk") && (ntohs(tcplayer->dest) == 80)){
            printf("==========================\n");
            printf("Blacklisted URL violation detected\n"); 
            printf("Source IP address:%s \n",ipSaddr);  /* Print the source IP address*/
            printf("Destination IP address:%s \n",ipDaddr);  /* Print the destination IP address*/
            printf("==========================\n");
          g_nums_black = g_nums_black+1; /* The number of blacklisted URLs plus*/
        }

        // strstr() - The function char *strstr() function finds the first occurrence of the substring needle in the string haystack.
        if (strstr((const char *)new_string, "www.bbc.com") && (ntohs(tcplayer->dest) == 80))
        {
            printf("==========================\n");
            printf("Blacklisted URL violation detected\n");
            printf("Source IP address:%s \n",ipSaddr);  /* Print the source IP address*/
            printf("Destination IP address:%s \n",ipDaddr);  /* Print the destination IP address*/
            printf("==========================\n");  
          g_nums_black = g_nums_black+1;  /* The number of blacklisted URLs plus*/
        }
      }
    }

  





}
