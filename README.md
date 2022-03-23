# project3

### SYN Flooding Attack

This attack is achieved when a server listening on a TCP socket is flooded with TCP SYN packets (packets whose SYN bit is set to 1 and all other flag bits are set to 0). For each received SYN packet, the server opens a TCP connection, allocates some resources, replies with a SYN-ACK packet and then waits for an ACK from the sender. However, the malicious sender does not send the ACK. This creates a half-open TCP connection at the server which occupies some resources. As the attacker sends many such SYN packets, the server resources get used up and as a result, legitimate connection requests are dropped. This is a form of denial-of-service attack. In most cases, the attacker generates the SYN packets from spoofed IP addresses. Spoofed IP addresses are randomly generated and do not correspond to the attacker's real IP address. They are used to hide the attacker's own identity.

Hint: To implement the above, you may need to use a dynamically growing array to store the source IP addresses of the incoming SYN packets. This array can be processed upon receiving the Cntrl+C signal to get the number of unique IP addresses stored in the array.

Testing your code: To test your code, you can send SYN packets to your loopback (lo) interface or localhost using hping3 on one terminal window while the sniffer is listening to the lo interface in another terminal window. You can issue the following command

`hping3 -c 100 -d 120 -S -w 64 -p 80 -i u100 --rand-source localhost`

### ARP Cache Poisoning

The Address Resolution Protocol (ARP) is used by systems to construct a mapping between network layer (Media Access Control) and link layer (Internet Protocol) addresses. Consider a simple scenario: two systems share a network - dcs_laptop has IP address 192.168.1.68 and is trying to communicate with broadband_router at 192.168.1.1. To achieve this, dcs_laptop broadcasts an ARP request asking for the MAC address of the node at 192.168.1.1. When broadband_router sees this message it responds with its MAC address. dcs_laptop will cache this address for future use and then use it to establish a connection.

The ARP protocol has a serious flaw in that it performs no validation. An attacker can craft a malicious ARP packet which tricks the router into associating the ip address of dcs_laptop with the attacker's own MAC address. This means all traffic bound for dcs_laptop will be redirected to the attacker, potentially exposing sensitive data or allowing for man-in-the-middle attacks. To make matters worse, ARP allows unsolicited responses, meaning dcs_laptop does not even have to send out a request - an attacker can simply broadcast a message informing all nodes to send dcs_laptop traffic to their machine.

Although ARP messages can be legitimate, the use of caching means they should be very rare. A burst of unsolicited ARP responses is a strong indication that an attacker has penetrated a network and is trying to take it over. You should add code which detect all ARP responses.

Hint: there is an ether_arp struct defined in netinet/if_ether.h

Testing your code: You have been provided with a python script which you may find useful when testing your code. The arp-poison.py script can be found in thetest directory. This can be run with the following command
`python3 arp-poison.py`

### Blacklisted URLs

Intrusion detection systems typically watch traffic originating from the network they protect in addition to attacks coming from outside. This can allow them to detect the presence of a virus trying to connect back to a control server for example, or perhaps monitor any attempts to smuggle sensitive information to the outside world. For this exercise, we have identified www.google.co.uk and www.bbc.com as a suspicious domains that we wish to monitor. Specifically, we wish to be alerted when we see HTTP traffic being sent to these domains.

Testing your code: One way to test your code for blacklisted URL detection is to use the wget command. On one terminal window you can run your sniffer code on the eth0 interface and in another terminal window run the following commands (one at a time)

`wget www.google.co.uk
wget www.bbc.com`

### Multithreading

ntrusion detection systems often monitor the traffic between the global internet and large corporate or government networks. As such they typically have deal with massive traffic volumes. In order to allow your system to handle high data rates you should make your code multi-threaded. There are several strategies you could choose to adopt to achieve this. Two common approaches are outlined below. Whatever approach you choose to implement you must remember to justify your decision in your report. For this work we will focus on POSIX threads you were introduced to in lab 3. In order to use POSIX threads, the lpthread linker flag must be added to the project makefile like so (should be done already):

`LDFLAGS := -lpthread -lpcap`
