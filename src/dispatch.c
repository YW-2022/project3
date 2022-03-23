#include "dispatch.h"

#include <pcap.h>

#include "sniff.h"
#include "analysis.h"

// Count the number of ARP, SYN, IP, Blacklist URL
extern int g_nums_arp;
extern int g_nums_syn;
extern int g_nums_ips;
extern int g_nums_black;

#include <pthread.h>
#include <stdio.h>
#include <sys/time.h>
#include <string.h>
#define MAX 10
pthread_t thread[2];  /*Create 2 threads at the process startup*/

/* int pthread_mutex_lock(pthread_mutex_t *mutex) : 
Locks a mutex object, which identifies a mutex. 
If the mutex is already locked by another thread, the thread waits for 
the mutex to become available. The thread that has locked a mutex becomes 
its current owner and remains the owner until the same thread has unlocked it. */
pthread_mutex_t mut;  

// Multithreading
void *thread_func(void *arg);

// Define a struct ---- Store the parameters in dispatch()
struct info
{
  struct pcap_pkthdr *header;
  const unsigned char *packet;
  int verbose;
} info;

// dispatch()
void dispatch(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose)
{
  // Define an int variable
  int temp;

  // memset(): Fill block of memory. 
  memset(&thread, 0, sizeof(thread)); 

  // Define a struct called *new_packet and use malloc() to dynamically allocate memory.
  struct info *new_packet = malloc(sizeof(struct info));

  // Three parameters: header, packet, verbose
  new_packet->header = (struct pcap_pkthdr *)header;
  new_packet->packet = (const unsigned char *)packet;
  new_packet->verbose = verbose;
  // Create thread
  temp = pthread_create(&thread[0], NULL, thread_func, (void *)new_packet);
  void *p = NULL;
  pthread_join(thread[0], &p);
}

void *thread_func(void *arg)
{
  // The mutex object referenced by mutex is locked by calling pthread_mutex_lock(). 
  // If the mutex is already locked, the calling thread blocks until the mutex becomes available. 
  // This operation returns with the mutex object referenced by mutex in the locked state with the calling thread as its owner.
  pthread_mutex_lock(&mut);
  // Define a struct called *base.
  struct info *base = (struct info *)(arg);
  // Call the analyse() function
  analyse(base->header, base->packet, base->verbose);
  // The pthread_mutex_unlock() function shall release the mutex object referenced by mutex. 
  pthread_mutex_unlock(&mut);
  // Terminate calling thread
  pthread_exit(NULL);
}