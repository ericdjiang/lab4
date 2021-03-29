/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "vnscommand.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t arp_thread;

    pthread_create(&arp_thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    srand(time(NULL));
    pthread_mutexattr_init(&(sr->rt_lock_attr));
    pthread_mutexattr_settype(&(sr->rt_lock_attr), PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&(sr->rt_lock), &(sr->rt_lock_attr));

    pthread_attr_init(&(sr->rt_attr));
    pthread_attr_setdetachstate(&(sr->rt_attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->rt_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->rt_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t rt_thread;
    pthread_create(&rt_thread, &(sr->rt_attr), sr_rip_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/
void sr_handleIP(struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int len, char* interface/* lent */) {

}

void sr_handleARP(struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int len, char* interface/* lent */) {
  sr_ethernet_hdr_t ether_hdr;
  memcpy((uint8_t*)&ether_hdr, packet, sizeof(sr_ethernet_hdr_t));
  /*assert(ntohs(ether_hdr.ether_type) == ETHERTYPE_ARP); */
  sr_arp_hdr_t* arp = (sr_arp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));

  /* printf("Receive an ARP packet\n");
  printARPHeader((uint8_t*) arp); */
  print_hdr_eth((uint8_t*)&ether_hdr);
  print_hdr_arp((uint8_t*)&arp);

  print_addr_eth((uint8_t*)&ether_hdr.ether_shost);
  /* struct sr_arpreq* req = sr_arpcache_insert(&sr->cache, arp->ar_sha, arp->ar_sip); */
  /* If this is an ARP request packet */
  if (arp->ar_op == htons(arp_op_request)) {
    /* Insert the Sender MAC in this packet to your ARP cache */
    sr_arpcache_insert(&sr->cache, arp->ar_sha, arp->ar_sip);
    /* Checking the corresponding ARP Request Queue, find all the pending packets and send them out (This part is only for optimization purposes. You do not need to implement this part when you are implementing the checkpoint 1 and checkpoint 2)
    // Generate a correct ARP response
    // 1) Malloc a space to store an Ethernet header and ARP header */
    uint8_t* outgoing_packet = (uint8_t* ) malloc (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    sr_ethernet_hdr_t* ether_hdr_resp = (sr_ethernet_hdr_t* ) outgoing_packet;
    sr_arp_hdr_t* arp_hdr_resp = (sr_arp_hdr_t*) (outgoing_packet + sizeof(sr_ethernet_hdr_t));
    /* 2) Fill the ARP opcode, Sender IP, Sender MAC, Target IP, Target MAC in ARP header
    // 3) Fill the Source MAC Address, Destination MAC Address, Ethernet Type in the Ethernet header */
    memcpy(ether_hdr_resp->ether_shost, sr_get_interface(sr, interface)->addr, sizeof(sr_get_interface(sr, interface)->addr));
    memcpy(ether_hdr_resp->ether_dhost, ether_hdr.ether_shost, sizeof(ether_hdr.ether_shost));
    ether_hdr_resp->ether_type = ether_hdr.ether_type;

    arp_hdr_resp->ar_op = htons(arp_op_reply);
    arp_hdr_resp->ar_sip = arp->ar_tip;
    memcpy(arp_hdr_resp->ar_sha, sr_get_interface(sr, interface)->addr, sizeof(sr_get_interface(sr, interface)->addr));
    arp_hdr_resp->ar_tip = arp->ar_sip;
    memcpy(arp_hdr_resp->ar_tha, arp->ar_sha, sizeof(arp->ar_sha));

    arp_hdr_resp->ar_hln = arp->ar_hln;
    arp_hdr_resp->ar_pln = arp->ar_pln;
    arp_hdr_resp->ar_hrd = arp->ar_hrd;
    arp_hdr_resp->ar_pro = arp->ar_pro;

    print_hdr_eth(ether_hdr_resp);
    print_hdr_arp(arp_hdr_resp);
    
    /* 4) All the above information can be obtained from the received input packet. Note that you need to look up the source MAC address from the outgoing interface’s sr_if struct. 
    /* Send this ARP response back to the Sender */
    sr_send_packet(sr, outgoing_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface);
    free(outgoing_packet);
  }
}

void sr_handlepacket(struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int len, char* interface/* lent */) {
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* Lab4: Fill your code here */

  sr_ethernet_hdr_t ethernet_hdr;
  memcpy((uint8_t*)&ethernet_hdr, packet, sizeof(sr_ethernet_hdr_t));
  uint16_t packet_type = ntohs(ethernet_hdr.ether_type);
  printf("packet type %x \n", packet_type);

  switch (packet_type) {
  case ethertype_ip:
    sr_handleIP(sr, packet, len, interface);
    break;
  
  case ethertype_arp:
    sr_handleARP(sr, packet, len, interface);
    break;

  default:
    break;
  }

}/* end sr_ForwardPacket */
