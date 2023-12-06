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
#include <string.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

#define min(a, b) ((a) < (b) ? (a) : (b))

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
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    pthread_detach(thread);
    
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

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
  struct sr_if* receiving_iface = sr_get_interface(sr, interface);
  assert(receiving_iface);
  sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *)packet;
  assert(ether_hdr);
  if(ether_hdr->ether_type == htons(ethertype_arp)){  /* it is an arp packet */
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
    assert(arp_hdr);
    if(arp_hdr->ar_op == htons(arp_op_request) && arp_hdr->ar_tip==receiving_iface->ip){  /* it is a request to me */
      uint8_t *arp_reply = malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));
      sr_ethernet_hdr_t *new_ether_hdr = (sr_ethernet_hdr_t *)arp_reply;
      sr_arp_hdr_t *new_arp_hdr = (sr_arp_hdr_t *)(arp_reply+sizeof(sr_ethernet_hdr_t));
      /* set arp_reply header(ether,arp) */
      memcpy(new_ether_hdr->ether_shost, receiving_iface->addr, ETHER_ADDR_LEN);
      memcpy(new_ether_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
      new_ether_hdr->ether_type = htons(ethertype_arp);
      
      new_arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
      new_arp_hdr->ar_pro = htons(ethertype_ip);
      new_arp_hdr->ar_hln = 6;
      new_arp_hdr->ar_pln = 4;
      new_arp_hdr->ar_op = htons(arp_op_reply);
      memcpy(new_arp_hdr->ar_sha, receiving_iface->addr, ETHER_ADDR_LEN);
      new_arp_hdr->ar_sip = receiving_iface->ip;
      memcpy(new_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
      new_arp_hdr->ar_tip = arp_hdr->ar_sip;
      /* send arp reply */
      sr_send_packet(sr, arp_reply, sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t), receiving_iface->name);
      free(arp_reply);
    }else if(arp_hdr->ar_op == htons(arp_op_reply)){  /* it is a reply to me */
      printf("It is an arp reply:\n");
      print_hdrs(packet, len);
      struct sr_arpreq *matching_req = sr_arpcache_insert(&(sr->cache),arp_hdr->ar_sha,arp_hdr->ar_sip);
      if(matching_req){ /* The arp reply's corresponding request has packets waiting to send */
        struct sr_packet *pkt;
        for(pkt=matching_req->packets;pkt!=NULL;pkt=pkt->next){
          sr_ethernet_hdr_t *old_ether_hdr = (sr_ethernet_hdr_t *)(pkt->buf);
          assert(old_ether_hdr);
          memcpy(old_ether_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
          sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
        }
      }
      sr_arpreq_destroy(&(sr->cache), matching_req);
    }
  }else if(ether_hdr->ether_type == htons(ethertype_ip)){ /* it is an ip packet */
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    assert(ip_hdr);
    /* verify checksum */
    uint16_t old_cksum = ip_hdr->ip_sum;
    ip_hdr->ip_sum=0;
    uint16_t new_cksum = cksum(ip_hdr,sizeof(sr_ip_hdr_t));
    if(old_cksum!=new_cksum){ /* if checksum is not correct, drop the packet */
      printf("Checksum is not correct! Packet dropped\n");
      return;
    }

    struct sr_if* matching_iface;
    for(matching_iface=sr->if_list;matching_iface!=NULL;matching_iface=matching_iface->next){
      if(matching_iface->ip==ip_hdr->ip_dst)  break;
    }
    if(matching_iface){ /* ip packet is for me(one of router interfaces) */
      struct in_addr tar_ip_addr;
      tar_ip_addr.s_addr = matching_iface->ip;
      printf("The packet is for me, targeted to one of my interfaces: %s\n", inet_ntoa(tar_ip_addr));
      if(ip_hdr->ip_p==ip_protocol_icmp){ /* it is icmp echo, send back icmp echo reply(type 0, code 0) */
        printf("It is an icmp echo\n");
        sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        assert(icmp_hdr);

        uint8_t *echo_reply = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        sr_ethernet_hdr_t *new_ether_hdr = (sr_ethernet_hdr_t *)echo_reply;
        sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(echo_reply + sizeof(sr_ethernet_hdr_t));
        sr_icmp_t3_hdr_t *new_icmp_hdr = (sr_icmp_t3_hdr_t *)(echo_reply + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        /* set header(icmp,ip,ether) */
        memcpy(new_icmp_hdr,icmp_hdr,sizeof(sr_icmp_t3_hdr_t));
        new_icmp_hdr->icmp_type = 0; 
        new_icmp_hdr->icmp_code = 0; 
        new_icmp_hdr->icmp_sum = 0;
        new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

        new_ip_hdr->ip_v = 4;
        new_ip_hdr->ip_hl = 5;
        new_ip_hdr->ip_tos = 0;
        new_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        new_ip_hdr->ip_id = ip_hdr->ip_id; 
        new_ip_hdr->ip_off = ip_hdr->ip_off;
        new_ip_hdr->ip_ttl = 64;
        new_ip_hdr->ip_p = ip_protocol_icmp;
        new_ip_hdr->ip_src = matching_iface->ip;
        new_ip_hdr->ip_dst = ip_hdr->ip_src;
        new_ip_hdr->ip_sum = 0;
        new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

        new_ether_hdr->ether_type = htons(ethertype_ip);
        memcpy(new_ether_hdr->ether_shost, receiving_iface->addr, ETHER_ADDR_LEN);
        memcpy(new_ether_hdr->ether_dhost, ether_hdr->ether_shost, ETHER_ADDR_LEN);

        /* send echo reply */
        sr_send_packet(sr, echo_reply, sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t), interface);
        free(echo_reply);
      }else{  /* send Port unreachable (type 3, code 3) */
        printf("It is a TCP/UDP packet, probably for Traceroute\n");
        print_hdrs(packet, len);
        uint8_t *port_unreachable = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        sr_ethernet_hdr_t *new_ether_hdr = (sr_ethernet_hdr_t *)port_unreachable;
        sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(port_unreachable + sizeof(sr_ethernet_hdr_t));
        sr_icmp_t3_hdr_t *new_icmp_hdr = (sr_icmp_t3_hdr_t *)(port_unreachable + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        /* set header(icmp,ip,ether) */
        new_icmp_hdr->icmp_type = 3; 
        new_icmp_hdr->icmp_code = 3;
        new_icmp_hdr->icmp_sum = 0;
        new_icmp_hdr->unused = 0;
        new_icmp_hdr->next_mtu = 0;
        memcpy(new_icmp_hdr->data, packet+sizeof(sr_ethernet_hdr_t), min(ICMP_DATA_SIZE, len-sizeof(sr_ethernet_hdr_t))); /* in case ip_packet size of original packet is smaller than ICMP_DATA_SIZE */
        new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

        new_ip_hdr->ip_v = 4;
        new_ip_hdr->ip_hl = 5;
        new_ip_hdr->ip_tos = 0;
        new_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        new_ip_hdr->ip_id = 0; 
        new_ip_hdr->ip_off = 0;
        new_ip_hdr->ip_ttl = 64;
        new_ip_hdr->ip_p = ip_protocol_icmp;
        new_ip_hdr->ip_src = receiving_iface->ip;
        new_ip_hdr->ip_dst = ip_hdr->ip_src;
        new_ip_hdr->ip_sum = 0;
        new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

        new_ether_hdr->ether_type = htons(ethertype_ip);
        memcpy(new_ether_hdr->ether_shost, receiving_iface->addr, ETHER_ADDR_LEN);
        memcpy(new_ether_hdr->ether_dhost, ether_hdr->ether_shost, ETHER_ADDR_LEN);
        /* send port unreachable */
        printf("About to send Port Unreachable(for Traceroute) packet: \n");
        print_hdrs(port_unreachable, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        sr_send_packet(sr, port_unreachable, sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t), interface);
        free(port_unreachable);
      }
    }else{  /* it is not for me */
      printf("It is a forwarding packet: \n");
      print_hdrs(packet, len);
      uint8_t new_ttl = ip_hdr->ip_ttl - 1;
      uint8_t *ttl_exceed = NULL;
      if(new_ttl==0){ /* check Time_to_live */
        ttl_exceed = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        sr_ethernet_hdr_t *ttl_ether_hdr = (sr_ethernet_hdr_t *)ttl_exceed;
        sr_ip_hdr_t *ttl_ip_hdr = (sr_ip_hdr_t *)(ttl_exceed + sizeof(sr_ethernet_hdr_t));
        sr_icmp_t3_hdr_t *ttl_icmp_hdr = (sr_icmp_t3_hdr_t *)(ttl_exceed + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        /* set header(icmp,ip,ether) */
        ttl_icmp_hdr->icmp_type = 11; 
        ttl_icmp_hdr->icmp_code = 0;
        ttl_icmp_hdr->icmp_sum = 0;
        ttl_icmp_hdr->unused = 0;
        ttl_icmp_hdr->next_mtu = 0;
        memcpy(ttl_icmp_hdr->data, packet+sizeof(sr_ethernet_hdr_t), min(ICMP_DATA_SIZE, len-sizeof(sr_ethernet_hdr_t))); /* in case ip_packet size of original packet is smaller than ICMP_DATA_SIZE */
        ttl_icmp_hdr->icmp_sum = cksum(ttl_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

        ttl_ip_hdr->ip_v = 4;
        ttl_ip_hdr->ip_hl = 5;
        ttl_ip_hdr->ip_tos = 0;
        ttl_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        ttl_ip_hdr->ip_id = 0; 
        ttl_ip_hdr->ip_off = 0;
        ttl_ip_hdr->ip_ttl = 64;
        ttl_ip_hdr->ip_p = ip_protocol_icmp;
        ttl_ip_hdr->ip_src = receiving_iface->ip;
        ttl_ip_hdr->ip_dst = ip_hdr->ip_src;
        ttl_ip_hdr->ip_sum = 0;
        ttl_ip_hdr->ip_sum = cksum(ttl_ip_hdr, sizeof(sr_ip_hdr_t));

        ttl_ether_hdr->ether_type = htons(ethertype_ip);
        memcpy(ttl_ether_hdr->ether_shost, receiving_iface->addr, ETHER_ADDR_LEN);
        memcpy(ttl_ether_hdr->ether_dhost, ether_hdr->ether_shost, ETHER_ADDR_LEN);

        printf("About to send Time Exceed packet: \n");
        print_hdrs(ttl_exceed, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
      }
      /* check longest prefix match */
      struct sr_rt* matching_entry = longest_prefix_match(sr, ip_hdr->ip_dst);
      if(matching_entry){ /* find match */
        if(ttl_exceed){ /* sent time exceed */
          sr_send_packet(sr, ttl_exceed, sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t), interface);
          free(ttl_exceed);
        }else{  /* forward packet */
          struct sr_if* outgoing_iface = sr_get_interface(sr, matching_entry->interface);
          uint8_t *forward_packet = (uint8_t *)malloc(len);
          memcpy(forward_packet, packet, len);
          sr_ethernet_hdr_t *fwd_ether_hdr = (sr_ethernet_hdr_t *)forward_packet;
          sr_ip_hdr_t *fwd_ip_hdr = (sr_ip_hdr_t *)(forward_packet + sizeof(sr_ethernet_hdr_t));
          /* set ip header(recompute checksum) and ether header */
          fwd_ip_hdr->ip_ttl = new_ttl;
          fwd_ip_hdr->ip_sum = 0;
          fwd_ip_hdr->ip_sum = cksum(fwd_ip_hdr, sizeof(sr_ip_hdr_t));

          memcpy(fwd_ether_hdr->ether_shost, outgoing_iface->addr, ETHER_ADDR_LEN);

          printf("About to send Forwarding packet through %s: \n", outgoing_iface->name);
          print_hdrs(forward_packet, len);

          /* ready to forward */
          struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), (matching_entry->gw).s_addr);
          if(arp_entry){
            memcpy(fwd_ether_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
            free(arp_entry);
            sr_send_packet(sr, forward_packet, len, outgoing_iface->name);
            free(forward_packet);
          }else{
            struct sr_arpreq *new_req = sr_arpcache_queuereq(&(sr->cache),(matching_entry->gw).s_addr,forward_packet,len,outgoing_iface->name);
            free(forward_packet);
            handle_arpreq(sr,new_req);
          }
        }
      }else{  /* no route found */
        if(ttl_exceed){ /* still sent time exceed if so */
          sr_send_packet(sr, ttl_exceed, sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t), interface);
          free(ttl_exceed);
        }
        uint8_t *net_unreachable = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        sr_ethernet_hdr_t *net_ether_hdr = (sr_ethernet_hdr_t *)net_unreachable;
        sr_ip_hdr_t *net_ip_hdr = (sr_ip_hdr_t *)(net_unreachable + sizeof(sr_ethernet_hdr_t));
        sr_icmp_t3_hdr_t *net_icmp_hdr = (sr_icmp_t3_hdr_t *)(net_unreachable + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        
        /* set header(icmp,ip,ether) */
        net_icmp_hdr->icmp_type = 3; 
        net_icmp_hdr->icmp_code = 0;
        net_icmp_hdr->icmp_sum = 0;
        net_icmp_hdr->unused = 0;
        net_icmp_hdr->next_mtu = 0;
        memcpy(net_icmp_hdr->data, packet+sizeof(sr_ethernet_hdr_t), min(ICMP_DATA_SIZE, len-sizeof(sr_ethernet_hdr_t))); /* in case ip_packet size of original packet is smaller than ICMP_DATA_SIZE */
        net_icmp_hdr->icmp_sum = cksum(net_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

        net_ip_hdr->ip_v = 4;
        net_ip_hdr->ip_hl = 5;
        net_ip_hdr->ip_tos = 0;
        net_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        net_ip_hdr->ip_id = 0; 
        net_ip_hdr->ip_off = 0;
        net_ip_hdr->ip_ttl = 64;
        net_ip_hdr->ip_p = ip_protocol_icmp;
        net_ip_hdr->ip_src = receiving_iface->ip;
        net_ip_hdr->ip_dst = ip_hdr->ip_src;
        net_ip_hdr->ip_sum = 0;
        net_ip_hdr->ip_sum = cksum(net_ip_hdr, sizeof(sr_ip_hdr_t));

        net_ether_hdr->ether_type = htons(ethertype_ip);
        memcpy(net_ether_hdr->ether_shost, receiving_iface->addr, ETHER_ADDR_LEN);
        memcpy(net_ether_hdr->ether_dhost, ether_hdr->ether_shost, ETHER_ADDR_LEN);

        /* send net unreachable */
        sr_send_packet(sr, net_unreachable, sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t), interface);
        free(net_unreachable);
      }
    }
  }else{
    printf("*** -> Can't recognize the type of Received packet: %d \n", ether_hdr->ether_type);
  }

}/* end sr_ForwardPacket */

struct sr_rt* longest_prefix_match(struct sr_instance* sr, uint32_t ip) {
  struct sr_rt* cur_entry = sr->routing_table;
  struct sr_rt* best_match = NULL;
  uint32_t longest_mask = 0;
  while (cur_entry != NULL) {
    /* Check if the destination IP ANDed with the mask is equal to the entry's dest ANDed with the mask */
    if ((ip & (cur_entry->mask).s_addr) == ((cur_entry->dest).s_addr & (cur_entry->mask).s_addr)) {
      if (best_match == NULL || (cur_entry->mask).s_addr > longest_mask) {
        longest_mask = (cur_entry->mask).s_addr;
        best_match = cur_entry;
      }
    }
    cur_entry = cur_entry->next;
  }
  return best_match;
}