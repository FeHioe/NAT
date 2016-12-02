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

#include "sr_nat.h"
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
 
void process_arp(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface_name);
void process_ip(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
void process_ip_nat(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
struct sr_if* sr_interface_contains_ip(struct sr_instance* sr, sr_ip_hdr_t* ip_header);
void send_icmp_messages(struct sr_instance* sr, uint8_t* packet, int type, int code);
void sr_ForwardPacket(struct sr_instance* sr, uint8_t* packet, unsigned int len, sr_ip_hdr_t* ip_header,char* interface);
void handle_arpreq(struct sr_arpreq *sr_req, struct sr_instance *sr);
void create_send_ICMP_packet(struct sr_packet *packet, struct sr_instance *sr, int type, int code);

void sendIPPacket(struct sr_instance* sr,
               uint8_t* packet, 
               unsigned int len, 
               struct sr_rt* rt){
    struct sr_if* iface = sr_get_interface(sr, rt->interface);
    struct sr_arpentry* entry;
    pthread_mutex_lock(&(sr->cache.lock));
    entry = sr_arpcache_lookup(&sr->cache, (uint32_t)(rt->gw.s_addr));
    sr_ethernet_hdr_t* eth_header = (sr_ethernet_hdr_t*) packet;
    sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*) (packet+SIZE_ETH);
    
    if (entry) {
        fprintf(stderr,"Found cache hit\n");
        iface = sr_get_interface(sr, rt->interface);
        memcpy(eth_header->ether_dhost,entry->mac,6);
        memcpy(eth_header->ether_shost,iface->addr,6);
        ip_header->ip_ttl = ip_header->ip_ttl - 1;
        ip_header->ip_sum = 0;
        ip_header->ip_sum = cksum((uint8_t *)ip_header,SIZE_IP);
        sr_send_packet(sr,packet,len,rt->interface);
        free(entry);
    } else {
        fprintf(stderr,"Adding ARP Request\n");
        memcpy(eth_header->ether_shost,iface->addr,6);
        struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), 
                                                     (uint32_t)(rt->gw.s_addr), 
                                                     packet, 
                                                     len, 
                                                     rt->interface);
        handle_arpreq(req, sr);
    }
    pthread_mutex_unlock(&(sr->cache.lock));
} /*end sendIPPacket */

void sr_send_icmp(struct sr_instance* sr,
        uint8_t *buf,
        unsigned int len, 
        uint8_t type, 
        uint8_t code,
        uint32_t ip_src){
  fprintf(stderr,"Send ICMP type %d code %d to\n",type, code);

    uint8_t* packet = malloc(len+SIZE_ICMP);
    memset(packet,0,len+SIZE_ICMP);
    memcpy(packet,buf,len);
    sr_ethernet_hdr_t* eth_header = (sr_ethernet_hdr_t*) packet;
    sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(packet+SIZE_ETH);
    sr_icmp_t3_hdr_t* icmp_header = (sr_icmp_t3_hdr_t*)(packet+SIZE_ETH+SIZE_IP);
    struct sr_rt* rt = sr_find_routing_entry_int(sr, ip_header->ip_src);
    
    if(rt){
        fprintf(stderr,"Found route %s\n",rt->interface);
        struct sr_if* iface = sr_get_interface(sr, rt->interface);

        if(type !=0 || code != 0){
            int data_size;
            if (len < SIZE_ETH+ICMP_DATA_SIZE){
                data_size = len-SIZE_ETH;
            } else {
                data_size = ICMP_DATA_SIZE;
            }
            fprintf(stderr,"ICMP data size = %d", data_size);
            memcpy(icmp_header->data,buf+SIZE_ETH,data_size);
            icmp_header->unused = 0;
            icmp_header->next_mtu = 0;
            len = SIZE_ETH+SIZE_IP+SIZE_ICMP;
        }
        icmp_header->icmp_type = type;
        icmp_header->icmp_code = code;
        icmp_header->icmp_sum = 0;
        icmp_header->icmp_sum = cksum((uint8_t*)icmp_header,len-SIZE_ETH-SIZE_IP);
        memcpy(eth_header->ether_shost,iface->addr,6);
        eth_header->ether_type = htons(0x0800);
        if (ip_src == 0){
            ip_src = iface->ip;
        }
        ip_header->ip_hl = 5;
        ip_header->ip_v = 4;
        ip_header->ip_tos = 0;
        ip_header->ip_len = htons(len-SIZE_ETH);
        ip_header->ip_off = htons(IP_DF);
        ip_header->ip_ttl = INIT_TTL;
        ip_header->ip_p = 1;
        ip_header->ip_sum = 0;
        ip_header->ip_dst = ip_header->ip_src;
        ip_header->ip_src = ip_src;
        ip_header->ip_sum = cksum((uint8_t*)(ip_header),SIZE_IP);
      
        struct sr_arpentry* entry;
        pthread_mutex_lock(&(sr->cache.lock));
        entry = sr_arpcache_lookup(&sr->cache, (uint32_t)(rt->gw.s_addr));
        sr_ethernet_hdr_t* eth_header = (sr_ethernet_hdr_t*) packet;
        sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*) (packet+SIZE_ETH);
        
        if (entry) {
            fprintf(stderr,"Found cache hit\n");
            iface = sr_get_interface(sr, rt->interface);
            memcpy(eth_header->ether_dhost,entry->mac,6);
            memcpy(eth_header->ether_shost,iface->addr,6);
            ip_header->ip_ttl = ip_header->ip_ttl - 1;
            ip_header->ip_sum = 0;
            ip_header->ip_sum = cksum((uint8_t *)ip_header,SIZE_IP);
            sr_send_packet(sr,packet,len,rt->interface);
            free(entry);
        } else {
            fprintf(stderr,"Adding ARP Request\n");
            memcpy(eth_header->ether_shost,iface->addr,6);
            struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), 
                                                         (uint32_t)(rt->gw.s_addr), 
                                                         packet, 
                                                         len, 
                                                         rt->interface);
            handle_arpreq(req, sr);
        }
        pthread_mutex_unlock(&(sr->cache.lock));
    }
}/* end sr_send_icmp */

void natHandleIPPacket(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface){
    /*Initialize headers*/
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

    struct sr_if *tgt_iface = sr_get_interface_from_ip(sr,ip_header->ip_dst);
    struct sr_rt * rt = NULL;
    struct sr_nat_mapping *map = NULL;
    struct sr_nat_connection *con = NULL;
    /*struct sr_if *int_if = sr_get_interface(sr,"eth1");*/
    struct sr_if *ext_if = sr_get_interface(sr,"eth2");

    /*Checksum check*/
    uint16_t checksum = ip_header->ip_sum;
    ip_header->ip_sum = 0;
    uint16_t expected_cksum = cksum(ip_header, ip_header->ip_hl * 4);
    ip_header->ip_sum = checksum;
    if (checksum != expected_cksum){
        fprintf(stderr, "IP header checksum fail.");
        return;
    }
    
     if (strcmp(interface, "eth1") == 0){ /*INTERNAL*/
        rt = (struct sr_rt*)sr_find_routing_entry_int(sr, ip_header->ip_dst);
        if (tgt_iface != NULL || rt == NULL){
            sr_send_icmp(sr, packet, len, 3, 3, 0);
        } else if (ip_header->ip_ttl <= 1){
            fprintf(stderr,"Packet died\n");
            sr_send_icmp(sr, packet, len, 11, 0,0);
        } else if(ip_header->ip_p==6) { /*TCP*/
            fprintf(stderr,"FWD TCP from int\n");
            sr_tcp_hdr_t *tcp_header = (sr_tcp_hdr_t*)(packet+SIZE_ETH+SIZE_IP);
            calc_cksum = sr_tcp_cksum(packet+SIZE_ETH, len-SIZE_ETH);
            if (calc_cksum != tcp_header->tcp_sum){
                fprintf(stderr,"\t TCP bad checksum %u\n", htons(calc_cksum));
            } else {
                fprintf(stderr,"\t fwding\n");
                map = sr_nat_insert_mapping(&(sr->nat),
                                        ip_header->ip_src,
                                        tcp_header->tcp_src,
                                        nat_mapping_tcp);
                con = sr_nat_update_connection(&(sr->nat), packet+SIZE_ETH, 1);
                ip_header->ip_src = ext_if->ip;
                ip_header->ip_sum = 0;
                ip_header->ip_sum = cksum((uint8_t*)ip_header,SIZE_IP);
                
                tcp_header->tcp_src = htons(map->aux_ext);
                tcp_header->tcp_sum = sr_tcp_cksum(packet+SIZE_ETH, len-SIZE_ETH);
                mfree(map);
                sendIPPacket(sr, packet, len, rt);
            }
            
        } else if(ip_header->ip_p==1 ) { /*ICMP*/
            fprintf(stderr,"FWD ICMP from int\n");
            sr_icmp_t8_hdr_t * icmp_header = (sr_icmp_t8_hdr_t*)(packet+SIZE_ETH+SIZE_IP);
            incm_cksum = icmp_header->icmp_sum;
            icmp_header->icmp_sum = 0;
            calc_cksum = cksum((uint8_t*)icmp_header,len-SIZE_ETH-SIZE_IP);
            icmp_header->icmp_sum = incm_cksum;
            if (incm_cksum != calc_cksum){
                fprintf(stderr,"Bad cksum %d != %d\n", incm_cksum, calc_cksum);
            }
            else if (icmp_header->icmp_type == 8 && icmp_header->icmp_code == 0){
                fprintf(stderr,"\t intfwd icmp id %d\n", icmp_header->icmp_id);
                map = sr_nat_insert_mapping(&(sr->nat),
                                        ip_header->ip_src,
                                        icmp_header->icmp_id,
                                        nat_mapping_icmp);
                /*map->ip_ext = ip_header->ip_dst;*/
                fprintf(stderr,"\t intfwd icmp ext id %d\n", map->aux_ext);
                icmp_header->icmp_id = map->aux_ext;
                icmp_header->icmp_sum = 0;
                icmp_header->icmp_sum = cksum((uint8_t*)icmp_header,len-SIZE_ETH-SIZE_IP);
                
                ip_header->ip_src = ext_if->ip;
                ip_header->ip_sum = 0;
                ip_header->ip_sum = cksum((uint8_t*)ip_header,SIZE_IP);
                mfree(map);
                sendIPPacket(sr, packet, len, rt);
            }
        }
    } else if (strcmp(interface, "eth2") == 0){ /*EXTERNAL*/
        if (ip_header->ip_ttl <= 1){
            fprintf(stderr,"Packet died\n");
            sr_send_icmp(sr, packet, len, 11, 0,0);
        } else if (tgt_iface == NULL) {
            fprintf(stderr,"NAT Not for us\n");
        } else if(ip_header->ip_p==6) { /*TCP*/
            fprintf(stderr,"FWD TCP from ext\n");
            sr_tcp_hdr_t *tcp_header = (sr_tcp_hdr_t*)(packet+SIZE_ETH+SIZE_IP);
            calc_cksum = sr_tcp_cksum(packet+SIZE_ETH, len-SIZE_ETH);
            if (calc_cksum != tcp_header->tcp_sum){
                fprintf(stderr,"\t TCP bad checksum %u\n", htons(calc_cksum));
            } if (ntohs(tcp_header->tcp_dst) < 1024){
                fprintf(stderr,"\t INVALID PORT TCP\n");
                sr_send_icmp(sr, packet, len, 3, 3, 0);
            } else {
                map = sr_nat_lookup_external(&(sr->nat),
                                        ntohs(tcp_header->tcp_dst),
                                        nat_mapping_tcp);
                con = sr_nat_update_connection(&(sr->nat), packet+SIZE_ETH, 0);
                if (map != NULL){/*} && con != NULL){*/
                    fprintf(stderr,"\t got copy\n");
                    ip_header->ip_dst = map->ip_int;
                    ip_header->ip_sum = 0;
                    ip_header->ip_sum = cksum((uint8_t*)ip_header,SIZE_IP);
                    
                    tcp_header->tcp_dst = map->aux_int;
                    tcp_header->tcp_sum = sr_tcp_cksum(packet+SIZE_ETH, len-SIZE_ETH);
                    mfree(map);
                    rt = (struct sr_rt*)sr_find_routing_entry_int(sr, ip_header->ip_dst);
                    if (rt != NULL){
                        sendIPPacket(sr, packet, len, rt);
                    }
                } else if (tcp_header->syn) {
                    rt = (struct sr_rt*)sr_find_routing_entry_int(sr, ip_header->ip_dst);
                    if (rt != NULL){
                        map = sr_nat_waiting_mapping(&(sr->nat),
                                                     ip_header->ip_src,
                                                     ntohs(tcp_header->tcp_dst),
                                                     nat_mapping_waiting,
                                                     packet);
                    }
                } /*else {
                    sr_send_icmp(sr, packet, len, 3, 3, 0);
                }*/
            }
        } else if(ip_header->ip_p==1 ) { /*ICMP*/
            fprintf(stderr,"FWD ICMP from ext\n");
            sr_icmp_t8_hdr_t * icmp_header = (sr_icmp_t8_hdr_t*)(packet+SIZE_ETH+SIZE_IP);
            incm_cksum = icmp_header->icmp_sum;
            icmp_header->icmp_sum = 0;
            calc_cksum = cksum((uint8_t*)icmp_header,len-SIZE_ETH-SIZE_IP);
            icmp_header->icmp_sum = incm_cksum;
            if (incm_cksum != calc_cksum){
                fprintf(stderr,"Bad cksum %d != %d\n", incm_cksum, calc_cksum);
            }
            else if (icmp_header->icmp_type == 0 && icmp_header->icmp_code == 0){
                fprintf(stderr,"\t extfwd icmp id %d\n", icmp_header->icmp_id);
                map = sr_nat_lookup_external(&(sr->nat),
                                             icmp_header->icmp_id,
                                             nat_mapping_icmp);
                if (map != NULL){
                    fprintf(stderr,"\t extfwd found mapping\n");
                    rt = (struct sr_rt*)sr_find_routing_entry_int(sr, map->ip_int);
                    if (rt != NULL){
                        fprintf(stderr,"\t extfwd found route\n");
                        icmp_header->icmp_id = map->aux_int;
                        icmp_header->icmp_sum = 0;
                        icmp_header->icmp_sum = cksum((uint8_t*)icmp_header,len-SIZE_ETH-SIZE_IP);
                        
                        ip_header->ip_dst = map->ip_int;
                        ip_header->ip_sum = 0;
                        ip_header->ip_sum = cksum((uint8_t*)ip_header,SIZE_IP);
                        sendIPPacket(sr, packet, len, rt);
                    }
                    mfree(map);
                }
            }
        } 
    }
}/* end natHandleIPPacket */

void sr_init(struct sr_instance* sr, unsigned short nat_check, unsigned int icmp_query_timeout, unsigned int tcp_established_timeout, unsigned int tcp_transitory_timeout){
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

    /* Add initialization code here! */
    sr->is_nat = nat_check;
    if (nat_check == 1){
        sr_nat_init(sr, &(sr->nat), icmp_query_timeout, tcp_established_timeout, tcp_transitory_timeout);
    }

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

  /* fill in code here */

  /* Recieves a raw ethernet frame */
  sr_ethernet_hdr_t *e_header = (sr_ethernet_hdr_t *) packet;
  
  
  /* Check ethernet frame type - Ether ARP or IP */
  uint16_t ethernet_type = ethertype((uint8_t *) e_header);

  if (ethernet_type == ethertype_arp) {
    printf("Ethernet Type: ARP\n");
    process_arp(sr, packet, len, interface);
  } else if (ethernet_type == ethertype_ip) {
    if (sr->is_nat == 1) {
        printf("Ethernet Type: IP - NAT\n");
        natHandleIPPacket(sr, packet, len, interface);
    } else {
        printf("Ethernet Type: IP\n");
        process_ip(sr, packet, len, interface);
    }
  }

}

void process_ip_nat(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){  
    sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    struct sr_if* ip_destined = sr_interface_contains_ip(sr, ip_header);

    /*Checksum check*/
    uint16_t checksum = ip_header->ip_sum;
    ip_header->ip_sum = 0;
    uint16_t expected_cksum = cksum(ip_header, ip_header->ip_hl * 4);
    ip_header->ip_sum = checksum;
    if (checksum != expected_cksum){
        fprintf(stderr, "IP header checksum fail.");
        return;
    }
    
    if (strcmp(interface, "eth1") == 0){ /* internal */
        if (ip_destined){

          /* Make packet */
          uint8_t* reply_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
          memset(reply_packet, 0 , sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
          memcpy(reply_packet, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t));

          /*Create ICMP type 3 header - Port unreachable*/
          sr_icmp_t3_hdr_t* reply_ICMPheader = (sr_icmp_t3_hdr_t*)(reply_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
          reply_ICMPheader->icmp_type = 3; 
          reply_ICMPheader->icmp_code = 3; 
          reply_ICMPheader->icmp_sum = 0; 
          reply_ICMPheader->unused = 0; 
          reply_ICMPheader->next_mtu = 0;

          int icmp_data_size;
          if (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t) < sizeof(sr_ethernet_hdr_t) + ICMP_DATA_SIZE){
            icmp_data_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t) - sizeof(sr_ethernet_hdr_t);
          } else {
            icmp_data_size = ICMP_DATA_SIZE;
          }

          memcpy(reply_ICMPheader->data, packet + sizeof(sr_ethernet_hdr_t), icmp_data_size); 
          reply_ICMPheader->icmp_sum = cksum(reply_ICMPheader, sizeof(sr_icmp_t3_hdr_t));
          
          /*Create IP header*/
          sr_ip_hdr_t *reply_IPheader = (sr_ip_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t));
          reply_IPheader->ip_v = 4;
          reply_IPheader->ip_hl = sizeof(sr_ip_hdr_t)/4; 
          reply_IPheader->ip_tos = 0; 
          reply_IPheader->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t)); 
          reply_IPheader->ip_id = htons(0); 
          reply_IPheader->ip_off = htons(IP_DF); 
          reply_IPheader->ip_ttl = 64; 
          reply_IPheader->ip_p = ip_protocol_icmp; 
          reply_IPheader->ip_sum = 0; /*Clear to 0*/

          /*Create Ethernet header*/
          sr_ethernet_hdr_t *reply_Eheader = (sr_ethernet_hdr_t *)reply_packet;
          reply_Eheader->ether_type = htons(ethertype_ip); 

          /*send packet*/
          struct sr_rt* lpm = check_routing_table(sr, reply_IPheader);
          if(lpm){
              struct sr_if* outgoing_interface = sr_get_interface(sr, lpm->interface);

              /* NAT translation */
              memcpy(reply_Eheader->ether_shost, outgoing_interface->addr, 6);

              uint32_t source = outgoing_interface->ip;
              reply_IPheader->ip_dst = reply_IPheader->ip_src;
              reply_IPheader->ip_src = source;
              reply_IPheader->ip_sum = cksum(reply_IPheader, sizeof(sr_ip_hdr_t));

              pthread_mutex_lock(&(sr->cache.lock));

              struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, lpm->gw.s_addr);

              if (entry) {
                  memcpy(reply_Eheader->ether_dhost, entry->mac, ETHER_ADDR_LEN);
                  memcpy(reply_Eheader->ether_shost, outgoing_interface->addr, ETHER_ADDR_LEN);
                     
                  sr_send_packet(sr, reply_packet, len, outgoing_interface->name);
                  free(entry);
              } else {
                  memcpy(reply_Eheader->ether_shost, outgoing_interface->addr, 6);
                  struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), lpm->gw.s_addr, reply_packet, len, lpm->interface);
                  handle_arpreq(req, sr);
              }
              pthread_mutex_unlock(&(sr->cache.lock));

          }

        } else if (ip_header->ip_ttl <= 1){

          /* Make packet */
          uint8_t* reply_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
          memset(reply_packet, 0 , sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
          memcpy(reply_packet, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t));

          /*Create ICMP type 3 header - Port unreachable*/
          sr_icmp_t3_hdr_t* reply_ICMPheader = (sr_icmp_t3_hdr_t*)(reply_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
          reply_ICMPheader->icmp_type = 11; 
          reply_ICMPheader->icmp_code = 0; 
          reply_ICMPheader->icmp_sum = 0; 
          reply_ICMPheader->unused = 0; 
          reply_ICMPheader->next_mtu = 0;

          int icmp_data_size;
          if (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t) < sizeof(sr_ethernet_hdr_t) + ICMP_DATA_SIZE){
            icmp_data_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t) - sizeof(sr_ethernet_hdr_t);
          } else {
            icmp_data_size = ICMP_DATA_SIZE;
          }

          memcpy(reply_ICMPheader->data, packet + sizeof(sr_ethernet_hdr_t), icmp_data_size); 
          reply_ICMPheader->icmp_sum = cksum(reply_ICMPheader, sizeof(sr_icmp_t3_hdr_t));
          
          /*Create IP header*/
          sr_ip_hdr_t *reply_IPheader = (sr_ip_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t));
          reply_IPheader->ip_v = 4;
          reply_IPheader->ip_hl = sizeof(sr_ip_hdr_t)/4; 
          reply_IPheader->ip_tos = 0; 
          reply_IPheader->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t)); 
          reply_IPheader->ip_id = htons(0); 
          reply_IPheader->ip_off = htons(IP_DF); 
          reply_IPheader->ip_ttl = 64; 
          reply_IPheader->ip_p = ip_protocol_icmp; 
          reply_IPheader->ip_sum = 0; /*Clear to 0*/

          /*Create Ethernet header*/
          sr_ethernet_hdr_t *reply_Eheader = (sr_ethernet_hdr_t *)reply_packet;
          reply_Eheader->ether_type = htons(ethertype_ip); 

          /*send packet*/
          struct sr_rt* lpm = check_routing_table(sr, reply_IPheader);
          if(lpm){
              struct sr_if* outgoing_interface = sr_get_interface(sr, lpm->interface);

              /* NAT translation */
              memcpy(reply_Eheader->ether_shost, outgoing_interface->addr, 6);

              uint32_t source = outgoing_interface->ip;
              reply_IPheader->ip_dst = reply_IPheader->ip_src;
              reply_IPheader->ip_src = source;
              reply_IPheader->ip_sum = cksum(reply_IPheader, sizeof(sr_ip_hdr_t));

              pthread_mutex_lock(&(sr->cache.lock));

              struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, lpm->gw.s_addr);

              if (entry) {
                  memcpy(reply_Eheader->ether_dhost, entry->mac, ETHER_ADDR_LEN);
                  memcpy(reply_Eheader->ether_shost, outgoing_interface->addr, ETHER_ADDR_LEN);
                     
                  sr_send_packet(sr, reply_packet, len, outgoing_interface->name);
                  free(entry);
              } else {
                  memcpy(reply_Eheader->ether_shost, outgoing_interface->addr, 6);
                  struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), lpm->gw.s_addr, reply_packet, len, lpm->interface);
                  handle_arpreq(req, sr);
              }
              pthread_mutex_unlock(&(sr->cache.lock));

          }

        } else if(ip_header->ip_p == 1) { /* ICMP */

            sr_icmp_t8_hdr_t * icmp_header = (sr_icmp_t8_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

            if (icmp_header->icmp_code == 0 && icmp_header->icmp_type == 8){
                struct sr_nat_mapping *map = sr_nat_insert_mapping(&(sr->nat), ip_header->ip_src, icmp_header->icmp_id, nat_mapping_icmp);

                icmp_header->icmp_id = map->aux_ext;
                icmp_header->icmp_sum = 0;
                icmp_header->icmp_sum = cksum(icmp_header, sizeof(sr_icmp_t3_hdr_t));

                struct sr_if *external_interface = sr_get_interface(sr, "eth2");
                ip_header->ip_src = external_interface->ip;
                ip_header->ip_sum = 0;
                ip_header->ip_sum = cksum((uint8_t*)ip_header, sizeof(sr_ip_hdr_t));

                /* free mappings */
                if (map->conns) {
                  struct sr_nat_connection *connection = map->conns;
                  while (connection){
                    struct sr_nat_connection *free_con = connection;
                    connection = connection->next;

                    free(free_con);
                  }
                }

                /* free packet */
                if (map->packet){
                  free(map->packet);
                }

                free(map);

              /*send packet*/
              struct sr_rt* lpm = check_routing_table(sr, ip_header);
              if(lpm){
                  struct sr_if* outgoing_interface = sr_get_interface(sr, lpm->interface);

                  /* NAT translation */
                  sr_ethernet_hdr_t* reply_Eheader = (sr_ethernet_hdr_t*) packet;

                  memcpy(reply_Eheader->ether_shost, outgoing_interface->addr, 6);

                  uint32_t source = outgoing_interface->ip;
                  ip_header->ip_dst = ip_header->ip_src;
                  ip_header->ip_src = source;
                  ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));

                  pthread_mutex_lock(&(sr->cache.lock));

                  struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, lpm->gw.s_addr);

                  if (entry) {
                      memcpy(reply_Eheader->ether_dhost, entry->mac, ETHER_ADDR_LEN);
                      memcpy(reply_Eheader->ether_shost, outgoing_interface->addr, ETHER_ADDR_LEN);
                         
                      sr_send_packet(sr, packet, len, outgoing_interface->name);
                      free(entry);
                  } else {
                      memcpy(reply_Eheader->ether_shost, outgoing_interface->addr, 6);
                      struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), lpm->gw.s_addr, packet, len, lpm->interface);
                      handle_arpreq(req, sr);
                  }
                  pthread_mutex_unlock(&(sr->cache.lock));

              }

        } else if(ip_header->ip_p == 6) { /* TCP */

            sr_tcp_hdr_t *tcp_header = (sr_tcp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

            struct sr_nat_mapping *map = sr_nat_insert_mapping(&(sr->nat), ip_header->ip_src, tcp_header->tcp_src, nat_mapping_tcp);
            /* struct sr_nat_connection *connection = need to update? */
            
            struct sr_if *external_interface = sr_get_interface(sr, "eth2");
            ip_header->ip_src = external_interface->ip;
            ip_header->ip_sum = 0;
            ip_header->ip_sum = cksum((uint8_t*)ip_header, sizeof(sr_ip_hdr_t));
            
            tcp_header->tcp_src = htons(map->aux_ext);

            /* free mappings */
            if (map->conns) {
              struct sr_nat_connection *connection = map->conns;
              while (connection){
                struct sr_nat_connection *free_con = connection;
                connection = connection->next;

                free(free_con);
              }
            }

            /* free packet */
            if (map->packet){
              free(map->packet);
            }

            free(map);

          /*send packet*/
          struct sr_rt* lpm = check_routing_table(sr, ip_header);
          if(lpm){
              struct sr_if* outgoing_interface = sr_get_interface(sr, lpm->interface);

              /* NAT translation */
              sr_ethernet_hdr_t* reply_Eheader = (sr_ethernet_hdr_t*) packet;

              memcpy(reply_Eheader->ether_shost, outgoing_interface->addr, 6);

              uint32_t source = outgoing_interface->ip;
              ip_header->ip_dst = ip_header->ip_src;
              ip_header->ip_src = source;
              ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));

              pthread_mutex_lock(&(sr->cache.lock));

              struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, lpm->gw.s_addr);

              if (entry) {
                  memcpy(reply_Eheader->ether_dhost, entry->mac, ETHER_ADDR_LEN);
                  memcpy(reply_Eheader->ether_shost, outgoing_interface->addr, ETHER_ADDR_LEN);
                     
                  sr_send_packet(sr, packet, len, outgoing_interface->name);
                  free(entry);
              } else {
                  memcpy(reply_Eheader->ether_shost, outgoing_interface->addr, 6);
                  struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), lpm->gw.s_addr, packet, len, lpm->interface);
                  handle_arpreq(req, sr);
              }
              pthread_mutex_unlock(&(sr->cache.lock));

          }
            
        }
    } else if (strcmp(interface, "eth2") == 0){ /* external */
        if (ip_header->ip_ttl <= 1){

          /* Make packet */
          uint8_t* reply_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
          memset(reply_packet, 0 , sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
          memcpy(reply_packet, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t));

          /*Create ICMP type 3 header - Port unreachable*/
          sr_icmp_t3_hdr_t* reply_ICMPheader = (sr_icmp_t3_hdr_t*)(reply_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
          reply_ICMPheader->icmp_type = 11; 
          reply_ICMPheader->icmp_code = 0; 
          reply_ICMPheader->icmp_sum = 0; 
          reply_ICMPheader->unused = 0; 
          reply_ICMPheader->next_mtu = 0;

          int icmp_data_size;
          if (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t) < sizeof(sr_ethernet_hdr_t) + ICMP_DATA_SIZE){
            icmp_data_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t) - sizeof(sr_ethernet_hdr_t);
          } else {
            icmp_data_size = ICMP_DATA_SIZE;
          }

          memcpy(reply_ICMPheader->data, packet + sizeof(sr_ethernet_hdr_t), icmp_data_size); 
          reply_ICMPheader->icmp_sum = cksum(reply_ICMPheader, sizeof(sr_icmp_t3_hdr_t));
          
          /*Create IP header*/
          sr_ip_hdr_t *reply_IPheader = (sr_ip_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t));
          reply_IPheader->ip_v = 4;
          reply_IPheader->ip_hl = sizeof(sr_ip_hdr_t)/4; 
          reply_IPheader->ip_tos = 0; 
          reply_IPheader->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t)); 
          reply_IPheader->ip_id = htons(0); 
          reply_IPheader->ip_off = htons(IP_DF); 
          reply_IPheader->ip_ttl = 64; 
          reply_IPheader->ip_p = ip_protocol_icmp; 
          reply_IPheader->ip_sum = 0; /*Clear to 0*/

          /*Create Ethernet header*/
          sr_ethernet_hdr_t *reply_Eheader = (sr_ethernet_hdr_t *)reply_packet;
          reply_Eheader->ether_type = htons(ethertype_ip); 

          /*send packet*/
          struct sr_rt* lpm = check_routing_table(sr, reply_IPheader);
          if(lpm){
              struct sr_if* outgoing_interface = sr_get_interface(sr, lpm->interface);

              /* NAT translation */
              memcpy(reply_Eheader->ether_shost, outgoing_interface->addr, 6);

              uint32_t source = outgoing_interface->ip;
              reply_IPheader->ip_dst = reply_IPheader->ip_src;
              reply_IPheader->ip_src = source;
              reply_IPheader->ip_sum = cksum(reply_IPheader, sizeof(sr_ip_hdr_t));

              pthread_mutex_lock(&(sr->cache.lock));

              struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, lpm->gw.s_addr);

              if (entry) {
                  memcpy(reply_Eheader->ether_dhost, entry->mac, ETHER_ADDR_LEN);
                  memcpy(reply_Eheader->ether_shost, outgoing_interface->addr, ETHER_ADDR_LEN);
                     
                  sr_send_packet(sr, reply_packet, len, outgoing_interface->name);
                  free(entry);
              } else {
                  memcpy(reply_Eheader->ether_shost, outgoing_interface->addr, 6);
                  struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), lpm->gw.s_addr, reply_packet, len, lpm->interface);
                  handle_arpreq(req, sr);
              }
              pthread_mutex_unlock(&(sr->cache.lock));

          }
        } else if(ip_header->ip_p == 1) { /* ICMP */

            sr_icmp_t8_hdr_t * icmp_header = (sr_icmp_t8_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

            if (icmp_header->icmp_type == 0 && icmp_header->icmp_code == 0){
                struct sr_nat_mapping *map = sr_nat_lookup_external(&(sr->nat), icmp_header->icmp_id, nat_mapping_icmp);
                
                if (map){
                    struct sr_rt* lpm = check_routing_table(sr, ip_header);
                    if (lpm){
                        icmp_header->icmp_id = map->aux_int;
                        icmp_header->icmp_sum = 0;
                        icmp_header->icmp_sum = cksum(icmp_header, sizeof(sr_icmp_t3_hdr_t));
                        
                        ip_header->ip_dst = map->ip_int;
                        ip_header->ip_sum = 0;
                        ip_header->ip_sum = cksum((uint8_t*)ip_header, sizeof(sr_ip_hdr_t));
                        
                      struct sr_if* outgoing_interface = sr_get_interface(sr, lpm->interface);

                      /* NAT translation */
                      sr_ethernet_hdr_t* reply_Eheader = (sr_ethernet_hdr_t*) packet;

                      memcpy(reply_Eheader->ether_shost, outgoing_interface->addr, 6);

                      uint32_t source = outgoing_interface->ip;
                      ip_header->ip_dst = ip_header->ip_src;
                      ip_header->ip_src = source;
                      ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));

                      pthread_mutex_lock(&(sr->cache.lock));

                      struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, lpm->gw.s_addr);

                      if (entry) {
                          memcpy(reply_Eheader->ether_dhost, entry->mac, ETHER_ADDR_LEN);
                          memcpy(reply_Eheader->ether_shost, outgoing_interface->addr, ETHER_ADDR_LEN);
                             
                          sr_send_packet(sr, packet, len, outgoing_interface->name);
                          free(entry);
                      } else {
                          memcpy(reply_Eheader->ether_shost, outgoing_interface->addr, 6);
                          struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), lpm->gw.s_addr, packet, len, lpm->interface);
                          handle_arpreq(req, sr);
                      }
                      pthread_mutex_unlock(&(sr->cache.lock));
                    }

                    /* free mappings */
                    if (map->conns) {
                      struct sr_nat_connection *connection = map->conns;
                      while (connection){
                        struct sr_nat_connection *free_con = connection;
                        connection = connection->next;

                        free(free_con);
                      }
                    }

                    /* free packet */
                    if (map->packet){
                      free(map->packet);
                    }

                    free(map);
                }
            }
        } else if(ip_header->ip_p == 6) { /* TCP */

            sr_tcp_hdr_t *tcp_header = (sr_tcp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

            if (ntohs(tcp_header->tcp_dst) < 1024){ /* invalid */

              /* Make packet */
              uint8_t* reply_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
              memset(reply_packet, 0 , sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
              memcpy(reply_packet, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t));

              /*Create ICMP type 3 header - Port unreachable*/
              sr_icmp_t3_hdr_t* reply_ICMPheader = (sr_icmp_t3_hdr_t*)(reply_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
              reply_ICMPheader->icmp_type = 3; 
              reply_ICMPheader->icmp_code = 3; 
              reply_ICMPheader->icmp_sum = 0; 
              reply_ICMPheader->unused = 0; 
              reply_ICMPheader->next_mtu = 0;

              int icmp_data_size;
              if (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t) < sizeof(sr_ethernet_hdr_t) + ICMP_DATA_SIZE){
                icmp_data_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t) - sizeof(sr_ethernet_hdr_t);
              } else {
                icmp_data_size = ICMP_DATA_SIZE;
              }

              memcpy(reply_ICMPheader->data, packet + sizeof(sr_ethernet_hdr_t), icmp_data_size); 
              reply_ICMPheader->icmp_sum = cksum(reply_ICMPheader, sizeof(sr_icmp_t3_hdr_t));
              
              /*Create IP header*/
              sr_ip_hdr_t *reply_IPheader = (sr_ip_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t));
              reply_IPheader->ip_v = 4;
              reply_IPheader->ip_hl = sizeof(sr_ip_hdr_t)/4; 
              reply_IPheader->ip_tos = 0; 
              reply_IPheader->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t)); 
              reply_IPheader->ip_id = htons(0); 
              reply_IPheader->ip_off = htons(IP_DF); 
              reply_IPheader->ip_ttl = 64; 
              reply_IPheader->ip_p = ip_protocol_icmp; 
              reply_IPheader->ip_sum = 0; /*Clear to 0*/

              /*Create Ethernet header*/
              sr_ethernet_hdr_t *reply_Eheader = (sr_ethernet_hdr_t *)reply_packet;
              reply_Eheader->ether_type = htons(ethertype_ip); 

              /*send packet*/
              struct sr_rt* lpm = check_routing_table(sr, reply_IPheader);
              if(lpm){
                  struct sr_if* outgoing_interface = sr_get_interface(sr, lpm->interface);

                  /* NAT translation */
                  memcpy(reply_Eheader->ether_shost, outgoing_interface->addr, 6);

                  uint32_t source = outgoing_interface->ip;
                  reply_IPheader->ip_dst = reply_IPheader->ip_src;
                  reply_IPheader->ip_src = source;
                  reply_IPheader->ip_sum = cksum(reply_IPheader, sizeof(sr_ip_hdr_t));

                  pthread_mutex_lock(&(sr->cache.lock));

                  struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, lpm->gw.s_addr);

                  if (entry) {
                      memcpy(reply_Eheader->ether_dhost, entry->mac, ETHER_ADDR_LEN);
                      memcpy(reply_Eheader->ether_shost, outgoing_interface->addr, ETHER_ADDR_LEN);
                         
                      sr_send_packet(sr, reply_packet, len, outgoing_interface->name);
                      free(entry);
                  } else {
                      memcpy(reply_Eheader->ether_shost, outgoing_interface->addr, 6);
                      struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), lpm->gw.s_addr, reply_packet, len, lpm->interface);
                      handle_arpreq(req, sr);
                  }
                  pthread_mutex_unlock(&(sr->cache.lock));

              }

            } else {
                struct sr_nat_mapping *map = sr_nat_lookup_external(&(sr->nat), ntohs(tcp_header->tcp_dst), nat_mapping_tcp);

                if (map){
                    ip_header->ip_dst = map->ip_int;
                    ip_header->ip_sum = 0;
                    ip_header->ip_sum = cksum((uint8_t*)ip_header, sizeof(sr_ip_hdr_t));
                    
                    tcp_header->tcp_dst = map->aux_int;

                    /* free mappings */
                    if (map->conns) {
                      struct sr_nat_connection *connection = map->conns;
                      while (connection){
                        struct sr_nat_connection *free_con = connection;
                        connection = connection->next;

                        free(free_con);
                      }
                    }

                    /* free packet */
                    if (map->packet){
                      free(map->packet);
                    }

                    free(map);

                    struct sr_rt* lpm = check_routing_table(sr, ip_header);
                    if (lpm){
                      struct sr_if* outgoing_interface = sr_get_interface(sr, lpm->interface);

                      /* NAT translation */
                      sr_ethernet_hdr_t* reply_Eheader = (sr_ethernet_hdr_t*) packet;

                      memcpy(reply_Eheader->ether_shost, outgoing_interface->addr, 6);

                      uint32_t source = outgoing_interface->ip;
                      ip_header->ip_dst = ip_header->ip_src;
                      ip_header->ip_src = source;
                      ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));

                      pthread_mutex_lock(&(sr->cache.lock));

                      struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, lpm->gw.s_addr);

                      if (entry) {
                          memcpy(reply_Eheader->ether_dhost, entry->mac, ETHER_ADDR_LEN);
                          memcpy(reply_Eheader->ether_shost, outgoing_interface->addr, ETHER_ADDR_LEN);
                             
                          sr_send_packet(sr, packet, len, outgoing_interface->name);
                          free(entry);
                      } else {
                          memcpy(reply_Eheader->ether_shost, outgoing_interface->addr, 6);
                          struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), lpm->gw.s_addr, packet, len, lpm->interface);
                          handle_arpreq(req, sr);
                      }
                      pthread_mutex_unlock(&(sr->cache.lock));
                    }
                } 
            }
        }
    }
  }
}

void process_ip(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) {
    /* Recieves a raw ethernet frame */
    sr_ethernet_hdr_t *e_header = (sr_ethernet_hdr_t *) packet;
    
    /*Initialize headers*/
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    
    /*Checksum check*/
    uint16_t checksum = ip_header->ip_sum;
    ip_header->ip_sum = 0;
    uint16_t expected_cksum = cksum(ip_header, ip_header->ip_hl * 4);
    ip_header->ip_sum = checksum;
    if (checksum != expected_cksum){
        fprintf(stderr, "IP header checksum fail.");
        return;
    }

    /* Check if destined for our interface */
    uint8_t ip_proto = ip_protocol(packet + sizeof(sr_ethernet_hdr_t)); 
    struct sr_if* ip_destined = sr_interface_contains_ip(sr, ip_header);
    
    if (ip_destined != NULL) {
        printf("This packet is destined for our interface.\n");
        
        /* Check IP protocol type. */
        if (ip_proto == ip_protocol_icmp) {
            /* ICMP */
            /*send_icmp_messages(0, -1); */
            sr_icmp_hdr_t *reply_ICMPheader = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

            /*Receive ECHO req*/
            if (reply_ICMPheader->icmp_type == 8) {
                /*Create Ethernet header*/
                memcpy(e_header->ether_dhost, e_header->ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN);
                memcpy(e_header->ether_shost, sr_get_interface(sr, interface)->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
            
                /*Create IP header*/
                uint32_t source = ip_header->ip_src;
                ip_header->ip_src = ip_header->ip_dst;
                ip_header->ip_dst = source;
                ip_header->ip_sum = 0;
                ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
            
                /*Create ICMP header*/
                reply_ICMPheader->icmp_type = 0;
                reply_ICMPheader->icmp_code = 0;
                reply_ICMPheader->icmp_sum = 0;
                int cksum_size = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
                reply_ICMPheader->icmp_sum = cksum(reply_ICMPheader, cksum_size);
                
				/* Send packet*/
                struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, ip_header->ip_dst);
                if (entry) {
                    sr_send_packet(sr, packet, len, interface);
                } else {
                    struct sr_arpreq* req = sr_arpcache_queuereq(&sr->cache, ip_header->ip_dst, packet, len, interface); 
                    handle_arpreq(req, sr);
                }
            } else {
				/* Packet is not an ECHO req. Drop packet.*/
                return;
            }
        } else if (ip_proto == ip_protocol_udp || ip_proto ==  ip_protocol_tcp){
           /* TCP & UDP */
            /*Initialize packet*/
            int reply_size = sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t);
            uint8_t *reply = malloc(reply_size);
            
            sr_ethernet_hdr_t *e_header = malloc(sizeof(sr_ethernet_hdr_t));
            memcpy(e_header, (sr_ethernet_hdr_t*)packet, sizeof(sr_ethernet_hdr_t));
            
            /*Create ICMP type 3 header - Port unreachable*/
            sr_icmp_t3_hdr_t *reply_ICMPheader = (sr_icmp_t3_hdr_t*)(reply + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            reply_ICMPheader->icmp_type = 3; 
            reply_ICMPheader->icmp_code = 3; 
            reply_ICMPheader->icmp_sum = 0; /*Clear to 0*/
            reply_ICMPheader->unused = 0; 
            reply_ICMPheader->next_mtu = 0; 
            memcpy(reply_ICMPheader->data, ip_header, ICMP_DATA_SIZE); 
            reply_ICMPheader->icmp_sum = cksum(reply_ICMPheader, sizeof(sr_icmp_t3_hdr_t));
            
            /*Create IP header*/
            sr_ip_hdr_t *reply_IPheader = (sr_ip_hdr_t *)(reply + sizeof(sr_ethernet_hdr_t));
            reply_IPheader->ip_v = 4;
            reply_IPheader->ip_hl = sizeof(sr_ip_hdr_t)/4; 
            reply_IPheader->ip_tos = 0; 
            reply_IPheader->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t)); 
            reply_IPheader->ip_id = htons(0); 
            reply_IPheader->ip_off = htons(IP_DF); 
            reply_IPheader->ip_ttl = 64; 
            reply_IPheader->ip_dst = ip_header->ip_src; /*Set destination to source since we're sending back*/
            reply_IPheader->ip_p = ip_protocol_icmp; 
            reply_IPheader->ip_sum = 0; /*Clear to 0*/
            
            /*Create Ethernet header*/
            sr_ethernet_hdr_t *reply_Eheader = (sr_ethernet_hdr_t *)reply;
            reply_Eheader->ether_type = htons(ethertype_ip); 
            
			/*Send packet*/
            struct sr_rt *lpm = check_routing_table(sr, ip_header);
            if (lpm == NULL)
                return;
            
            struct sr_if *outgoing_interface = sr_get_interface(sr, lpm->interface);
            reply_IPheader->ip_src = ip_header->ip_dst;
            reply_IPheader->ip_sum = cksum(reply_IPheader, sizeof(sr_ip_hdr_t));
            struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, lpm->gw.s_addr);
                
            if (entry){
                memcpy(reply_Eheader->ether_dhost, entry->mac, ETHER_ADDR_LEN);
                memcpy(reply_Eheader->ether_shost, outgoing_interface->addr, ETHER_ADDR_LEN);
                    
                sr_send_packet(sr, reply, len, outgoing_interface->name);
                free(entry);
            } else {
                struct sr_arpreq *req= sr_arpcache_queuereq(&sr->cache, lpm->gw.s_addr, reply, len, lpm->interface);
                handle_arpreq(req, sr);
            }
            

            return;
        } else {
           /* Ignore the packet otherwise */
            return;
        }
        
    } else {
        printf("This packet is not destined for our interface.\n");
        /*sizeof(sr_ip_hdr_t)*/
        /*sr_ForwardPacket(sr, packet, sizeof(sr_ip_hdr_t), ip_header, interface);*/

        /* Check for TTL */
        if(ip_header->ip_ttl - 1 < 1){
            /* Send a ttl packet*/
            /*Initialize packet*/
            int reply_size = sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t);
            uint8_t *reply = malloc(reply_size);
            
            sr_ethernet_hdr_t *e_header = malloc(sizeof(sr_ethernet_hdr_t));
            memcpy(e_header, (sr_ethernet_hdr_t*)packet, sizeof(sr_ethernet_hdr_t));
            
            /*Create ICMP type 3 header - Time Exceeded*/
            sr_icmp_t3_hdr_t *reply_ICMPheader = (sr_icmp_t3_hdr_t*)(reply + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            reply_ICMPheader->icmp_type = 11; 
            reply_ICMPheader->icmp_code = 0; 
            reply_ICMPheader->icmp_sum = 0; /*Clear to 0*/
            reply_ICMPheader->unused = 0; 
            reply_ICMPheader->next_mtu = 0; 
            memcpy(reply_ICMPheader->data, ip_header, ICMP_DATA_SIZE); 
            reply_ICMPheader->icmp_sum = cksum(reply_ICMPheader, sizeof(sr_icmp_t3_hdr_t)); 
            
            /*Create IP header*/
            sr_ip_hdr_t *reply_IPheader = (sr_ip_hdr_t *)(reply + sizeof(sr_ethernet_hdr_t));
            reply_IPheader->ip_v = 4; 
            reply_IPheader->ip_hl = sizeof(sr_ip_hdr_t)/4; 
            reply_IPheader->ip_tos = 0; 
            reply_IPheader->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t)); 
            reply_IPheader->ip_id = htons(0); 
            reply_IPheader->ip_off = htons(IP_DF); 
            reply_IPheader->ip_ttl = 64; 
            reply_IPheader->ip_dst = ip_header->ip_src; /*Set destination to source since we're sending back*/
            reply_IPheader->ip_p = ip_protocol_icmp; 
            reply_IPheader->ip_src = sr_get_interface(sr, interface)->ip; /*Get the ip of the packet*/
            reply_IPheader->ip_sum = 0; /*Clear to 0*/
            reply_IPheader->ip_sum = cksum(reply_IPheader, sizeof(sr_ip_hdr_t));
            
            /*Create Ethernet header*/
            sr_ethernet_hdr_t *reply_Eheader = (sr_ethernet_hdr_t *)reply;
            memcpy(reply_Eheader->ether_dhost, e_header->ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN); /*Set destination to source*/
            memcpy(reply_Eheader->ether_shost, e_header->ether_dhost, sizeof(uint8_t)*ETHER_ADDR_LEN); /*Set source to destination*/
            reply_Eheader->ether_type = htons(ethertype_ip); 
            
			/* Find the longest matching prefix*/
            struct sr_rt *lpm = NULL;
            struct sr_rt* routingtable = sr->routing_table;
            while(routingtable != NULL) {
                uint32_t rt_m = routingtable->dest.s_addr & routingtable->mask.s_addr;
                
                /*  Want to check if the IP destination address matches the address in the routing table
                 and make sure that it is always lpm */
                if ((rt_m & ip_header->ip_src) == rt_m && (lpm == NULL || lpm->dest.s_addr < rt_m)){
                    lpm = routingtable;
                }
                
                routingtable = routingtable->next;
            }
            
			/* Forward packet*/
            if (lpm){
                struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, lpm->gw.s_addr);
                
                if (entry){
                    struct sr_if *outgoing_interface = sr_get_interface(sr, lpm->interface);
                    
                    reply_IPheader->ip_src = sr_get_interface(sr, interface)->ip;
                    reply_IPheader->ip_sum = 0; /*Clear to 0*/
                    reply_IPheader->ip_sum = cksum(reply_IPheader, sizeof(sr_ip_hdr_t));
                    
                    memcpy(reply_Eheader->ether_dhost, entry->mac, ETHER_ADDR_LEN);
                    memcpy(reply_Eheader->ether_shost, outgoing_interface->addr, ETHER_ADDR_LEN);
                    
                    sr_send_packet(sr, reply, len, outgoing_interface->name);
                    free(entry);
                } else {
                    struct sr_arpreq *req= sr_arpcache_queuereq(&sr->cache, lpm->gw.s_addr, reply, len, lpm->interface);
                    handle_arpreq(req, sr);
                }
            }
            return;
        }
		
		/* Decrement TTL*/
        ip_header->ip_ttl = ip_header->ip_ttl - 1;
        ip_header->ip_sum = 0; /*Clear to 0*/
        ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
        
        /*Find out which entry in the routing table has the longest prefix match with the destination IP address */
        struct sr_rt *lpm = check_routing_table(sr, ip_header);
  
        if (lpm) {
            /* Check the ARP cache for the next-hop MAC address corresponding to the next-hop IP. */
            struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, lpm->gw.s_addr);

            /* If there is already an IP->MAC address mapping, send the packet to the destination MAC address */
            if (entry) {
                /* Get the interface we are sending to */
                struct sr_if *outgoing_interface = sr_get_interface(sr, lpm->interface);
            
                /* Create new Ethernet packet */
                sr_ethernet_hdr_t *ethernet_header =(sr_ethernet_hdr_t *) packet;
                memcpy(ethernet_header->ether_dhost, entry->mac, ETHER_ADDR_LEN);
                memcpy(ethernet_header->ether_shost, outgoing_interface->addr, ETHER_ADDR_LEN);
                ethernet_header->ether_type = e_header->ether_type;

                sr_send_packet(sr, packet, len, outgoing_interface->name);
                free(entry);

                /* Send an ARP for the next-hop IP (if one hasn't been sent within the last second) */
            } else {

                struct sr_arpreq *req= sr_arpcache_queuereq(&sr->cache, ip_header->ip_dst, packet, len, lpm->interface);

                handle_arpreq(req, sr);
            }
        } else {
        /*Not in routing table and send net unreachable */
           /*Initialize packet*/
            int reply_size = sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t);
            uint8_t *reply = malloc(reply_size);
            
            sr_ethernet_hdr_t *e_header = malloc(sizeof(sr_ethernet_hdr_t));
            memcpy(e_header, (sr_ethernet_hdr_t*)packet, sizeof(sr_ethernet_hdr_t));
            
            /*Create ICMP type 3 header - Net Unreachable*/
            sr_icmp_t3_hdr_t *reply_ICMPheader = (sr_icmp_t3_hdr_t*)(reply + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            reply_ICMPheader->icmp_type = 3; 
            reply_ICMPheader->icmp_code = 0; 
            reply_ICMPheader->icmp_sum = 0; 
            reply_ICMPheader->unused = 0; 
            reply_ICMPheader->next_mtu = 0; 
            memcpy(reply_ICMPheader->data, ip_header, ICMP_DATA_SIZE); 
            reply_ICMPheader->icmp_sum = cksum(reply_ICMPheader, sizeof(sr_icmp_t3_hdr_t)); 
            
            /*Create IP header*/
            sr_ip_hdr_t *reply_IPheader = (sr_ip_hdr_t *)(reply + sizeof(sr_ethernet_hdr_t));
            reply_IPheader->ip_v = 4; 
            reply_IPheader->ip_hl = sizeof(sr_ip_hdr_t)/4; 
            reply_IPheader->ip_tos = 0; 
            reply_IPheader->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t)); 
            reply_IPheader->ip_id = htons(0); 
            reply_IPheader->ip_off = htons(IP_DF); 
            reply_IPheader->ip_ttl = 64; 
            reply_IPheader->ip_dst = ip_header->ip_src; /*Set destination to source since we're sending back*/
            reply_IPheader->ip_p = ip_protocol_icmp; 
            reply_IPheader->ip_src = sr_get_interface(sr, interface)->ip; /*Get the ip of the packet*/
            reply_IPheader->ip_sum = 0; /*Clear to 0*/
            reply_IPheader->ip_sum = cksum(reply_IPheader, sizeof(sr_ip_hdr_t));
            
            /*Create Ethernet header*/
            sr_ethernet_hdr_t *reply_Eheader = (sr_ethernet_hdr_t *)reply;
            memcpy(reply_Eheader->ether_dhost, e_header->ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN); /*Set destination to source*/
            memcpy(reply_Eheader->ether_shost, e_header->ether_dhost, sizeof(uint8_t)*ETHER_ADDR_LEN); /*Set source to destination*/
            reply_Eheader->ether_type = htons(ethertype_ip); 
            
			/* Find longest match prefix*/
            struct sr_rt *lpm = NULL;
            struct sr_rt* routingtable = sr->routing_table;
            while(routingtable != NULL) {
                uint32_t rt_m = routingtable->dest.s_addr & routingtable->mask.s_addr;

                /*  Want to check if the IP destination address matches the address in the routing table 
                and make sure that it is always lpm */
                if ((rt_m & ip_header->ip_src) == rt_m && (lpm == NULL || lpm->dest.s_addr < rt_m)){
                    lpm = routingtable;
                }

                routingtable = routingtable->next;
            }
            
			/*Send packet*/
            if (lpm){
                struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, lpm->gw.s_addr);
                
                if (entry){
                    struct sr_if *outgoing_interface = sr_get_interface(sr, lpm->interface);
                    
                    reply_IPheader->ip_src = sr_get_interface(sr, interface)->ip;
                    reply_IPheader->ip_sum = 0; /*Clear to 0*/
                    reply_IPheader->ip_sum = cksum(reply_IPheader, sizeof(sr_ip_hdr_t));
                    
                    memcpy(reply_Eheader->ether_dhost, entry->mac, ETHER_ADDR_LEN);
                    memcpy(reply_Eheader->ether_shost, outgoing_interface->addr, ETHER_ADDR_LEN);
                    
                    sr_send_packet(sr, reply, len, outgoing_interface->name);
                    free(entry);
                } else {
                    struct sr_arpreq *req= sr_arpcache_queuereq(&sr->cache, lpm->gw.s_addr, reply, len, lpm->interface);
                    handle_arpreq(req, sr);
                }
            }
        }
	}
}


struct sr_if* sr_interface_contains_ip(struct sr_instance* sr, sr_ip_hdr_t* ip_header)
{
  assert(sr);
  assert(ip_header);


  /* List of our interface*/ 
  struct sr_if* interface = NULL;
  interface = sr->if_list;

  while (interface) {
       if (interface->ip == ip_header->ip_dst) {
            return interface;
       }
        interface = interface->next;
  }
   return NULL;
}




void process_arp(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface_name) {
  /* Get ARP header*/
  sr_arp_hdr_t *arp_header = malloc(sizeof(sr_arp_hdr_t));
  memcpy(arp_header, (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t)), sizeof(sr_arp_hdr_t));
  
  /* Check type of ARP */
  if (ntohs(arp_header->ar_op) == arp_op_request) {
    /* Recieved an ARP Request. Want to send out an ARP Reply */
    
    /* Check destined ARP */
    int destined_ARP = 0;
    struct sr_if* iterate = sr->if_list;
    
    while (iterate){
        if (iterate->ip == arp_header->ar_tip){
            destined_ARP = 1;
            break;
        }
        iterate = iterate->next;
    }
    
    if (destined_ARP == 1) {
        /* Create ARP reply message packet */
        int reply_size = sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t);
        uint8_t *reply = malloc(reply_size);
    
        sr_ethernet_hdr_t *e_header = malloc(sizeof(sr_ethernet_hdr_t));
        memcpy(e_header, (sr_ethernet_hdr_t*)packet, sizeof(sr_ethernet_hdr_t));
        struct sr_if *source_addr = sr_get_interface(sr, interface_name);
    
        /*Create Etehrnet header*/
        sr_ethernet_hdr_t *reply_Eheader = (sr_ethernet_hdr_t *)reply;
        memcpy(reply_Eheader->ether_dhost, e_header->ether_shost, ETHER_ADDR_LEN); /*Set destination to source*/
        memcpy(reply_Eheader->ether_shost, source_addr->addr, ETHER_ADDR_LEN); /*Set source to destination*/
        reply_Eheader->ether_type = e_header->ether_type; 

        /*Create ARP header*/
        sr_arp_hdr_t *reply_ARPheader = (sr_arp_hdr_t *)(reply + sizeof(sr_ethernet_hdr_t));
        reply_ARPheader->ar_hrd = arp_header->ar_hrd; 
        reply_ARPheader->ar_pro = arp_header->ar_pro; 
        reply_ARPheader->ar_hln = arp_header->ar_hln; 
        reply_ARPheader->ar_pln = arp_header->ar_pln; 
        reply_ARPheader->ar_op = htons(arp_op_reply); 
        memcpy(reply_ARPheader->ar_sha, iterate->addr, ETHER_ADDR_LEN); /*sender MAC addr*/
        reply_ARPheader->ar_sip = iterate->ip; /* sender IP addr */
        memcpy(reply_ARPheader->ar_tha, arp_header->ar_sha, ETHER_ADDR_LEN); /*destination MAC addr */
        reply_ARPheader->ar_tip = arp_header->ar_sip; /* destination IP addr */
    
		/*Send packet*/
        sr_send_packet(sr, reply, reply_size, iterate->name);
        free(reply);
    } else {
		/* Not destined to us - drop packet*/
        return;
    }

  } else if (ntohs(arp_header->ar_op) == arp_op_reply) { 
    /* Recieved an ARP reply */
    
    /* Check destined ARP */
    int destined_ARP = 0;
    struct sr_if* iterate = sr->if_list;
    
    while (iterate){
        if (iterate->ip == arp_header->ar_tip){
            destined_ARP = 1;
            break;
        }
        iterate = iterate->next;
    }
    
    if (destined_ARP == 1){
        /* Update the ARP cache with the given MAC address */
        struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, arp_header->ar_sha, arp_header->ar_sip);
    
        sr_ethernet_hdr_t *e_header = malloc(sizeof(sr_ethernet_hdr_t));
        memcpy(e_header, (sr_ethernet_hdr_t*)packet, sizeof(sr_ethernet_hdr_t));

        /* With the IP->MAC mapping filled in the ARP request, send all remaining packets*/
        if (req != NULL) {
            struct sr_packet *req_packet = req->packets;
            while (req_packet) {
                struct sr_if *interface = sr_get_interface(sr, req_packet->iface);

                /* Send packet back to the sender*/
                sr_ethernet_hdr_t *reply_Eheader = (sr_ethernet_hdr_t *)req_packet->buf;
                memcpy(reply_Eheader->ether_dhost, arp_header->ar_sha, ETHER_ADDR_LEN); 
                memcpy(reply_Eheader->ether_shost, interface->addr, ETHER_ADDR_LEN); 
        
                sr_send_packet(sr, req_packet->buf, req_packet->len, req_packet->iface);
                req_packet = req_packet->next; 
            }
      
            sr_arpreq_destroy(&sr->cache, req);
      
        } 
    } else {
		/* Not destined to us - drop packet*/
        return;
    }
  }
}



