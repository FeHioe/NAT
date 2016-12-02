
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_router.h"
#include "sr_rt.h"

void handle_arpreq(struct sr_arpreq *sr_req, struct sr_instance *sr);

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  /* Initialize any variables here */
  nat->icmp = time(NULL);
  nat->tcp = 1024;

  return success;
}

int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */
  struct sr_nat_mapping *map = nat->mappings;
  while (map) {
    struct sr_nat_mapping *temp = map;
    map = map->next;

    /* freeing NAT */
    if (temp->conns) {
      struct sr_nat_connection *connection = temp->conns;
      while (connection){
        struct sr_nat_connection *free_con = connection;
        connection = connection->next;

        free(free_con);
      }
    }

    free(temp);
  }

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void * nat_ptr) {  /* Periodic Timout handling */
  struct sr_instance *sr = (struct sr_instance *)nat_ptr;
  struct sr_nat *nat = &(sr->nat);
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */
    struct sr_nat_mapping *map = nat->mappings;
    struct sr_nat_mapping *temp = NULL;

    while(map){ 
      double elapsed = difftime(curtime, map->last_updated);
        
      if (map->type == nat_mapping_icmp && nat->icmp_query_timeout < elapsed){

          if(temp){
            temp->next = map->next;
          } else {
            nat->mappings = NULL;
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

      } else if (map->type == nat_mapping_waiting && 6.0 <= elapsed){

          struct sr_nat_mapping *external_map = sr_nat_lookup_external(nat, map->aux_ext, nat_mapping_tcp);
          if(external_map){
            unsigned char exists = 0;
            struct sr_nat_connection *connection = map->conns;

            while (connection) {
              if (connection->ip == map->ip_ext){
                exists = 1;
                break;
              }
              connection = connection->next;
            }

            if (exists == 0){

              /* Make packet */
              uint8_t* packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
              memset(packet, 0 , sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
              memcpy(packet, map->packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t));

              /*Create ICMP type 3 header - Port unreachable*/
              sr_icmp_t3_hdr_t* reply_ICMPheader = (sr_icmp_t3_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
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

              memcpy(reply_ICMPheader->data, map->packet + sizeof(sr_ethernet_hdr_t), icmp_data_size); 
              reply_ICMPheader->icmp_sum = cksum(reply_ICMPheader, sizeof(sr_icmp_t3_hdr_t));
              
              /*Create IP header*/
              sr_ip_hdr_t *reply_IPheader = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
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
              sr_ethernet_hdr_t *reply_Eheader = (sr_ethernet_hdr_t *)packet;
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

                  /* calculate length */
                  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t);

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

          } else {

            /* Make packet */
            uint8_t* packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
            memset(packet, 0 , sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
            memcpy(packet, map->packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t));

            /*Create ICMP type 3 header - Port unreachable*/
            sr_icmp_t3_hdr_t* reply_ICMPheader = (sr_icmp_t3_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
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

            memcpy(reply_ICMPheader->data, map->packet + sizeof(sr_ethernet_hdr_t), icmp_data_size); 
            reply_ICMPheader->icmp_sum = cksum(reply_ICMPheader, sizeof(sr_icmp_t3_hdr_t));
            
            /*Create IP header*/
            sr_ip_hdr_t *reply_IPheader = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
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
            sr_ethernet_hdr_t *reply_Eheader = (sr_ethernet_hdr_t *)packet;
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

                /* calculate length */
                unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t);

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

          if(temp){
            temp->next = map->next;
          } else {
            nat->mappings = NULL;
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

      }else if (map->type == nat_mapping_tcp){
          if (nat->tcp_established_timeout <= elapsed){

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

          } else {
            int delete = 0;
            struct sr_nat_connection *connection = map->conns;
            struct sr_nat_connection *temp = NULL;


            while (connection) {

			        /* check if this actually works */
			        unsigned int timeout;
              if (connection->tcp_timeout == 0) {
                timeout = nat->tcp_established_timeout;
              } else {
                timeout = nat->tcp_transitory_timeout;
              }

              if (timeout <= difftime(curtime, connection->last_updated)){
                temp->next = connection->next;
                free(connection);
                connection = temp;
              } else {
                delete = 1;
              }
            }

            if (delete) {
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
      }
      
      temp = map;
      map = map->next;
    }

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}


/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
  
  struct sr_nat_mapping *map = nat->mappings;
  while (map){
    if (map->aux_ext == aux_ext && map->type == type) {
      memcpy(copy, map, sizeof(struct sr_nat_mapping));
      break;
    }
    map = map->next;
  }

  if (map){
    map->last_updated = time(NULL);
  } else {
    copy = NULL;
  }

  
  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
  
  struct sr_nat_mapping *map = nat->mappings;
  while(map) {
    if (map->ip_int == ip_int && map->aux_int == aux_int && map->type == type){
      memcpy(copy, map, sizeof(struct sr_nat_mapping));
      break;
    }
    map = map->next;
  }

  if (map){
    map->last_updated = time(NULL);
  } else {
    copy = NULL;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = NULL;
  mapping = sr_nat_lookup_internal(nat, ip_int, aux_int, type);
  
  if (mapping != NULL){
    return mapping;
  }
  
  mapping = malloc(sizeof(struct sr_nat_mapping));
  mapping->type = type;
  mapping->ip_int = ip_int;
  mapping->aux_int = aux_int;
  mapping->last_updated = time(NULL);
  mapping->conns = NULL;
  mapping->next = nat->mappings;
  
  if (type == nat_mapping_icmp){

    mapping->aux_ext = nat->icmp;
    nat->icmp += 1;

  } else {

    mapping->aux_ext = nat->tcp;
    nat->tcp += 1;

    if (nat->tcp == 0){
      nat->tcp = 1024;
    }

  }
  
  nat->mappings = mapping;

  struct sr_nat_mapping *copy = malloc(sizeof(struct sr_nat_mapping));
  memcpy(copy, mapping, sizeof(struct sr_nat_mapping));

  if (mapping->conns){
    copy->conns = NULL;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}
