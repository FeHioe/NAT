#include <stdio.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "sr_nat.h"
#include "sr_protocol.h"
#include "sr_router.h"

int sr_nat_init(void *sr, struct sr_nat *nat, unsigned int icmp_query_timeout, unsigned int tcp_established_timeout, unsigned int tcp_transitory_timeout) {

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
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, sr);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  /* Initialize any variables here */
  nat->icmp_query_timeout = icmp_query_timeout;
  nat->tcp_established_timeout = tcp_established_timeout;
  nat->tcp_transitory_timeout = tcp_transitory_timeout;
  
  nat->icmp_id = time(NULL);
  nat->tcp_id = 1024;

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

void *mfree(struct sr_nat_mapping * map){
   if (map->conns != NULL){
      struct sr_nat_connection *con = map->conns;
      for (con = map->conns; con != NULL; con = con->next) {
          free(con);
      }
   }
   if (map->packet != NULL){
     free(map->packet);
   }
   free(map);
   return NULL;
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

        if (temp){
          temp->next = map->next;  
        } else {
          nat->mappings = NULL;
        }

        /* free mappings */
        mfree(map);

      } else if (map->type == nat_mapping_waiting && 6.0 <= elapsed){

        struct sr_nat_mapping *external_map = sr_nat_lookup_external(nat, map->aux_ext, nat_mapping_tcp);
        if (external_map){
          unsigned char exists = 0;
          struct sr_nat_connection *connection = map->conns;

          while (connection) {
            if (connection->conn_ip == map->ip_ext){
              exists = 1;
              break;
            }
            connection = connection->next;
          }

          if (exists == 0){
            sr_send_icmp(sr, map->packet, SIZE_ETH+SIZE_IP+SIZE_TCP, 3, 3, 0);
          }

        } else {
          sr_send_icmp(sr, map->packet, SIZE_ETH+SIZE_IP+SIZE_TCP, 3, 3, 0);
        }

        if (temp){
          temp->next = map->next;  
        } else {
          nat->mappings = NULL;
        }

        /* free mappings */
        mfree(map);

      } else if (map->type == nat_mapping_tcp){
          if (nat->tcp_established_timeout <= elapsed){
              mfree(map);
          } else {
            unsigned char exists = 0;
            struct sr_nat_connection *connection = map->conns;
            struct sr_nat_connection *temp_con = NULL;

            while (connection) {
              unsigned int timeout;
              if (connection->state == ESTAB2){
                timeout = nat->tcp_established_timeout;
              } else {
                timeout = nat->tcp_transitory_timeout;
              }

              if (timeout <= difftime(curtime, connection->last_updated)){
                temp_con->next = connection->next;
                free(connection);
                connection = temp_con;
              } else {
                exists = 1;
              }
            }

            if (exists == 0){
              mfree(map);
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
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat, uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *map = nat->mappings;

  while(map){
    if (map->aux_ext == aux_ext && map->type == type){
      copy = malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, map, sizeof(struct sr_nat_mapping));

      if (map->conns){
        copy->conns = NULL;
      }
      copy->packet = NULL;

      pthread_mutex_unlock(&(nat->lock));
      return copy;
    }
    map = map->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return NULL;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat, uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *map = nat->mappings;

  while(map){
    if (map->ip_int == ip_int && map->aux_int == aux_int && map->type == type){
      copy = malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, map, sizeof(struct sr_nat_mapping));

      if (map->conns){
        copy->conns = NULL;
      }
      copy->packet = NULL;

      pthread_mutex_unlock(&(nat->lock));
      return copy;
    }
    map = map->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return NULL;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat, uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = NULL;
  mapping = sr_nat_lookup_internal(nat, ip_int, aux_int, type);
  
  if (mapping){
    return mapping;
  }
  
  mapping = malloc(sizeof(struct sr_nat_mapping));
  mapping->type = type;
  mapping->ip_int = ip_int;
  mapping->aux_int = aux_int;
  mapping->last_updated = time(NULL);
  mapping->conns = NULL;
  mapping->packet = NULL;
  mapping->next = nat->mappings;
  
  if (type == nat_mapping_icmp){

    mapping->aux_ext = nat->icmp_id;
    nat->icmp_id += 1;

  } else {

    mapping->aux_ext = nat->tcp_id;
    nat->tcp_id += 1;

    if (nat->tcp_id == 0){
      nat->tcp_id = 1024;
    }

  }
  
  nat->mappings = mapping;

 struct sr_nat_mapping *copy = malloc(sizeof(struct sr_nat_mapping));
 memcpy(copy, mapping, sizeof(struct sr_nat_mapping));

 if (mapping->conns){
    copy->conns = NULL;
 }
 copy->packet = NULL;

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* ---------------------------------------------------------- */

struct sr_nat_connection *sr_nat_update_connection(struct sr_nat *nat, void * buf, unsigned char internal){ 
    pthread_mutex_lock(&(nat->lock));
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)buf;  
    sr_tcp_hdr_t *tcp_header = (sr_tcp_hdr_t *)(buf+SIZE_IP);
    /* handle lookup here, malloc and assign to copy. */
    struct sr_nat_connection *con = NULL;
    struct sr_nat_connection *copy = NULL;
    struct sr_nat_mapping *maps = nat->mappings;
    while(maps != NULL){
        if(internal && 
           maps->ip_int == ip_header->ip_src && 
           maps->aux_int == tcp_header->tcp_src &&
           maps->type == nat_mapping_tcp){
             fprintf(stderr,"\t got map\n");
            con = maps->conns;
            break;
        } else if(!internal &&  
                  maps->aux_ext == ntohs(tcp_header->tcp_dst) &&
                  maps->type == nat_mapping_tcp){
            fprintf(stderr,"\t got map\n");
            con = maps->conns;
            break;
        }
        maps = maps->next;
    }
  
    while (con != NULL){
       if(internal && con->conn_ip == ip_header->ip_dst){
         fprintf(stderr,"\t got con\n");
          copy = con;
          break;
       } else if(!internal && con->conn_ip == ip_header->ip_src){
         fprintf(stderr,"\t got con\n");
          copy = con;
          break;
       }
       con = con->next;
    }
    
    if (maps!= NULL && copy == NULL && internal && tcp_header->syn){
      fprintf(stderr,"\t creating con\n");
       copy = malloc(sizeof(struct sr_nat_connection*));
       copy->conn_ip = (internal ? ip_header->ip_dst : ip_header->ip_src);
       copy->state = SYN_SENT;
       maps->last_updated = time(NULL);
       copy->last_updated = time(NULL);
       con = malloc(sizeof(struct sr_nat_connection));
       memcpy(con,copy,sizeof(struct sr_nat_connection));
       con->next = maps->conns;
       maps->conns = con;
    } else if (copy != NULL){  
       maps->last_updated = time(NULL);
       copy->last_updated = time(NULL);
       switch (copy->state)
       {
          case SYN_SENT :
             if(tcp_header->syn && tcp_header->ack && !internal)
                copy->state = SYN_REC;
          break;
          case SYN_REC :
             if(tcp_header->syn && tcp_header->ack && internal)
                copy->state = ESTAB1;
          break;
          case ESTAB1 :
             if(tcp_header->ack && !internal)
                copy->state = ESTAB2;
          break;
          case ESTAB2 :
             if(tcp_header->fin || tcp_header->rst)
                copy->state = CLOSING;
          break; 
       }
       con = copy;
       copy = malloc(sizeof(struct sr_nat_connection));
       memcpy(copy,con,sizeof(struct sr_nat_connection));
    }
    
    pthread_mutex_unlock(&(nat->lock));
    return copy;
}