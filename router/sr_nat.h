
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp,
  nat_mapping_waiting
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

struct sr_nat_connection {
  /* add TCP connection state data members here */
  uint32_t conn_ip;
  uint8_t state;
/*#define LISTEN 1*/
#define SYN_SENT 2
#define SYN_REC 3
#define ESTAB1 4
#define ESTAB2 5
/*#define FIN_W1 6
#define FIN_W2 7
#define CLOSE_W 7*/
#define CLOSING 8
/*#define LAST_ACK 9
#define TIME_W 10
#define CLOSED 0*/
  /*uint8_t ext_flags;
  uint8_t int_flags;*/
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
  void *packet;
};

struct sr_nat {
  /* add any fields here */
  struct sr_nat_mapping *mappings;
  unsigned int icmp_query_timeout;
  unsigned int tcp_established_timeout;
  unsigned int tcp_transitory_timeout;
  
  unsigned short icmp_id;
  unsigned short tcp_id;
   
  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};


int   sr_nat_init(void *sr,
                  struct sr_nat *nat,
                  unsigned int icmp_timeout,
                  unsigned int tcp_est_timeout,
                  unsigned int tcp_trans_timeout);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *sr_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );
  
/* Insert a new connection into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_connection(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, uint16_t ip_ext);
  
/* Insert a new connection into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_connection *sr_nat_update_connection(struct sr_nat *nat,
  void *buf, unsigned char internal);

void * mfree(struct sr_nat_mapping * map);

#endif