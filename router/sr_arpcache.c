#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>

#include "sr_nat.h"
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include <time.h>
#include "sr_utils.h"
#include "sr_rt.h"

void handle_arpreq(struct sr_arpreq *sr_req, struct sr_instance *sr);

void create_send_ICMP_packet(struct sr_packet *packet, struct sr_instance *sr, int type, int code){
    /*Initialize packet*/
    int reply_size = sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t);
    uint8_t *reply = malloc(reply_size);
    
    /*Initialize headers*/
    sr_ip_hdr_t *IP_header = (sr_ip_hdr_t*)(packet->buf + sizeof(sr_ethernet_hdr_t));
    
    sr_ethernet_hdr_t *e_header = malloc(sizeof(sr_ethernet_hdr_t));
    memcpy(e_header, (sr_ethernet_hdr_t*)packet->buf, sizeof(sr_ethernet_hdr_t));

    /*Create ICMP type 3 header - Host unreachable*/
    sr_icmp_t3_hdr_t *reply_ICMPheader = (sr_icmp_t3_hdr_t*)(reply + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    reply_ICMPheader->icmp_type = type; 
    reply_ICMPheader->icmp_code = code; 
    reply_ICMPheader->icmp_sum = 0; /*Clear to 0*/
    reply_ICMPheader->unused = 0;
    reply_ICMPheader->next_mtu = 0; 
        memcpy(reply_ICMPheader->data, IP_header, ICMP_DATA_SIZE); 
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
    reply_IPheader->ip_dst = IP_header->ip_src; /*Set destination to source since we're sending back*/
    reply_IPheader->ip_p = ip_protocol_icmp; 
    reply_IPheader->ip_src = sr_get_interface(sr, packet->iface)->ip; /*Get the ip of the packet*/
    reply_IPheader->ip_sum = 0; /*Clear to 0*/
    reply_IPheader->ip_sum = cksum(reply_IPheader, sizeof(sr_ip_hdr_t));
    
    /*Create Ethernet header*/
    sr_ethernet_hdr_t *reply_Eheader = (sr_ethernet_hdr_t *)reply;
    reply_Eheader->ether_type = htons(ethertype_ip);

    /*Send the packet - check for longest prefix match so that the destination is in the routing table*/
    struct sr_rt *lpm = check_routing_table(sr, reply_IPheader);
    if(lpm == NULL)
        return;
    
    struct sr_if *router_iface = sr_get_interface(sr, lpm->interface);
    struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, lpm->gw.s_addr); 
    if (entry) {
        /*ARP HIT - Hop to next destination*/
	    /*Update Ethernet header*/
	    memcpy(reply_Eheader->ether_dhost, entry->mac, ETHER_ADDR_LEN); /*Set destination to mac address*/
	    memcpy(reply_Eheader->ether_shost, router_iface->addr,ETHER_ADDR_LEN); 
	    
        sr_send_packet(sr, reply, reply_size, router_iface->name);
        free(entry);
    }else {
        /*ARP MISS - queue and retry*/
        struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, lpm->gw.s_addr, reply, reply_size, lpm->interface);
        handle_arpreq(req, sr);
    }
}

void send_arp_req(struct sr_arpreq *req, struct sr_instance *sr){
    /*Initalize*/
    struct sr_packet *packet = req->packets;
    struct sr_if *packet_iface = sr_get_interface(sr, packet->iface);
    
    int reply_size = sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t);
    uint8_t *reply = malloc(reply_size);
    
    sr_ethernet_hdr_t *e_header = malloc(sizeof(sr_ethernet_hdr_t));
    memcpy(e_header, (sr_ethernet_hdr_t*)packet->buf, sizeof(sr_ethernet_hdr_t));
    
    /*Create Etehrnet header*/
    sr_ethernet_hdr_t *reply_Eheader = (sr_ethernet_hdr_t *)reply;
    memset(reply_Eheader->ether_dhost, 255, ETHER_ADDR_LEN); /*Set destination to source*/
    memcpy(reply_Eheader->ether_shost, packet_iface->addr, ETHER_ADDR_LEN); /*Set source to destination*/
    reply_Eheader->ether_type = htons(ethertype_arp); 
    
    /*Create ARP header*/
    sr_arp_hdr_t *reply_ARPheader = (sr_arp_hdr_t *)(reply + sizeof(sr_ethernet_hdr_t));
    reply_ARPheader->ar_hrd = htons(arp_hrd_ethernet); 
    reply_ARPheader->ar_pro = htons(ethertype_ip); 
    reply_ARPheader->ar_hln = ETHER_ADDR_LEN; 
    reply_ARPheader->ar_pln = sizeof(uint32_t); 
    reply_ARPheader->ar_op = htons(arp_op_request); 
    memcpy(reply_ARPheader->ar_sha, packet_iface->addr,  ETHER_ADDR_LEN); /*sender MAC addr*/
    reply_ARPheader->ar_sip = packet_iface->ip; /* sender IP addr */
    memset(reply_ARPheader->ar_tha, 255, ETHER_ADDR_LEN); /*destination MAC addr */
    reply_ARPheader->ar_tip = req->ip; /* destination IP addr */
    
    /*Send packet*/
    sr_send_packet(sr, reply, reply_size, packet_iface->name);
    free(reply);
}

void handle_arpreq(struct sr_arpreq *sr_req, struct sr_instance *sr){
    /*Get the current time*/
    time_t current_time = time(0);
    
    /*Calculate the time delay between the sent request*/
    if (difftime(current_time, sr_req->sent) >= 1.0) {
        if (sr_req->times_sent >= 5){
            /*Send destination host unreachable message to all packets waiting on this request*/
            struct sr_packet *packet = sr_req->packets;
            while (packet){
                /*Create a reply packet and send*/
                /*send_icmp_messages(sr, packet, 3, 1); Send message*/
            
                    create_send_ICMP_packet(packet, sr, 3, 1);
            
                    packet = packet->next;
            }
	    
            /*Destroy the request*/
            sr_arpreq_destroy(&sr->cache, sr_req); 
        }else {
            /*Send ARP request*/
            send_arp_req(sr_req, sr);
            sr_req->sent = current_time;
            sr_req->times_sent = sr_req->times_sent + 1;
        }
    }
}

/*
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    /* Fill this in */
    /*Get the request*/
    struct sr_arpcache *sr_cache = &sr->cache;
    struct sr_arpreq *sr_req = sr_cache->requests;

    /*Go through each ARP request*/
    while(sr_req){
        struct sr_arpreq *req = sr_req->next;

        handle_arpreq(sr_req, sr);
	/*Send to next hop*/

        sr_req = req;
    }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

void sr_handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req){
    time_t curtime = time(NULL);
    struct sr_packet *packet;
    if (req->times_sent >= 5) {
        for (packet = req->packets; packet != NULL; packet = packet->next) {
            sr_send_icmp(sr, packet->buf, packet->len, 3, 1, 0);
        }
        sr_arpreq_destroy(&sr->cache, req);
    } 
    else if (req->sent == 0 || difftime(curtime, req->sent) >= 1.0){
        uint8_t *out = calloc(1,sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));
        sr_ethernet_hdr_t *ethHeader = (sr_ethernet_hdr_t *)out;
        sr_arp_hdr_t *arpHeader = (sr_arp_hdr_t *)(out+sizeof(sr_ethernet_hdr_t));
        
        /* set ARPHeader to request */
        arpHeader->ar_hrd = htons(0x0001); 
        arpHeader->ar_pro = htons(0x800); 
        arpHeader->ar_op = htons(0x0001);
        arpHeader->ar_hln = 0x0006; 
        arpHeader->ar_pln = 0x0004;
        memset(arpHeader->ar_tha, 255, 6);
        arpHeader->ar_tip = req->ip;/*ENDIANESS*/
        /* set Ethernet Header */
        ethHeader->ether_type = htons(0x0806);
        memset(ethHeader->ether_dhost, 255,6);
    
        /* get outgoing interface and send the request */
        struct sr_if* if_walker;
        if_walker = sr_get_interface(sr, req->packets->iface);
        if (if_walker){
            arpHeader->ar_sip = if_walker->ip;
            memcpy(arpHeader->ar_sha, if_walker->addr, 6);
            memcpy(ethHeader->ether_shost, if_walker->addr, 6);
            sr_send_packet (sr 
                            ,out
                            ,sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)
                            ,if_walker->name);
        }
        req->sent = curtime;
        req->times_sent++;
        free(out);
    }
}