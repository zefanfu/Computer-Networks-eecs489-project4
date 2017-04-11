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
#include <string.h>

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
    print_hdrs(packet, len);

    struct sr_if* iface = sr_get_interface(sr, interface);
    struct sr_ethernet_hdr* e_hdr = 0;

    assert(iface);

    e_hdr = (struct sr_ethernet_hdr*)packet;

    if (e_hdr->ether_type == htons(ethertype_arp)) {
        sr_handle_arp_pkt(sr, packet + sizeof(struct sr_ethernet_hdr), interface);
    } else if (e_hdr->ether_type == htons(ethertype_ip)) {
        sr_handle_ip_pkt(sr, (packet + sizeof(sr_ethernet_hdr_t)), len, interface);
    } else {
        Debug("unknown ether type");
    }

}/* end sr_ForwardPacket */

void sr_handle_arp_pkt(struct sr_instance* sr, uint8_t* a_packet, char* interface)
{
    struct sr_if* iface = sr_get_interface(sr, interface);
    struct sr_arp_hdr* a_hdr_recv = (struct sr_arp_hdr*)a_packet;

    if (a_hdr_recv->ar_op == htons(arp_op_request)) {
        unsigned int len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr);

   
        uint8_t* buf = (uint8_t*)malloc(len);
        struct sr_ethernet_hdr* e_hdr_reply = (struct sr_ethernet_hdr*)buf;
        memcpy(e_hdr_reply->ether_dhost, a_hdr_recv->ar_sha, ETHER_ADDR_LEN);
        memcpy(e_hdr_reply->ether_shost, iface->addr, ETHER_ADDR_LEN);
        e_hdr_reply->ether_type = htons(ethertype_arp);

        /* fill the arp header */
        struct sr_arp_hdr* a_hdr_reply = (struct sr_arp_hdr*)(buf + sizeof(struct sr_ethernet_hdr));
        a_hdr_reply->ar_hrd = htons(arp_hrd_ethernet);
        a_hdr_reply->ar_pro = a_hdr_recv->ar_pro;
        a_hdr_reply->ar_hln = ETHER_ADDR_LEN;
        a_hdr_reply->ar_pln = sizeof(uint32_t);
        a_hdr_reply->ar_op = htons(arp_op_reply);
        memcpy(a_hdr_reply->ar_sha, iface->addr, ETHER_ADDR_LEN);
        a_hdr_reply->ar_sip = iface->ip;
        memcpy(a_hdr_reply->ar_tha, a_hdr_recv->ar_sha, ETHER_ADDR_LEN);
        a_hdr_reply->ar_tip = a_hdr_recv->ar_sip;

        sr_send_packet(sr, buf, len, interface);

        free(buf);

    } else if (a_hdr_recv->ar_op == htons(arp_op_reply)) {
        struct sr_arpreq* req = sr_arpcache_insert(&(sr->cache), a_hdr_recv->ar_sha, a_hdr_recv->ar_sip);

        if (req) {
            /* send all packets on the req->packets linked list */
            struct sr_packet* pkt;
            struct sr_ethernet_hdr* e_hdr_out;
            for (pkt = req->packets; pkt != NULL; pkt = pkt->next) {
                uint8_t* buf = (uint8_t*)malloc(pkt->len);
                memcpy(buf, pkt->buf, pkt->len);
                e_hdr_out = (struct sr_ethernet_hdr*)buf;
                memcpy(e_hdr_out->ether_dhost, a_hdr_recv->ar_sha, ETHER_ADDR_LEN);
                memcpy(e_hdr_out->ether_shost, iface->addr, ETHER_ADDR_LEN);
                e_hdr_out->ether_type = htons(ethertype_ip);

                sr_send_packet(sr, buf, pkt->len, interface);

                free(buf);
            }

            sr_arpreq_destroy(&(sr->cache), req);
        }


    } else {
        Debug("unknown ether type");
    }

}

void sr_handle_ip_pkt(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) 
{
    assert(sr);
    assert(packet);
    assert(interface);
    struct sr_if* iface = sr_get_interface(sr, interface);
    struct sr_ethernet_hdr* e_hdr_recv = (struct sr_ethernet_hdr*)packet;
    struct sr_ip_hdr* ip_hdr_recv = (struct sr_ip_hdr*)packet;

    if(len<sizeof(struct sr_ip_hdr)) {
        /*checksum*/
        uint16_t store_sum=ip_hdr_recv->ip_sum;
        ip_hdr_recv->ip_sum=0;
        uint16_t compute_sum=cksum(ip_hdr_recv,4*(ip_hdr_recv->ip_hl));
        if(compute_sum!=store_sum){
            printf("ip check sum not same\n");
            return;
        }
        ip_hdr_recv->ip_sum=compute_sum;

        uint8_t* buf;
        unsigned int buf_len;

        if (sr_for_us(sr, packet + sizeof(struct sr_ethernet_hdr))) {

            if (sr_is_icmp_echo(sr, packet + sizeof(struct sr_ethernet_hdr))) {
                buf_len = len;
                buf = (uint8_t*)malloc(buf_len);

                sr_set_icmp_echo_hdr(buf + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr),
                    packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr),
                    buf_len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr));


                /* 
                void sr_set_ip_hdr(uint8_t* buf, unsigned int ip_hl, unsigned int ip_v, uint8_t ip_tos, uint16_t ip_len, 
    uint16_t ip_id, uint16_t ip_off, uint8_t ip_ttl, uint8_t ip_p, uint32_t ip_src, uint32_t ip_dst) {
                */
                sr_set_ip_hdr(buf + sizeof(struct sr_ethernet_hdr), 5, 4, 0, buf_len - sizeof(struct sr_ethernet_hdr),
                    ip_hdr_recv->ip_id , htons(IP_DF), 64, ip_protocol_icmp, ntohl(dest_to_src(sr, ip_hdr_recv->ip_dst)), ntohl(ip_hdr_recv->ip_src));
                

                sr_set_ether_hdr(buf, e_hdr_recv->ether_shost, iface->addr, ethertype_ip);

                printf("send:\n");
                print_hdrs(buf, buf_len);
                sr_send_packet(sr, buf, buf_len, interface);

                free(buf);

            } 
            else { /* not echo request*/
            /* if it iss  TCP / UDP send ICMP unreachable*/
                if ((ip_hdr_recv->ip_p == ip_protocol_tcp)||(ip_hdr_recv->ip_p == ip_protocol_udp)){
                    buf_len = len;
                    buf = (uint8_t*)malloc(buf_len);
                    sr_set_icmp_hdr_type(buf + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr),
                    packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr),
                    buf_len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr), 3,3);

                    sr_set_ip_hdr(buf + sizeof(struct sr_ethernet_hdr), 5, 4, 0, buf_len - sizeof(struct sr_ethernet_hdr),
                    ip_hdr_recv->ip_id , htons(IP_DF), 64, ip_protocol_icmp, ntohl(dest_to_src(sr, ip_hdr_recv->ip_dst)), ntohl(ip_hdr_recv->ip_src));
                

                    sr_set_ether_hdr(buf, e_hdr_recv->ether_shost, iface->addr, ethertype_ip);

                    printf("send:\n");
                    print_hdrs(buf, buf_len);
                    sr_send_packet(sr, buf, buf_len, interface);

                    free(buf);
                }

            }
        } 
        else 
        { /* not for us, forward*/

        }

    }
}


int sr_for_us(struct sr_instance *sr, uint8_t* ip_packet) 
{
    assert(sr);
    assert(ip_packet);

    struct sr_ip_hdr* ip_hdr = (struct sr_ip_hdr*)ip_packet;
    struct sr_if* if_walker = NULL;

    for (if_walker = sr->if_list; if_walker != NULL; if_walker = if_walker->next) {
        if (if_walker->ip == ip_hdr->ip_dst) {
            return 1;
        }
    }

    return 0;
}

int sr_is_icmp_echo(struct sr_instance *sr, uint8_t* ip_packet) 
{
    assert(sr);
    assert(ip_packet);

    struct sr_ip_hdr* ip_hdr = (struct sr_ip_hdr*)ip_packet;
    if (ip_hdr->ip_p != ip_protocol_icmp) {
        return 0;
    }

    struct sr_icmp_hdr* icmp_hdr = (struct sr_icmp_hdr*)(ip_packet + sizeof(struct sr_ip_hdr));
    if (icmp_hdr->icmp_type != 8) {
        return 0;
    }

    return 1;

}

void sr_set_icmp_echo_hdr(uint8_t* buf, uint8_t* req_packet, unsigned int len) {
    /* ??????????????? */
    memcpy(buf, req_packet, len); /* copy identifier, seqNum and data */

    struct sr_icmp_hdr* icmp_hdr = (struct sr_icmp_hdr*)buf;
    icmp_hdr->icmp_type = 0;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_sum = 0; /*set checksum to be 0 before computing */

    icmp_hdr->icmp_sum = cksum(buf, len);
}
void sr_set_icmp_hdr_type(uint8_t* buf, uint8_t* req_packet, unsigned int len, uint8_t type, uint8_t code){
    memcpy(buf, req_packet, len); /* copy identifier, seqNum and data */

    struct sr_icmp_hdr* icmp_hdr = (struct sr_icmp_hdr*)buf;
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;
    icmp_hdr->icmp_sum = 0; /*set checksum to be 0 before computing */

    icmp_hdr->icmp_sum = cksum(buf, len);
}


void sr_set_ip_hdr(uint8_t* buf, unsigned int ip_hl, unsigned int ip_v, uint8_t ip_tos, uint16_t ip_len, 
    uint16_t ip_id, uint16_t ip_off, uint8_t ip_ttl, uint8_t ip_p, uint32_t ip_src, uint32_t ip_dst) {

    struct sr_ip_hdr* ip_hdr = (struct sr_ip_hdr*)buf;
    ip_hdr->ip_hl = ip_hl;
    ip_hdr->ip_v = ip_v;
    ip_hdr->ip_tos = ip_tos;
    ip_hdr->ip_len = htons(ip_len);
    ip_hdr->ip_id = htons(ip_id);
    ip_hdr->ip_off = htons(ip_off);
    ip_hdr->ip_ttl = ip_ttl;
    ip_hdr->ip_p = ip_p;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_src = htonl(ip_src);
    ip_hdr->ip_dst = htonl(ip_dst);

    ip_hdr->ip_sum = cksum(buf, ip_len);
}


void sr_set_ether_hdr(uint8_t* buf, uint8_t* dhost, uint8_t* shost, uint16_t type) {
    struct sr_ethernet_hdr* e_hdr = (struct sr_ethernet_hdr*)buf;
    memcpy(e_hdr->ether_dhost, dhost, ETHER_ADDR_LEN);
    memcpy(e_hdr->ether_shost, shost, ETHER_ADDR_LEN);
    e_hdr->ether_type = htons(type);
}

uint32_t dest_to_src(struct sr_instance* sr, uint32_t ip_dst){
    struct sr_rt* rt_walker = NULL;
    /* uint32_t max_mask = 0;*/
    struct sr_rt* max_mask_rt =  malloc(sizeof(struct sr_rt*));
    struct sr_rt* rt_lpm = NULL;
    /* uint32_t result_ip = 0xFFFFFFFF;*/
    for (rt_walker = sr->routing_table; rt_walker != NULL; rt_walker = rt_walker->next) {
        if ( ((rt_walker->dest.s_addr& rt_walker->mask.s_addr) == (ip_dst & rt_walker->mask.s_addr)) &&
            (rt_walker->mask.s_addr >= max_mask_rt->mask.s_addr)) {
                rt_lpm = rt_walker;
                max_mask_rt->mask.s_addr = rt_walker->mask.s_addr;
        }
    }
    struct sr_if* interface=sr_get_interface(sr, rt_lpm->interface);
    return interface->ip;
}