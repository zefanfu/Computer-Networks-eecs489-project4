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


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

void sr_handle_arp(struct sr_instance* sr, uint8_t* packet, char* interface);
void sr_handle_arp();


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

    struct sr_if* iface = sr_get_interface(sr, interface);
    struct sr_ethernet_hdr* e_hdr = 0;

    assert(iface);

    e_hdr = (struct sr_ethernet_hdr*)packet;

    if (e_hdr->ether_type) == htons(ethertype_arp) {
        sr_handle_arp(sr, packet + sizeof(struct sr_ethernet_hdr), interface);
    } else if (e_hdr->ether_type == htons(ethertype_ip)) {
        sr_handle_ip();
    } else {
        Debug("unknown ether type");
    }

}/* end sr_ForwardPacket */

void sr_handle_arp(struct sr_instance* sr, uint8_t* a_packet, char* interface)
{
    struct sr_if* iface = sr_get_interface(sr, interface);
    struct sr_arp_hdr* a_hdr_recv = (struct sr_arp_hdr*)a_packet;

    if (a_hdr_recv->ar_op == htons(arp_op_request)) {
        unsigned int len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr);

        // create a ethernet packet
        uint8_t* buf = (uint8_t*)malloc(len);
        struct sr_ethernet_hdr* e_hdr_reply = (struct sr_ethernet_hdr*)packet;
        strncpy(e_hdr_reply->ether_dhost, a_hdr_recv->sha, ETHER_ADDR_LEN);
        strncpy(e_hdr_reply->ether_shost, iface->addr, ETHER_ADDR_LEN);
        e_hdr_reply->ether_type = htons(ethertype_arp);

        // fill the arp header
        struct sr_arp_hdr* a_hdr_reply = (struct sr_arp_hdr*)(buf + sizeof(struct sr_ethernet_hdr));
        a_hdr_reply->ar_hrd = htons(arp_hrd_ethernet); // ???????
        a_hdr_reply->ar_pro = a_hdr_recv->ar_pro;      // ??????????
        a_hdr_reply->hln = htons(ETHER_ADDR_LEN);
        a_hdr_reply->pln = htons(sizeof(uint32_t));
        a_hdr_reply->op = htons(arp_op_reply);
        strncpy(a_hdr_reply->ar_sha, iface->addr, ETHER_ADDR_LEN); // ??????
        a_hdr_reply->ar_sip = iface->ip;
        strncpy(a_hdr_reply->ar_tha, a_hdr_recv->ar_sha, ETHER_ADDR_LEN);
        a_hdr_reply->ar_tip = a_hdr_recv->ar_sip;

        sr_send_packet(sr, buf, len, interface);

        free(buf);

    } else if (a_hdr_recv->ar_op == htons(arp_op_reply)) {
        struct sr_arpreq* req = sr_arpcache_insert(&(sr->cache), a_hdr_recv->ar_sha, a_hdr_recv->ar_sip);

        //
        if (req) {
            // send all packets on the req->packets linked list
            struct sr_packet* pkt;
            struct sr_ethernet_hdr* e_hdr_out;
            for (pkt = req->packets; pkt != NULL; pkt = pkt->next) {
                e_hdr_out = (struct sr_ethernet_hdr*)pkt->buf;
                strncpy(e_hdr_out->ether_dhost, a_hdr_recv->ar_sha, ETHER_ADDR_LEN);
                strncpy(e_hdr_out->ether_shost, iface->addr, ETHER_ADDR_LEN);
                e_hdr_reply->ether_type = htons(ethertype_ip);

                sr_send_packet(sr, buf, len, interface);
            }

            sr_arpreq_destroy(&(sr->cache), req);
        }


    } else {
        Debug("unknown ether type");
    }

}