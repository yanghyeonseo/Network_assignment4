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
void sr_init(struct sr_instance *sr)
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
* Method: ip_black_list(struct sr_ip_hdr *iph)
* Scope:  Local
*
* This method is called each time the sr_handlepacket() is called.
* Block IP addresses in the blacklist and print the log.
* - Format : "[IP blocked] : <IP address>"
* - e.g.) [IP blocked] : 10.0.2.100
*
*---------------------------------------------------------------------*/
int ip_black_list(struct sr_ip_hdr *iph)
{
	char ip_blacklist[20] = "10.0.2.0"; /* DO NOT MODIFY */
	char mask[20] = "255.255.255.0"; /* DO NOT MODIFY */
	/**************** fill in code here *****************/
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	/****************************************************/
}

static uint8_t *create_icmp_packet(struct sr_instance *sr,
								char *interface /* lent */,
								struct sr_ip_hdr *i_hdr0 /* lent */,
								uint8_t type, uint8_t code) {
	struct sr_if *ifc = sr_get_interface(sr, interface);

	/* generate ICMP packet */
	unsigned int new_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr);
	uint8_t *new_pck = calloc(1, new_len);
	struct sr_ethernet_hdr *e_hdr = (struct sr_ethernet_hdr *)new_pck;
	struct sr_ip_hdr *i_hdr = (struct sr_ip_hdr *)(((uint8_t *)e_hdr) + sizeof(struct sr_ethernet_hdr));
	struct sr_icmp_t3_hdr *ict3_hdr = (struct sr_icmp_t3_hdr *)(((uint8_t *)i_hdr) + sizeof(struct sr_ip_hdr));

	/* ICMP */
	ict3_hdr->icmp_type = type;
	ict3_hdr->icmp_code = code;
	ict3_hdr->unused = 0;
	ict3_hdr->next_mtu = 0;				/* Maximum Transmission Unit */
	memcpy(ict3_hdr->data, i_hdr0, ICMP_DATA_SIZE);
	ict3_hdr->icmp_sum = 0;
	ict3_hdr->icmp_sum = cksum(ict3_hdr, sizeof(struct sr_icmp_t3_hdr));

	/* IP */
	i_hdr->ip_v = 0x4;
	i_hdr->ip_hl = 0x5;
	i_hdr->ip_tos = 0;					/* Type Of Service */
	i_hdr->ip_len = htons(sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr));
	i_hdr->ip_id = 0;					/* Identifier */
	i_hdr->ip_off = 0;					/* Fragment Off */
	i_hdr->ip_ttl = INIT_TTL;
	i_hdr->ip_p = ip_protocol_icmp;
	i_hdr->ip_src = ifc->ip;
	i_hdr->ip_dst = i_hdr0->ip_src;
	i_hdr->ip_sum = 0;
	i_hdr->ip_sum = cksum(i_hdr, sizeof(struct sr_ip_hdr));

	/* Ethernet */
	e_hdr->ether_type = htons(ethertype_ip);

	return new_pck;
}

static void forward_packet(struct sr_instance *sr,
					 uint8_t *packet /* lent */,
					 unsigned int len)
{
	struct sr_ethernet_hdr *e_hdr = (struct sr_ethernet_hdr *)packet;
	struct sr_ip_hdr *i_hdr = (struct sr_ip_hdr *)(((uint8_t *)e_hdr) + sizeof(struct sr_ethernet_hdr));

	struct sr_rt *rtentry = sr_findLPMentry(sr->routing_table, i_hdr->ip_dst);
	if (rtentry != NULL)
	{
		struct sr_if *ifc = sr_get_interface(sr, rtentry->interface);
		memcpy(e_hdr->ether_shost, ifc->addr, ETHER_ADDR_LEN);
		struct sr_arpentry *arpentry = sr_arpcache_lookup(&(sr->cache), i_hdr->ip_dst);
		if (arpentry != NULL)
		{
			memcpy(e_hdr->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);
			free(arpentry);
			/* send */
			sr_send_packet(sr, packet, len, rtentry->interface);
		}
		else
		{
			/* queue */
			struct sr_arpreq *arpreq = sr_arpcache_queuereq(&(sr->cache), i_hdr->ip_dst, packet, len, rtentry->interface);
			sr_arpcache_handle_arpreq(sr, arpreq);
		}
	}
}
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
void sr_handlepacket(struct sr_instance *sr,
					 uint8_t *packet /* lent */,
					 unsigned int len,
					 char *interface /* lent */)
{

	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);

    /*
        We provide local variables used in the reference solution.
        You can add or ignore local variables.
    */
	uint8_t *new_pck;	  /* new packet */
	unsigned int new_len; /* length of new_pck */

	unsigned int len_r; /* length remaining, for validation */
	uint16_t checksum;	/* checksum, for validation */

	struct sr_ethernet_hdr *e_hdr0, *e_hdr; /* Ethernet headers */
	struct sr_ip_hdr *i_hdr0, *i_hdr;		/* IP headers */
	struct sr_arp_hdr *a_hdr0, *a_hdr;		/* ARP headers */
	struct sr_icmp_hdr *ic_hdr0;			/* ICMP header */
	struct sr_icmp_t3_hdr *ict3_hdr;		/* ICMP type3 header */
	struct sr_icmp_t11_hdr *ict11_hdr;		/* ICMP type11 header */

	struct sr_if *ifc;			  /* router interface */
	uint32_t ipaddr;			  /* IP address */
	struct sr_rt *rtentry;		  /* routing table entry */
	struct sr_arpentry *arpentry; /* ARP table entry in ARP cache */
	struct sr_arpreq *arpreq;	  /* request entry in ARP cache */
	struct sr_packet *en_pck;	  /* encapsulated packet in ARP cache */

	/* validation */
	if (len < sizeof(struct sr_ethernet_hdr))
		return;
	len_r = len - sizeof(struct sr_ethernet_hdr);
	e_hdr0 = (struct sr_ethernet_hdr *)packet; /* e_hdr0 set */

	/* IP packet arrived */
	if (e_hdr0->ether_type == htons(ethertype_ip))
	{
		/* validation */
		if (len_r < sizeof(struct sr_ip_hdr))
			return;

		len_r = len_r - sizeof(struct sr_ip_hdr);
		i_hdr0 = (struct sr_ip_hdr *)(((uint8_t *)e_hdr0) + sizeof(struct sr_ethernet_hdr)); /* i_hdr0 set */

		if (i_hdr0->ip_v != 0x4)
			return;

		checksum = i_hdr0->ip_sum;
		i_hdr0->ip_sum = 0;
		if (checksum != cksum(i_hdr0, sizeof(struct sr_ip_hdr)))
			return;
		i_hdr0->ip_sum = checksum;

		/* check destination */
		for (ifc = sr->if_list; ifc != NULL; ifc = ifc->next)
		{
			if (i_hdr0->ip_dst == ifc->ip)
				break;
		}

		/* check ip black list */
		if (ip_black_list(i_hdr0))
		{
			/* Drop the packet */
			return;
		}

		/* destined to router interface */
		if (ifc != NULL)
		{
			/* with ICMP */
			if (i_hdr0->ip_p == ip_protocol_icmp)
			{
				/* validation */
				if (len_r < sizeof(struct sr_icmp_hdr))
					return;

				ic_hdr0 = (struct sr_icmp_hdr *)(((uint8_t *)i_hdr0) + sizeof(struct sr_ip_hdr)); /* ic_hdr0 set */

				/* echo request type */
				if (ic_hdr0->icmp_type == 0x08)
				{

					/* validation */
					checksum = ic_hdr0->icmp_sum;
					ic_hdr0->icmp_sum = 0;
					if (checksum != cksum(ic_hdr0, len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr)))
						return;
					ic_hdr0->icmp_sum = checksum;

					/* modify to echo reply */
					i_hdr0->ip_ttl = INIT_TTL;
					ipaddr = i_hdr0->ip_src;
					i_hdr0->ip_src = i_hdr0->ip_dst;
					i_hdr0->ip_dst = ipaddr;
					i_hdr0->ip_sum = 0;
					i_hdr0->ip_sum = cksum(i_hdr0, sizeof(struct sr_ip_hdr));
					ic_hdr0->icmp_type = 0x00;
					ic_hdr0->icmp_sum = 0;
					ic_hdr0->icmp_sum = cksum(ic_hdr0, len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr));
					rtentry = sr_findLPMentry(sr->routing_table, i_hdr0->ip_dst);
					if (rtentry != NULL)
					{
						ifc = sr_get_interface(sr, rtentry->interface);
						memcpy(e_hdr0->ether_shost, ifc->addr, ETHER_ADDR_LEN);
						arpentry = sr_arpcache_lookup(&(sr->cache), ipaddr);
						if (arpentry != NULL)
						{
							memcpy(e_hdr0->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);
							free(arpentry);
							/* send */
							sr_send_packet(sr, packet, len, rtentry->interface);
						}
						else
						{
							/* queue */
							arpreq = sr_arpcache_queuereq(&(sr->cache), ipaddr, packet, len, rtentry->interface);
							sr_arpcache_handle_arpreq(sr, arpreq);
						}
					}

					/* done */
					return;
				}

				/* other types */
				else
					return;
			}
			/* with TCP or UDP */
			else if (i_hdr0->ip_p == ip_protocol_tcp || i_hdr0->ip_p == ip_protocol_udp)
			{
				/* validation */
				if (len_r + sizeof(struct sr_ip_hdr) < ICMP_DATA_SIZE)
					return;

				/**************** fill in code here *****************/
				new_pck = create_icmp_packet(sr, interface, i_hdr0, 3, 3);
				new_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr);

				forward_packet(sr, new_pck, new_len);

				/* done */
				free(new_pck);
				/*****************************************************/
				return;
			}
			/* with others */
			else
				return;
		}
		/* destined elsewhere, forward */
		else
		{
			/* refer routing table */
			rtentry = sr_findLPMentry(sr->routing_table, i_hdr0->ip_dst);

			/* routing table hit */
			if (rtentry != NULL)
			{
				/* check TTL expiration */
				if (i_hdr0->ip_ttl == 1)
				{
					/**************** fill in code here *****************/
					/* generate ICMP time exceeded packet */
					new_pck = create_icmp_packet(sr, interface, i_hdr0, 11, 0);
					new_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t11_hdr);

					forward_packet(sr, new_pck, new_len);

					/* done */
					free(new_pck);
					/*****************************************************/
					return;
				}
				/* TTL not expired */
				else {
					/**************** fill in code here *****************/
					i_hdr0->ip_ttl -= 1;
					i_hdr0->ip_sum = 0;
					i_hdr0->ip_sum = cksum(i_hdr0, sizeof(struct sr_ip_hdr));

					forward_packet(sr, packet, len);
					/*****************************************************/
					/* done */
					return;
				}
			}
			/* routing table miss */
			else
			{
				/**************** fill in code here *****************/
				new_pck = create_icmp_packet(sr, interface, i_hdr0, 3, 0);
				new_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr);

				forward_packet(sr, new_pck, new_len);
				/*****************************************************/
				/* done */
				free(new_pck);
				return;
			}
		}
	}
	/* ARP packet arrived */
	else if (e_hdr0->ether_type == htons(ethertype_arp))
	{

		/* validation */
		if (len_r < sizeof(struct sr_arp_hdr))
			return;

		a_hdr0 = (struct sr_arp_hdr *)(((uint8_t *)e_hdr0) + sizeof(struct sr_ethernet_hdr)); /* a_hdr0 set */

		/* destined to me */
		ifc = sr_get_interface(sr, interface);
		if (a_hdr0->ar_tip == ifc->ip)
		{
			/* request code */
			if (a_hdr0->ar_op == htons(arp_op_request))
			{
				/**************** fill in code here *****************/
				new_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr);
				new_pck = calloc(1, new_len);
				e_hdr = (struct sr_ethernet_hdr *)new_pck;
				a_hdr = (struct sr_arp_hdr *)(((uint8_t *)e_hdr) + sizeof(struct sr_ethernet_hdr));

				/* ARP */
				memcpy(a_hdr, a_hdr0, sizeof(struct sr_arp_hdr));
				a_hdr->ar_op = htons(arp_op_reply);
				memcpy(a_hdr->ar_sha, ifc->addr, ETHER_ADDR_LEN);
				a_hdr->ar_sip = ifc->ip;
				memcpy(a_hdr->ar_tha, a_hdr0->ar_sha, ETHER_ADDR_LEN);
				a_hdr->ar_tip = a_hdr0->ar_sip;

				/* Ethernet */
				memcpy(e_hdr->ether_dhost, a_hdr0->ar_sha, ETHER_ADDR_LEN);
				memcpy(e_hdr->ether_shost, ifc->addr, ETHER_ADDR_LEN);
				e_hdr->ether_type = htons(ethertype_arp);

				sr_send_packet(sr, new_pck, new_len, interface);
				/*****************************************************/
				/* done */
				free(new_pck);
				return;
			}

			/* reply code */
			else if (a_hdr0->ar_op == htons(arp_op_reply))
			{
				/**************** fill in code here *****************/
				arpreq = sr_arpcache_insert(&(sr->cache), a_hdr0->ar_sha, a_hdr0->ar_sip);

				if (arpreq != NULL) {
					for (en_pck = arpreq->packets; en_pck; en_pck = en_pck->next) {
						e_hdr = (struct sr_ethernet_hdr *)en_pck->buf;
						memcpy(e_hdr->ether_dhost, a_hdr0->ar_sha, ETHER_ADDR_LEN);
						sr_send_packet(sr, en_pck->buf, en_pck->len, en_pck->iface);
					}
					sr_arpreq_destroy(&(sr->cache), arpreq);
				}
				/*****************************************************/
			}

			/* other codes */
			else
				return;
		}

		/* destined to others */
		else
			return;
	}

	/* other packet arrived */
	else
		return;

} /* end sr_ForwardPacket */

struct sr_rt *sr_findLPMentry(struct sr_rt *rtable, uint32_t ip_dst)
{
	struct sr_rt *entry, *lpmentry = NULL;
	uint32_t mask, lpmmask = 0;

	ip_dst = ntohl(ip_dst);

	/* scan routing table */
	for (entry = rtable; entry != NULL; entry = entry->next)
	{
		mask = ntohl(entry->mask.s_addr);
		/* longest match so far */
		if ((ip_dst & mask) == (ntohl(entry->dest.s_addr) & mask) && mask > lpmmask)
		{
			lpmentry = entry;
			lpmmask = mask;
		}
	}

	return lpmentry;
}
