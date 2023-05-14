#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "ethertype.h"
#include "arp_table.h"
#include "packet.h"
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#define ICMP_ECHO 8
#define ODD 64 // original data datagram
#define TE 11 // Time exceeded
#define HU 3 // Host unreachable

#define ARP_REQUEST_CODE 1 // ARP op codes 
#define ARP_REPLY_CODE 2

#define ARP_SIZE 1000

struct route_table_entry *best_route(uint32_t dip, struct route_table_entry * rtable, int rtable_size) {
	uint32_t prefix;
	int st = 0, dr = rtable_size - 1, med;

	// Searching the best route entry through binary search
	while (st <= dr) {
		med = (st + dr) >> 1;
		prefix = ntohl(rtable[med].mask) & ntohl(dip);
		// We try to find entry with the same prefix as out destianation adress
		if (prefix >= ntohl(rtable[med].prefix))
			st = med + 1;	
		else
			dr = med - 1;
	}
	// If we found it we return it else we return NULL
	if ((ntohl(rtable[dr].mask) & ntohl(dip)) != ntohl(rtable[dr].prefix))
		return NULL;
	
	return &rtable[dr];
}

int rtable_comparor(const void* a, const void* b) {
	uint32_t mask_a, mask_b;
	mask_a = ntohl(((struct route_table_entry *)a)->mask);
	mask_b = ntohl(((struct route_table_entry *)b)->mask);

	uint32_t prx_a, prx_b;
	prx_a = ntohl(((struct route_table_entry *)a)->prefix);
	prx_b = ntohl(((struct route_table_entry *)b)->prefix);

	// comparator that sorts by prefix and then if they are equal
	// by mask
	if ((prx_a & mask_a) < (prx_b & mask_b))
		return -1;
	else if ((prx_b & mask_a) < (prx_a & mask_b))
		return 1;
	
	if (mask_a < mask_b)
		return -1;
	else if (mask_b < mask_a)
		return 1;
	
	return 0;
}

void icmp_error(int interface, int err, struct iphdr *packet_ip, struct ether_header *packet_eth, struct icmphdr *packet_icmp) {
	memcpy((char *)packet_eth + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), packet_ip, sizeof(struct iphdr) + ODD);

	// initializing the ether header for the packet
	packet_eth->ether_type = htons(ETHERTYPE_IP);
	memcpy(packet_eth->ether_dhost, packet_eth->ether_shost, 6 * sizeof (uint8_t));
	get_interface_mac(interface, packet_eth->ether_shost);
	

	// initializing the IP header for the packet
	packet_ip->tot_len = htons(sizeof(struct iphdr) +  sizeof(struct icmphdr) + sizeof(struct iphdr) + ODD);
	if (err == 11)
		packet_ip->ttl = htons(64);
	packet_ip->daddr = packet_ip->saddr;
	packet_ip->protocol = IPPROTO_ICMP;

	// getting source adress for packet
	struct in_addr raddr;
	inet_aton(get_interface_ip(interface), &raddr);
	memcpy(&packet_ip->saddr, &raddr.s_addr, 4 * sizeof(uint8_t));

	// calculating checksum
	packet_ip->check = htons(0);
	packet_ip->check = checksum((uint16_t *)packet_ip, sizeof(struct iphdr));

	// settying the type of the error we faced
	packet_icmp->code = 0;
	packet_icmp->type = err;

	// calculating checksum
	packet_icmp->checksum = htons(0);
	packet_icmp->checksum = htons(checksum((uint16_t *)packet_icmp, sizeof(struct icmphdr)));
	
	// sending new packet
	send_to_link(interface, (char *)packet_eth, sizeof(struct ether_header) + sizeof(struct iphdr) +  sizeof(struct icmphdr) + sizeof(struct iphdr) + ODD);
}	

void add_in_arp(struct arp_entry_table *table, struct arp_entry new_entry) {
	// reallocing memory if necessary
	table->nr_entry++;
	if (table->nr_entry == table->aloc_mem) {
		table->aloc_mem += ARP_SIZE;
		table->table = (struct arp_entry *)realloc(table->table, table->aloc_mem * sizeof(struct arp_entry));

	}

	// updating arp table
	table->table[table->nr_entry - 1] = new_entry;
}

struct arp_entry *find_arp_entry(struct arp_entry_table *table, uint32_t find) {
	// seing if we have the mac adrress of our ip adress in our arp entries
	for (int i = 0; i < table->nr_entry; i++)
		if (!memcmp(&table->table[i].ip, &find, 4))
			return &table->table[i];

	return NULL;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// allocating memory for our route entry table and reading the values for it
	struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * 100000);
	int rtable_size = read_rtable(argv[1], rtable);
	// we sort after the prefix and then mask to find entries faster
	qsort(rtable, rtable_size, sizeof(struct route_table_entry), rtable_comparor);

	// allocating and initializing arp table
	struct arp_entry_table arp_table;
	arp_table.table = malloc(ARP_SIZE * sizeof(struct arp_entry));
	arp_table.nr_entry = 0;
	arp_table.aloc_mem = ARP_SIZE;

	// queue of packets that don't have an entry in the arp table yet
	queue q = queue_create();
	queue temp_q = queue_create();

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			// We are in the IP case
			// Get the headeres
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof (struct ether_header));
			struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof (struct ether_header) + sizeof(struct iphdr));

			if (ip_hdr->protocol == IPPROTO_ICMP) {
				struct in_addr raddr;
				inet_aton(get_interface_ip(interface), &raddr);
				// check if ECHO icmp is meant for us
				if (icmp_hdr->type == ICMP_ECHO && ip_hdr->daddr == raddr.s_addr) {
					// updating destination (to initial source because we 
					// are replying to an echo) and source
					ip_hdr->daddr = ip_hdr->saddr;
					memcpy(&ip_hdr->saddr, &raddr.s_addr, 4 * sizeof(uint8_t));

					// making checksum
					ip_hdr->check = htons(0);
					ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

					// type is echo reply and checksum
					icmp_hdr->type = htons(0);
					icmp_hdr->checksum = htons(0);
					icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

					// sending packet
					send_to_link(interface, buf, len);
					continue;
				}
			}

			//  checking check_sum
			uint16_t check_sum = ntohs(ip_hdr->check);
			ip_hdr->check = htons(0);
			if (check_sum != checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)))
				continue;
			ip_hdr->check = htons(check_sum);

			// checking ttl
			if (ip_hdr->ttl <= 1) {
				icmp_error(interface, 11, ip_hdr, eth_hdr, icmp_hdr); // icmp time exceeded error
				continue;
			}
			
			// calculating the best entry from the route table to send our packet to
			struct route_table_entry *best_entry = best_route((uint32_t)ip_hdr->daddr, rtable, rtable_size);
			
			if (best_entry == NULL) {
				icmp_error(interface, 3, ip_hdr, eth_hdr, icmp_hdr); // icmp host unreachable error
				continue;
			}

			// updating ttl and checksum to the new values
			(ip_hdr->ttl)--;
			ip_hdr->check = htons(0);
			ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

			// check if our entry has a mac addres in the arp table
			struct arp_entry *new_arp= find_arp_entry(&arp_table, ip_hdr->daddr);

			if (new_arp != NULL) {
				// if we found it we set the destination to the mac adress and send the packet
				memcpy(eth_hdr->ether_dhost, new_arp->mac, 6 * sizeof(uint8_t));
				send_to_link(best_entry->interface, buf, len);
			} else {
				// if we don't have a mac address yet we put the packet in a wainting queue
				struct packet aux;
				aux.len = len;
				aux.interface = interface;
				memcpy(aux.buf, buf, sizeof(struct ether_header) + sizeof(struct arp_header));
				queue_enq(q, &aux);

				// Now we have to send a broadcast to receive the mac address for our ip address
				struct packet send_pack;
				send_pack.interface = best_entry->interface;
				send_pack.len = sizeof(struct ether_header) + sizeof(struct arp_header);

				// we made a new packet and we initialize the headers for it
				struct ether_header *send_eth = (struct ether_header *)send_pack.buf;
				struct arp_header *send_arp = (struct arp_header *)(send_pack.buf + sizeof(struct ether_header));
				
				memset(send_eth->ether_dhost, 0xff, 6 * sizeof (uint8_t)); // broadcast
				get_interface_mac(send_pack.interface, send_eth->ether_shost);
				send_eth->ether_type = htons(ETHERTYPE_ARP);

				send_arp->htype = htons(1);
				send_arp->ptype = htons(0x0800);
				send_arp->hlen = 6;
				send_arp->plen = 4;
				send_arp->op = htons(ARP_REQUEST_CODE);

				// set the destination for the next hop
				memcpy(&send_arp->tpa, &best_entry->next_hop, 4 * sizeof(uint8_t));
				
				// get the ip address of the next hop and set it as source
				struct in_addr raddr;
				inet_aton(get_interface_ip(send_pack.interface), &raddr);
				memcpy(&send_arp->spa, &raddr,  4 * sizeof (uint8_t));

				// and we ask for the mac of our target ip address
				memset(send_arp->tha, 0, 6 * sizeof(uint8_t));
				get_interface_mac(send_pack.interface, send_arp->sha);

				// send the packet
				send_to_link(send_pack.interface, send_pack.buf, send_pack.len);
			}
			
		} else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			// We are in ARP case
			// taking headers
			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

			if (ntohs(arp_hdr->op) == ARP_REQUEST_CODE) {
				struct in_addr raddr;
				inet_aton(get_interface_ip(interface), &raddr);

				// if the target is us we need to reply to the request
				if (memcmp(&raddr, &arp_hdr->tpa, 4 * sizeof(uint8_t)) != 0) {
					continue;
				}

				// type is arp
				eth_hdr->ether_type = htons(ETHERTYPE_ARP);
				
				// we invert destiantion and source to reply
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6 * sizeof (uint8_t));
				get_interface_mac(interface, eth_hdr->ether_shost);

				arp_hdr->htype = htons(1);
				arp_hdr->ptype = htons(0x0800);
				arp_hdr->hlen = 6;
				arp_hdr->plen = 4;
				arp_hdr->op = htons(ARP_REPLY_CODE);

				arp_hdr->tpa = arp_hdr->spa;
				inet_pton(AF_INET, get_interface_ip(interface), &arp_hdr->spa);
				memcpy(arp_hdr->tha, arp_hdr->sha, 6 * sizeof(uint8_t));
				get_interface_mac(interface, arp_hdr->sha);

				send_to_link(interface, buf, len);
			} else if (ntohs(arp_hdr->op) == ARP_REPLY_CODE) {
				// we received a reply so we can add a new mac to our arp table
				struct arp_entry new_entry;
				memcpy(&new_entry.ip, &arp_hdr->spa, 4 * sizeof(uint8_t));
				memcpy(new_entry.mac, arp_hdr->sha, 6 * sizeof(uint8_t));
				add_in_arp(&arp_table, new_entry);

				// try to send any packet we may have in our queue
				while (!queue_empty(q)) {
					struct packet *reply = queue_deq(q);

					struct ether_header *reply_eth = (struct ether_header *)(reply->buf);
					struct iphdr *reply_ip = (struct iphdr *)(reply->buf + sizeof(struct ether_header));

					// get the address of the route entry and check if the ip is in our arp talbe
					struct route_table_entry *reply_entry = best_route((uint32_t)reply_ip->daddr, rtable, rtable_size);
					if (find_arp_entry(&arp_table, reply_entry->next_hop) == NULL) {
						queue_enq(temp_q, &reply);
						continue;
					}

					// if it is than we now have the mac adress and now can send the packet
					memcpy(reply_eth->ether_dhost, reply_eth->ether_shost, 6 * sizeof(uint8_t));
					send_to_link(reply_entry->interface, reply->buf, reply->len);
				}
				while (!queue_empty(temp_q))
					queue_enq(q, (struct packet *)queue_deq(temp_q));
			}
		}
	}
}

