/** @file
 * @brief Packet Sockets related functions
 */

/*
 * Copyright (c) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_sockets_raw, CONFIG_NET_SOCKETS_LOG_LEVEL);

#include <errno.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/net_context.h>
#include <zephyr/net/ethernet.h>
#include <zephyr/net/dsa.h>

#include "connection.h"
#include "packet_socket.h"

enum net_verdict net_packet_socket_input(struct net_pkt *pkt, uint8_t proto)
{
	sa_family_t orig_family;
	enum net_verdict net_verdict;

#if defined(CONFIG_NET_DSA)
	/*
	 * For DSA the master port is not supporting raw packets. Only the
	 * lan1..3 are working with them.
	 */
	if (dsa_is_port_master(net_pkt_iface(pkt))) {
		return NET_CONTINUE;
	}
#endif
	
	// #if defined (CONFIG_NET_VLAN)

	orig_family = net_pkt_family(pkt);
	uint16_t vlan_tag = net_pkt_vlan_tag(pkt);

	
	// if packet is from tunnel, no asset side processing is needed
	if (vlan_tag == NET_VLAN_TAG_UNSPEC){
		return NET_DROP;
	}
	// --------------assign vlan tag to the packet----------------
	struct net_if *old_iface = net_pkt_iface(pkt);
	struct net_if *vlan_iface = net_eth_get_vlan_iface(net_pkt_iface(pkt), vlan_tag);
	net_pkt_set_iface(pkt, vlan_iface);



	// ---------- if tunnel packet it is ment to handled via kernel space ARP request, dtls socket .... ---------
	if (vlan_tag == CONFIG_VLAN_TAG_TUNNEL){
		return NET_CONTINUE;
	}
	if (vlan_iface == NULL) {
		LOG_INF("ERR: Received frame with wrong tag");
		return NET_DROP;
	}
	net_pkt_set_family(pkt, AF_PACKET);

	net_verdict = net_conn_input(pkt, NULL, proto, NULL);

	//--------------- in case we wouldnt drop----------------------
	// restore old iface and family
	net_pkt_set_family(pkt, orig_family);

	//print Net_verdict drop, continue,ok but with string reprensation
	switch (net_verdict) {
		case NET_DROP:
			printf("net_verdict: NET_DROP");
			break;
		case NET_CONTINUE:
			printf("net_verdict: NET_CONTINUE");
			break;
		case NET_OK:
			printf("net_verdict: NET_OK");
			break;
	}
	return NET_DROP;
	// // net_pkt_set_iface(pkt, old_iface);

	// net_pkt_set_family(pkt, orig_family);

	// if (net_verdict == NET_DROP) {
	// 	return NET_CONTINUE;
	// } else {
	// 	return net_verdict;
	// }
}
