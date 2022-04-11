// +build ignore

// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 SUSE Linux Products GmbH. All Rights Reserved.
//
// Based on tcpaccept(8) from BCC by Brendan Gregg
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define PACKET_HOST 0
#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD

static inline int try_parse_l2packet(struct __sk_buff *skb)
{
	int offset = 0;
	u16 protocol;

	if (bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto), &protocol, 2) < 0)
		return -1;

	offset = sizeof(struct ethhdr);

	switch (bpf_ntohs(protocol)) {
		case ETH_P_IP:
			protocol = 0;
			if (bpf_skb_load_bytes(skb, offset + offsetof(struct iphdr, protocol), &protocol, 1) < 0)
				return -1;

			offset += sizeof(struct iphdr);

			break;
		case ETH_P_IPV6:
			protocol = 0;
			if (bpf_skb_load_bytes(skb, offset + offsetof(struct ipv6hdr, nexthdr), &protocol, 1) < 0)
				return -1;

			offset += sizeof(struct ipv6hdr);
			break;
		default:
			return -1;
	}

	if (protocol != IPPROTO_UDP)
		return -1;

	return offset;
}

static inline int try_parse_ipv4(struct __sk_buff *skb)
{
	u8 protocol;

	if (bpf_skb_load_bytes(skb, offsetof(struct iphdr, protocol), &protocol, 1) < 0)
		return -1;

	if (protocol != IPPROTO_UDP)
		return -1;

	return sizeof(struct iphdr);
}


static inline int try_parse_ipv6(struct __sk_buff *skb)
{
	u8 protocol;

	if (bpf_skb_load_bytes(skb, offsetof(struct ipv6hdr, nexthdr), &protocol, 1) < 0)
		return -1;

	if (protocol != IPPROTO_UDP)
		return -1;

	return sizeof(struct ipv6hdr);
}

SEC("socket")
int socket_filter(struct __sk_buff *skb)
{
	u16 sport;
	int offset = 0;

	if (skb->pkt_type != PACKET_HOST)
		return 0;

	offset = try_parse_l2packet(skb);
	if (offset < 0) {
		// not an l2packet, try with ipv4
		offset = try_parse_ipv4(skb);
		if (offset < 0) {
			// no ipv4 last try is ipv6
			offset = try_parse_ipv6(skb);
			if (offset < 0)
				return 0;
		}
	}

	// at this point we know we have an UDP packet
	if (bpf_skb_load_bytes(skb, offset + offsetof(struct udphdr, source), &sport, 2) < 0)
		return 0;

	if (bpf_ntohs(sport) != 53)
		return 0;

	return skb->len;
}

char LICENSE[] SEC("license") = "GPL";
